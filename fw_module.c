#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/netfilter_ipv4.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "fw.h"

// two IP addresses (ip1 and ip2) to check if they belong to the same network subnet.
#define EQUAL_NET_ADDR(ip1, ip2, mask) (((ip1 ^ ip2) & mask) == 0)
#define IGNORE(x) (x == 0)

// extracts the i-th byte (octet) of a 32-bit IP address. IP addresses are typically represented in four octets (A.B.C.D). 
#define IP_POS(ip, i) (ip >> ((8*(3-i))) & 0xFF)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rishabh");
MODULE_DESCRIPTION("Firewall");
MODULE_VERSION("1.0");


/* List node containing a filter rule */
struct rule_node 
{
	struct fw_rule rule;
	struct list_head list;
};

// struct list_head is used to implement a Doubly Linked List
struct list_head In_lhead;	/* Head of inbound-rule list */
struct list_head Out_lhead;	/* Head of outbound-rule list */

static int Device_open; /* Opening counter of a device file */
static char *Buffer;	/* A buffer for receving data from a user space */


// General filter uses exact match algorithm based on the given rule list.

static unsigned int fw_general_filter(void *priv, struct sk_buff *skb,
const struct nf_hook_state *state, struct list_head *rule_list_head)
{
	struct list_head *listh;
	struct rule_node *node;
	struct fw_rule *r;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;

	uint32_t s_ip;
	uint32_t d_ip;
	uint16_t s_port;
	uint16_t d_port;
	unsigned char proto;

	// if socket buffer doesn't exist or rule list is empty, accept packet
	if(!skb || rule_list_head->next == rule_list_head)
	return NF_ACCEPT;

	/* Get IP header and extract information */
	iph = (struct iphdr *)skb_network_header(skb);
	if(iph == NULL)
	return NF_ACCEPT;

	proto = iph->protocol;
	s_ip = iph->saddr;
	d_ip = iph->daddr;

	// if protocol is UDP, extracts UDP header and source and dest port
	if(proto == IPPROTO_UDP) 
	{
		udph = (struct udphdr *)(skb_transport_header(skb));
		s_port = udph->source;
		d_port = udph->dest;
	}

	// if protocol is TCP, extracts TCP header and source and dest port
	else if(proto == IPPROTO_TCP) 
	{
		tcph = (struct tcphdr *)(skb_transport_header(skb));
		s_port = tcph->source;
		d_port = tcph->dest;
	}

	// accepts other protocols
	else
	return NF_ACCEPT;

	/* Loop through the rule list and perform exact match */
	listh = rule_list_head;
	list_for_each_entry(node, listh, list) 
	{
		r = &node->rule;

		if(!IGNORE(r->proto) && (r->proto != iph->protocol))
			continue;

		if(!IGNORE(r->s_ip) && !EQUAL_NET_ADDR(r->s_ip, s_ip, r->s_mask))
			continue;

		if(!IGNORE(r->s_port) && (r->s_port != s_port))
			continue;

		if(!IGNORE(r->d_ip) && !EQUAL_NET_ADDR(r->d_ip, d_ip, r->s_mask))
			continue;

		if(!IGNORE(r->d_port) && (r->d_port != d_port))
			continue;

		// if none of the if cases satisfy, then it means that a rule has been 
		// matched and we need to drop this packet

		// KERN_INFO is a log level used in the Linux kernel's printk function, 
		// which is a standard way to print messages to the kernel log.
		printk(KERN_INFO "Firewall: Drop packet "
		       "src %d.%d.%d.%d : %d   dst %d.%d.%d.%d : %d   proto %d\n",
		       IP_POS(s_ip, 3), IP_POS(s_ip, 2),
		       IP_POS(s_ip, 1), IP_POS(s_ip, 0), s_port,
		       IP_POS(d_ip, 3), IP_POS(d_ip, 2),
		       IP_POS(d_ip, 1), IP_POS(d_ip, 0), d_port,
		       iph->protocol);

		return NF_DROP;
	}
	
	return NF_ACCEPT;
}


/*
 * Inbound filter is applied to all inbound packets.
 */
static unsigned int fw_in_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return fw_general_filter(priv, skb, state, &In_lhead);
}


/*
 * Outbound filter is applied to all outbound packets.
 */
static unsigned int fw_out_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return fw_general_filter(priv, skb, state, &Out_lhead);
}


/*
 * The function handles an open operation of a device file.
 */
// inode: A pointer to the inode structure that represents the file or device 
// being accessed. It is used for file system operations.
// file: A pointer to the file structure, which represents the open file 
// descriptor for the device.

static int fw_dev_open(struct inode *inode, struct file *file)
{
	// if device_open is non zero, it indicates that the device is already in use,
	// so return -EBUSY: standard linux error code for "device or resource is busy"
	if(Device_open)
		return -EBUSY;

	/* Increase value to enforce a signal access policy */
	Device_open++;

	// if kernel module, cannot be acquired, log an error message
	// THIS_MODULE is a special macro used in the Linux kernel to 
	// refer to the current module.
	if(!try_module_get(THIS_MODULE)) 
	{
		printk(KERN_ALERT "Firewall: Module is not available\n");
		// no such process
		return -ESRCH;
	}

	// successful, so return 0
	return 0;
}


/*
 * The function handles a release operation of a device file.
 */
static int fw_dev_release(struct inode *inode, struct file *file)
{
	// module_put decreases reference count of the module
	// Reference count is used to track how many users of parts of the kernel
	// are using the model

	module_put(THIS_MODULE);
	Device_open--;
	return 0;
}


/*
 * The function handles user-space view operation, which reads inbound and
 * outbound rules stored in the module. The function is called iteratively
 * until it returns 0.
 */

// reads data from device file into user space memory
// It reads rules from two linked lists (In_lhead and Out_lhead), which store network
// filtering rules, and writes the data to the user-space buffer.

// loff_t *offset: pointer to offset in the file (not used here)
static ssize_t fw_dev_read(struct file *file, char *buffer, size_t length, loff_t *offset)
{
	int byte_read = 0;
	static struct list_head *inlp = &In_lhead;
	static struct list_head *outlp = &Out_lhead;

	// for accessing individual rules
	struct rule_node *node;
	// pointer to the rule's data that will be copied into user space buffer
	char *readptr;

	/* Read a rule if it is not the last one in the inbound list */
	if(inlp->next != &In_lhead) 
	{
		node = list_entry(inlp->next, struct rule_node, list);
		// readptr is set to point to the rule inside node (fw_rule). casted to
		// char* to enable byte by byte reading
		readptr = (char*)&node->rule;
		inlp = inlp->next;
	}

	/* Read a rule if it is not the last one in the outbound list */
	else if(outlp->next != &Out_lhead) 
	{
		node = list_entry(outlp->next, struct rule_node, list);
		readptr = (char*)&node->rule;
		outlp = outlp->next;
	}

	/* Reset reading pointers to heads of inbound and outbound lists */
	else 
	{
		inlp = &In_lhead;
		outlp = &Out_lhead;
		return 0;
	}

	/* Write to a user-space buffer */
	while(length && (byte_read < sizeof(struct fw_rule))) 
	{
		// put_user copies a byte from kernel space (readptr[byte_read]) to the user
		// space (&buffer[byte_read]). Handles necessary access control between
		// kernel space and user space

		put_user(readptr[byte_read], &(buffer[byte_read]));
		byte_read++;
		length--;
	}

	return byte_read;
}


/*
 * The function adds a rule to either an inbound list or an outbound list.
 */
static void fw_rule_add(struct fw_rule *rule)
{
	struct rule_node *nodep;
	nodep = (struct rule_node *)kmalloc(sizeof(struct rule_node), GFP_KERNEL);

	// if memory allocation fails
	if(nodep == NULL) 
	{
		printk(KERN_ALERT "Firewall: Cannot add a new rule due to "
		       "insufficient memory\n");
		return;
	}

	// copies contents of rule to rule_node struct
	nodep->rule = *rule;

	// rule.in is a variable defined in struct fw_rule
	if(nodep->rule.in == 1) 
	{
		// adds the rule node to the tail of In_lhead, which is DLL to store all
		// inbound rules

		list_add_tail(&nodep->list, &In_lhead);
		printk(KERN_INFO "Firewall: Add rule to the inbound list ");
	}

	else 
	{
		list_add_tail(&nodep->list, &Out_lhead);
		printk(KERN_INFO "Firewall: Add rule to the outbound list ");
	}

	printk(KERN_INFO
	       "src %d.%d.%d.%d : %d   dst %d.%d.%d.%d : %d   proto %d\n",
	       IP_POS(rule->s_ip, 3), IP_POS(rule->s_ip, 2),
	       IP_POS(rule->s_ip, 1), IP_POS(rule->s_ip, 0), rule->s_port,
	       IP_POS(rule->d_ip, 3), IP_POS(rule->d_ip, 2),
	       IP_POS(rule->d_ip, 1), IP_POS(rule->d_ip, 0), rule->d_port,
	       rule->proto);
}


/*
 * The function deletes a rule from inbound and outbound lists.
 */
static void fw_rule_del(struct fw_rule *rule)
{
	struct rule_node *node;
	struct list_head *lheadp;
	struct list_head *lp;

	if(rule->in == 1)
	lheadp = &In_lhead;
	
	else
	lheadp = &Out_lhead;

	for(lp = lheadp; lp->next != lheadp; lp = lp->next) 
	{
		// obtains the corresponding rule_node struct from lp->next
		node = list_entry(lp->next, struct rule_node, list);
		if(node->rule.in == rule->in &&
		   node->rule.s_ip == rule->s_ip &&
		   node->rule.s_mask == rule->s_mask &&
		   node->rule.s_port == rule->s_port &&
		   node->rule.d_ip == rule->d_ip &&
		   node->rule.d_mask == rule->d_mask &&
		   node->rule.d_port == rule->d_port &&
		   node->rule.proto == rule->proto) 
		{
			list_del(lp->next);

			// freeing up memory allocated for rule_node
			kfree(node);
			printk(KERN_INFO "Firewall: Remove rule "
			       "src %d.%d.%d.%d : %d   dst %d.%d.%d.%d : %d   "
			       "proto %d\n",
			       IP_POS(rule->s_ip, 3), IP_POS(rule->s_ip, 2),
			       IP_POS(rule->s_ip, 1), IP_POS(rule->s_ip, 0),
			       rule->s_port,
			       IP_POS(rule->d_ip, 3), IP_POS(rule->d_ip, 2),
			       IP_POS(rule->d_ip, 1), IP_POS(rule->d_ip, 0),
			       rule->d_port, rule->proto);
			break;
		}
	}
}


/*
 * The function handles user-space write operation, which sends add and remove
 * instruction to the Firewall module
 */
// handles write operations from user-space to kernel-space. Processes instructions
// to either add or remove firewall rules based on data received from user space
static ssize_t fw_dev_write(struct file *file, const char *buffer, size_t length, loff_t *offset)
{
	// holds control info (type of info and the rule data)
	struct fw_ctl *ctlp;
	int byte_write = 0;

	// length of incoming data needs to be the size of fw_ctl atleast
	if(length < sizeof(*ctlp)) 
	{
		printk(KERN_ALERT
		       "Firewall: Receives incomplete instruction\n");
		return byte_write;
	}

	/* Transfer user-space data to kernel-space buffer */
	while(length && (byte_write < sizeof(*ctlp))) 
	{
		// transfers one byte at a time from user space (buffer)
		// to kernel space (Buffer)
		get_user(Buffer[byte_write], buffer + byte_write);
		byte_write++;
		length--;
	}

	// casts Buffer to struct fw_ctl for easy access of data and type of operation
	ctlp = (struct fw_ctl *)Buffer;
	switch(ctlp->mode) 
	{
		case FW_ADD:
			fw_rule_add(&ctlp->rule);
			break;

		case FW_REMOVE:
			fw_rule_del(&ctlp->rule);
			break;

		default:
			printk(KERN_ALERT
				"Firewall: Received an unknown command\n");
	}

	return byte_write;
}


/* Inbound hook configuration for netfilter */
struct nf_hook_ops fw_in_hook_ops = {			
	.hook = fw_in_filter, // the network packed will be processed by this hook function
	.pf = PF_INET,  // protocol family: IPv4
	.hooknum = NF_INET_PRE_ROUTING,  // hook will be invoked before routing the packet 
	.priority = NF_IP_PRI_FIRST  // specifies priority of hook. This means highest priority
};


/* Outbound hook configuration for netfilter */
struct nf_hook_ops fw_out_hook_ops = {
	.hook = fw_out_filter,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_FIRST
};


/* File operation configuration for a device file */
// operations to be performed when interacting with a device from user space
struct file_operations fw_dev_fops = {
	.read = fw_dev_read,
	.write = fw_dev_write,
	.open = fw_dev_open,
	.release = fw_dev_release
};


/*
 * The Firewall kernel module is initialized by this function.
 */
static int __init fw_mod_init(void)
{
	int ret;

	/* Initialize static global variables */
	Device_open = 0;

	// allocates memory the size of fw_ctl to the kernel space Buffer
	Buffer = (char *)kmalloc(sizeof(struct fw_ctl *), GFP_KERNEL);
	if(Buffer == NULL) 
	{
		printk(KERN_ALERT
		       "Firewall: Fails to start due to out of memory\n");
		return -1;
	}

	// initializes list heads for inbound and outbound rules
	INIT_LIST_HEAD(&In_lhead);
	INIT_LIST_HEAD(&Out_lhead);

	/* Register character device */
	/*
	register_chrdev registers the Firewall device as a character device in the 
	kernel. This makes the Firewall module available to user-space programs.
	*/

	/*
	DEVICE_MAJOR_NUM: The major device number for the character device. This number 
	identifies the device in the kernel.

	DEVICE_INTF_NAME: The name of the device file (e.g., /dev/fw_device).

	&fw_dev_fops: A pointer to the file operations structure (fw_dev_fops) that 
	defines how user-space programs can interact with the Firewall device 
	(e.g., read, write, open, and close).
	*/

	ret = register_chrdev(DEVICE_MAJOR_NUM, DEVICE_INTF_NAME, &fw_dev_fops);
	if(ret < 0) 
	{
		printk(KERN_ALERT
		       "Firewall: Fails to start due to device register\n");
		return ret;
	}

	printk(KERN_INFO "Firewall: "
	       "Char device %s is registered with major number %d\n",
	       DEVICE_INTF_NAME, DEVICE_MAJOR_NUM);

	// mknod creates a device node and enables user space programs to interact 
	// with the Firewall device using standard file operations
	printk(KERN_INFO "Firewall: "
	       "To communicate to the device, use: mknod %s c %d 0\n",
	       DEVICE_INTF_NAME, DEVICE_MAJOR_NUM);

	/* Register netfilter inbound and outbound hooks */
	nf_register_net_hook(&init_net, &fw_in_hook_ops);
	nf_register_net_hook(&init_net, &fw_out_hook_ops);
	return 0;
}

// tells the kernel to call fw_mod_init when module is loaded
module_init(fw_mod_init);


/*
 * The Firewall module is cleaned up by this function.
 */
static void __exit fw_mod_cleanup(void)
{
	struct rule_node *nodep;
	struct rule_node *ntmp;

	kfree(Buffer);

	list_for_each_entry_safe(nodep, ntmp, &In_lhead, list) 
	{
		list_del(&nodep->list);
		kfree(nodep);
		printk(KERN_INFO "Firewall: Deleted inbound rule %p\n",
		       nodep);
	}

	list_for_each_entry_safe(nodep, ntmp, &Out_lhead, list) 
	{
		list_del(&nodep->list);
		kfree(nodep);
		printk(KERN_INFO "Firewall: Deleted outbound rule %p\n",
		       nodep);
	}

	unregister_chrdev(DEVICE_MAJOR_NUM, DEVICE_INTF_NAME);
	printk(KERN_INFO "Firewall: Device %s is unregistered\n",
	       DEVICE_INTF_NAME);

	nf_unregister_net_hook(&init_net, &fw_in_hook_ops);
	nf_unregister_net_hook(&init_net, &fw_out_hook_ops);
}
/* Add the (above) cleanup function to the module */
module_exit(fw_mod_cleanup);
