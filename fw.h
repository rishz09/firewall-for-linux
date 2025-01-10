#ifndef _FW_H_
#define _FW_H_

#include <linux/types.h>

#define DEVICE_INTF_NAME "fw_file"
#define DEVICE_MAJOR_NUM 100


/* Mode of an instruction */
enum fw_mode {
	FW_NONE = 0,
	FW_ADD = 1,
	FW_REMOVE = 2,
	FW_VIEW = 3
};


/* Filter rule of Firewall */
struct fw_rule {
	uint32_t in;
	uint32_t s_ip;
	uint32_t s_mask;
	uint16_t s_port;
	uint32_t d_ip;
	uint32_t d_mask;
	uint16_t d_port;
	uint8_t proto;
};


/* Control instruction */
struct fw_ctl {
	enum fw_mode mode;
	struct fw_rule rule;
};

#endif
