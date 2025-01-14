# firewall-for-linux
A small firewall project to filter TCP and UDP packets in Linux. Users are able to choose rules, according to which the filtering occurs.

Users are given the option to specify rules based on direction, source, destination and protocol number. To view a guide for adding and deleting rules, users can execute the following line after installation of the module:

```
$ ./fw --help
```

This firewall utilizes a user-space program `fw` and a kernel-space module `fw_module`. Data transfer and communication between these two modules occurs via a device file `fw_file`.

The firewall uses **Netfilter** to compare packets with the user specified rules. If a packet matches all the rules, that packet is dropped.

## Prerequisites
* Secure Boot must be turned off in the BIOS. This is because the firewall has a kernel-level module, and without turning off Secure Boot, OS won't allow any non-verified / non-trusted kernel level module to be installed.

* Kernel-level programming libraries / frameworks must be installed in the system as these are required during compilation.

## Installation
Makefile compiles both user-space program and kernel-space module. Execute the following line:
```
$ make
```

The device file can be created by executing the following line:
```
$ sudo mknod fw_file c 100 0
```
* **c** - character device, which means data will be handled one character at a time.
* **100** - major number of the device.
* **0** - minor number of the device.

The kernel module `fw_module` is inserted into the kernel of Linux by executing the following line:
```
$ sudo insmod ./fw_module.ko
```

## Usage
As mentioned above, different ways to add / delete / view rules can be seen by executing the following rules:
```
$ ./fw --help
```
An example is demonstrated below:

Suppose we want to filter incoming IP address of Google's server, we can do it this way:

```
sudo ./fw -a -o -d 142.250.193.68
```
* **-a** - add rule
* **-o** - output
* **-d** - destination IP Address
* **142.250.193.68** is the destination IP Address of Google's server
* IP Address can be found out using:
```
ping www.google.com 
```

Similarly, the rule can be removed using the following:
```
sudo ./fw -a -o -d 142.250.193.68
```
* **-r** - remove rule


## **Video Demonstration**
https://youtu.be/GlwsAmnLoJQ
