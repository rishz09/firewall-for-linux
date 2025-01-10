obj-m += fw_module.o

# builds both user space app and kernel space module
oall:	fw fwmod

# target fw is dependent on fw.c and fw.h
fw:	fw.c fw.h
	gcc -Wall -o fw fw.c

# used to build kernel module
# asks make tool to change the directory to the kernel build directory, and then run the
# make command with CWD
# this line triggers the build process of the kernel module fw_module.o using kernel's build
# system
fwmod:	
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

# cleans up all built files
clean:
	rm -f fw fw_file
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
