#define pr_fmt(fmt) "ipanema: " fmt

#include <linux/seq_file.h>
#include <linux/cpu.h>

#include "sched.h"
#include "ipanema_common.h"


static ssize_t ipanema_policies_write(struct file *file, const char __user *buf,
				      size_t count, loff_t *ppos)
{
	int res;
	char kbuf[MAX_POLICY_NAME_LEN];

	count = min((int)count, MAX_POLICY_NAME_LEN);

	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;

	/* Remove the newline */
	kbuf[count - 1] = '\0';

	res = ipanema_set_policy(kbuf);
	if (res)
		return res;

	return count;
}

static void *ipanema_policies_start(struct seq_file *f, loff_t *pos)
{
	read_lock(&ipanema_rwlock);
	return seq_list_start(&ipanema_policies, *pos);
}

static void *ipanema_policies_next(struct seq_file *f, void *v, loff_t *pos)
{
	return seq_list_next(v, &ipanema_policies, pos);
}

static void ipanema_policies_stop(struct seq_file *f, void *v)
{
	read_unlock(&ipanema_rwlock);
}

static int ipanema_policies_show(struct seq_file *f, void *v)
{
	struct ipanema_policy *policy = list_entry(v, struct ipanema_policy,
						   list);
	seq_printf(f, "%d %s %*pbl\n",
		   policy->id, policy->name,
		   cpumask_pr_args(&policy->allowed_cores));
	return 0;
}

static const struct seq_operations ipanema_policies_ops = {
	.start = ipanema_policies_start,
	.next  = ipanema_policies_next,
	.show  = ipanema_policies_show,
	.stop  = ipanema_policies_stop
};

static int ipanema_policies_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ipanema_policies_ops);
}

static const struct file_operations ipanema_policies_fops = {
	.open    = ipanema_policies_open,
	.read    = seq_read,
	.write   = ipanema_policies_write,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static void *ipanema_modules_start(struct seq_file *f, loff_t *pos)
{
	read_lock(&ipanema_rwlock);
	return seq_list_start(&ipanema_modules, *pos);
}

static void *ipanema_modules_next(struct seq_file *f, void *v, loff_t *pos)
{
	return seq_list_next(v, &ipanema_modules, pos);
}

static void ipanema_modules_stop(struct seq_file *f, void *v)
{
	read_unlock(&ipanema_rwlock);
}

static int ipanema_modules_show(struct seq_file *f, void *v)
{
	struct ipanema_module *m = list_entry(v, struct ipanema_module, list);
	seq_printf(f, "%s\n", m->name);
	return 0;
}

static const struct seq_operations ipanema_modules_ops = {
	.start = ipanema_modules_start,
	.next  = ipanema_modules_next,
	.show  = ipanema_modules_show,
	.stop  = ipanema_modules_stop
};

static int ipanema_modules_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ipanema_modules_ops);
}

static const struct file_operations ipanema_modules_fops = {
	.open    = ipanema_modules_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

struct proc_dir_entry *ipa_procdir;
EXPORT_SYMBOL(ipa_procdir);

/*
 * /proc files cannot be created during early init phases. Do that once
 * the kernel has booted.
 */
__init int ipanema_create_procfs(void)
{
	ipa_procdir = proc_mkdir("ipanema", NULL);
	proc_create("modules", 0444, ipa_procdir, &ipanema_modules_fops);
	proc_create("policies", 0666, ipa_procdir, &ipanema_policies_fops);

	pr_info("procfs files created\n");

	return 0;
}
late_initcall(ipanema_create_procfs);
