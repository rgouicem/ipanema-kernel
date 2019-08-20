#define pr_fmt(fmt) "ipanema: " fmt

#include <linux/seq_file.h>
#include <linux/cpu.h>

#include "sched.h"
#include "ipanema.h"


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
	seq_printf(f, "%llu %s %d\n",
		   policy->id, policy->name, module_refcount(policy->kmodule));
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
	proc_create("policies", 0444, ipa_procdir, &ipanema_policies_fops);

	pr_info("procfs files created\n");

	return 0;
}
late_initcall(ipanema_create_procfs);
