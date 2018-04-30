#include <linux/slab.h>
#include <linux/cpumask.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>

#include "sched.h"
#include "ipanema_common.h"
#include "monitor.h"

DEFINE_PER_CPU(struct sched_stats, fair_stats);
DEFINE_PER_CPU(struct sched_stats, ipanema_stats);

void reset_stats(void)
{
	int cpu;
	struct sched_stats *s;
	struct rq_flags rf;

	for_each_possible_cpu(cpu) {
		rq_lock(cpu_rq(cpu), &rf);
		s = per_cpu_ptr(&fair_stats, cpu);
		memset(s, 0, sizeof(struct sched_stats));
		s = per_cpu_ptr(&ipanema_stats, cpu);
		memset(s, 0, sizeof(struct sched_stats));
		rq_unlock(cpu_rq(cpu), &rf);
	}
}

static struct dentry *sched_monitor_dir;
static struct dentry *fair_monitor;
static struct dentry *ipanema_monitor;

static void *sched_monitor_seq_start(struct seq_file *s, loff_t *pos)
{
	int cpu = *pos - (long)SEQ_START_TOKEN - 1;

	if (*pos == 0)
		return SEQ_START_TOKEN;

	if (cpu_possible(cpu))
		return NULL;

	return SEQ_START_TOKEN + 1;
}

static int sched_monitor_seq_show(struct seq_file *m, void *v)
{
	int cpu = (int)(v - SEQ_START_TOKEN - 1);
	struct sched_stats *s = per_cpu_ptr(m->private, cpu);
	int i;

	if (unlikely(v == SEQ_START_TOKEN)) {
		seq_printf(m, "cpu");
		for (i = 0; i < NR_EVENTS; i++)
			seq_printf(m, ";%s (time);%s (hits)",
				   evts_names[i], evts_names[i]);
		seq_printf(m, "\n");
		return 0;
	}

	seq_printf(m, "%d", cpu);
	for (i = 0; i < NR_EVENTS; i++)
		seq_printf(m, ";%llu;%llu",
			   s->time[i], s->hits[i]);
	seq_printf(m, "\n");

	return 0;
}

static void *sched_monitor_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	int cpu = (int)(v - SEQ_START_TOKEN - 1);

	if (cpu_possible(cpu + 1)) {
		*pos = *pos + 1;
		return v + 1;
	}

	return NULL;
}

static void sched_monitor_seq_stop(struct seq_file *m, void *v)
{
}

static struct seq_operations sched_monitor_seq_ops = {
	.start = sched_monitor_seq_start,
	.next  = sched_monitor_seq_next,
	.stop  = sched_monitor_seq_stop,
	.show  = sched_monitor_seq_show
};

static int sched_monitor_open(struct inode *inode, struct file *file)
{
	struct seq_file *sf;
	int ret;

	ret = seq_open(file, &sched_monitor_seq_ops);
	sf = (struct seq_file *) (file->private_data);
	if (!strncmp(file->f_path.dentry->d_iname, "fair", 5))
		sf->private = (void *)&fair_stats;
	else
		sf->private = (void *)&ipanema_stats;

	return ret;
};

static struct file_operations sched_monitor_file_ops = {
	.owner   = THIS_MODULE,
	.open    = sched_monitor_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};

static int __init monitor_debugfs_init(void)
{
	sched_monitor_dir = debugfs_create_dir("sched_monitor", NULL);
	if (!sched_monitor_dir)
		goto exit;

	fair_monitor = debugfs_create_file("fair", 0444, sched_monitor_dir,
					   NULL, &sched_monitor_file_ops);
	ipanema_monitor = debugfs_create_file("ipanema", 0444,
					      sched_monitor_dir, NULL,
					      &sched_monitor_file_ops);

	return 0;
exit:
	return -ENOMEM;
}
late_initcall(monitor_debugfs_init);
