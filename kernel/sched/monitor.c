#include <linux/slab.h>
#include <linux/cpumask.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>

#include "sched.h"
#include "ipanema_common.h"
#include "monitor.h"

#define F_DENTRY(filp) ((filp)->f_path.dentry)

bool sched_monitor_enabled;
bool sched_monitor_idle_enabled;
bool sched_monitor_fair_enabled;
bool sched_monitor_ipanema_enabled;

static char *evts_names[] = {
	"enqueue_task", "dequeue_task", "yield_task", "yield_to_task",
	"check_preempt_curr", "pick_next_task", "put_prev_task",
	"select_task_rq", "migrate_task_rq", "task_woken", "rq_online",
	"rq_offline", "set_curr_task", "task_tick", "task_fork", "task_dead",
	"switched_from", "switched_to", "prio_changed", "lb_periodic"
};

DEFINE_PER_CPU(struct sched_stats, fair_stats);
DEFINE_PER_CPU(struct sched_stats, ipanema_stats);
DEFINE_PER_CPU(struct idle_stats, idle_stats);
struct wc_stats wc_stats;
DECLARE_PER_CPU(u64, last_sched);

void reset_stats(void)
{
	int cpu;
	struct sched_stats *s;
	struct idle_stats *i;
	struct rq_flags rf;

	for_each_possible_cpu(cpu) {
		rq_lock(cpu_rq(cpu), &rf);
		s = per_cpu_ptr(&fair_stats, cpu);
		memset(s, 0, sizeof(struct sched_stats));
		s = per_cpu_ptr(&ipanema_stats, cpu);
		memset(s, 0, sizeof(struct sched_stats));
		i = per_cpu_ptr(&idle_stats, cpu);
		i->time = i->hits = 0;
		*per_cpu_ptr(&last_sched, cpu) = cpu_clock(cpu);
		per_cpu(sched_time, cpu) = 0;
		rq_unlock(cpu_rq(cpu), &rf);
	}
	atomic64_set(&(wc_stats.time), 0);
}

static struct dentry *sched_monitor_dir;
static struct dentry *fair_monitor;
static struct dentry *ipanema_monitor;
static struct dentry *time_dir_debugfs;
static struct dentry *fair_dir_debugfs;
static struct dentry *ipanema_dir_debugfs;
static struct dentry *idle_dir_debugfs;

static void *sched_monitor_seq_start(struct seq_file *s, loff_t *pos)
{
	if (*pos == 0)
		return SEQ_START_TOKEN;

	if (!cpu_possible(*pos - (long)SEQ_START_TOKEN))
		return NULL;

	return (void *)*pos + 1;
}

static int sched_monitor_seq_show(struct seq_file *m, void *v)
{
	int cpu = (int)(v - SEQ_START_TOKEN - 1);
	struct sched_stats *s = per_cpu_ptr(m->private, cpu);
	struct idle_stats *is = per_cpu_ptr(&idle_stats, cpu);
	int i;

	if (unlikely(v == SEQ_START_TOKEN)) {
		seq_printf(m, "cpu");
		for (i = 0; i < NR_EVENTS; i++)
			seq_printf(m, ";%s (time);%s (hits)",
				   evts_names[i], evts_names[i]);
		seq_printf(m, ";idle (time); idle (hits)\n");
		return 0;
	}

	seq_printf(m, "%d", cpu);
	for (i = 0; i < NR_EVENTS; i++)
		seq_printf(m, ";%llu;%llu",
			   s->time[i], s->hits[i]);
	seq_printf(m, ";%llu;%llu\n", is->time, is->hits);

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

/*
 * sched_monitor
 */
DEFINE_PER_CPU(u64, sched_time);
DEFINE_PER_CPU(u64, sched_time_start);
DEFINE_PER_CPU(bool, sched_monitoring);
DEFINE_PER_CPU(void *, sched_monitoring_fn);

ssize_t sched_monitor_reset_write(struct file *file,
				  const char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	reset_stats();
	return count;
}

static const struct file_operations sched_monitor_reset_fops = {
	.open   = simple_open,
	.llseek = default_llseek,
	.write  = sched_monitor_reset_write,
};

int sched_monitor_sched_class_stats_open(struct inode *inode, struct file *file)
{
	struct dentry *parent = F_DENTRY(file)->d_parent;

	if (!parent)
		return -EACCES;

	if (!strncmp(parent->d_iname, "fair_stats", 10))
		file->private_data = (void *)&fair_stats;
	else if (!strncmp(parent->d_iname, "ipanema_stats", 13))
		file->private_data = (void *)&ipanema_stats;
	else if (!strncmp(parent->d_iname, "idle_stats", 10))
		file->private_data = (void *)&idle_stats;
	else
		return -EPERM;

	return 0;
}

ssize_t sched_monitor_sched_class_stats_read(struct file *file,
					     char __user *user_buf,
					     size_t count, loff_t *ppos)
{
	int ret, i, cpu;
	size_t n = 0;
	char *buf;
	struct sched_stats *s;
	struct idle_stats *is;

	if (*ppos != 0)
		return 0;

	ret = kstrtoint(F_DENTRY(file)->d_name.name, 10, &cpu);
	if (ret)
		return ret;

	buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	if (file->private_data == &idle_stats) {
		is = per_cpu_ptr(file->private_data, cpu);
		n += scnprintf(buf + n, PAGE_SIZE - n,
			       "Idle: %llu ns (%llu hits)\n",
			       is->time, is->hits);
	} else {
		s = per_cpu_ptr(file->private_data, cpu);
		for (i = 0; i < NR_EVENTS; i++) {
			n += scnprintf(buf + n, PAGE_SIZE - n,
				       "%19s: %llu ns (%llu hits)\n",
				       evts_names[i], s->time[i], s->hits[i]);
			if (n >= PAGE_SIZE)
				break;
		}
	}

	n = min(n, count);
	copy_to_user(user_buf, buf, n);
	*ppos += n;

	kfree(buf);

	return n;
}

static const struct file_operations sched_monitor_sched_class_fops = {
	.open   = sched_monitor_sched_class_stats_open,
	.llseek = default_llseek,
	.read   = sched_monitor_sched_class_stats_read,
};

static int __init monitor_debugfs_init(void)
{
	int cpu;
	char buf[10];

	sched_monitor_dir = debugfs_create_dir("sched_monitor", NULL);
	if (!sched_monitor_dir)
		goto exit;

	fair_monitor = debugfs_create_file("fair", 0444, sched_monitor_dir,
					   NULL, &sched_monitor_file_ops);
	ipanema_monitor = debugfs_create_file("ipanema", 0444,
					      sched_monitor_dir, NULL,
					      &sched_monitor_file_ops);

	debugfs_create_bool("enable", 0666, sched_monitor_dir,
			    &sched_monitor_enabled);
	debugfs_create_bool("enable_fair", 0666, sched_monitor_dir,
			    &sched_monitor_fair_enabled);
	debugfs_create_bool("enable_ipanema", 0666, sched_monitor_dir,
			    &sched_monitor_ipanema_enabled);
	debugfs_create_bool("enable_idle", 0666, sched_monitor_dir,
			    &sched_monitor_idle_enabled);

	debugfs_create_file("reset", 0222, sched_monitor_dir, NULL,
			    &sched_monitor_reset_fops);

	time_dir_debugfs = debugfs_create_dir("sched_time", sched_monitor_dir);
	fair_dir_debugfs = debugfs_create_dir("fair_stats", sched_monitor_dir);
	ipanema_dir_debugfs = debugfs_create_dir("ipanema_stats",
						 sched_monitor_dir);
	idle_dir_debugfs = debugfs_create_dir("idle_stats",
					      sched_monitor_dir);
	debugfs_create_atomic64_t("nr_runnable", 0444, idle_dir_debugfs,
				  &(wc_stats.nr_runnable));
	debugfs_create_atomic64_t("nr_busy", 0444, idle_dir_debugfs,
				  &(wc_stats.nr_busy));
	debugfs_create_atomic64_t("time_not_wc", 0444, idle_dir_debugfs,
				  &(wc_stats.time));

	for_each_possible_cpu(cpu) {
		snprintf(buf, 10, "%d", cpu);
		debugfs_create_u64(buf, 0444, time_dir_debugfs,
				   (u64 *)&per_cpu(sched_time, cpu));
		debugfs_create_file(buf, 0444, fair_dir_debugfs, NULL,
				    &sched_monitor_sched_class_fops);
		debugfs_create_file(buf, 0444, ipanema_dir_debugfs, NULL,
				    &sched_monitor_sched_class_fops);
		debugfs_create_file(buf, 0444, idle_dir_debugfs, NULL,
				    &sched_monitor_sched_class_fops);
	}

	return 0;
exit:
	return -ENOMEM;
}
late_initcall(monitor_debugfs_init);
