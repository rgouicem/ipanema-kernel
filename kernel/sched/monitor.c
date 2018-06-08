#include <linux/slab.h>
#include <linux/cpumask.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>

#include "sched.h"
#include "ipanema_common.h"
#include "monitor.h"

#define F_DENTRY(filp) ((filp)->f_path.dentry)

#ifdef CONFIG_SCHED_MONITOR

#if defined(CONFIG_SCHED_MONITOR_FAIR) || defined(CONFIG_SCHED_MONITOR_IPANEMA)
static char *evts_names[] = {
	"enqueue_task", "dequeue_task", "yield_task", "yield_to_task",
	"check_preempt_curr", "pick_next_task", "put_prev_task",
	"select_task_rq", "migrate_task_rq", "task_woken", "rq_online",
	"rq_offline", "set_curr_task", "task_tick", "task_fork", "task_dead",
	"switched_from", "switched_to", "prio_changed", "lb_periodic"
};
#endif

static struct dentry *sched_monitor_dir;
bool sched_monitor_enabled;

#ifdef CONFIG_SCHED_MONITOR_CORE
DEFINE_PER_CPU(u64, sched_time);
DEFINE_PER_CPU(u64, sched_time_start);
DEFINE_PER_CPU(bool, sched_monitoring);
DEFINE_PER_CPU(void *, sched_monitoring_fn);
static struct dentry *time_dir_debugfs;
#endif	/* CONFIG_SCHED_MONITOR_CORE */

#ifdef CONFIG_SCHED_MONITOR_FAIR
DEFINE_PER_CPU(struct sched_stats, fair_stats);
bool sched_monitor_fair_enabled;
static struct dentry *fair_dir_debugfs;

#ifdef CONFIG_SCHED_MONITOR_FAIR_IDLE_BALANCING
static struct dentry *fair_idle_balance_dir_debugfs;
DEFINE_PER_CPU(struct idle_balance_stats, fair_idle_balance_stats);
#endif	/* SCHED_MONITOR_FAIR_IDLE_BALANCING */

#endif	/* CONFIG_SCHED_MONITOR_FAIR */

#ifdef CONFIG_SCHED_MONITOR_IPANEMA
DEFINE_PER_CPU(struct sched_stats, ipanema_stats);
bool sched_monitor_ipanema_enabled;
static struct dentry *ipanema_dir_debugfs;

#ifdef CONFIG_SCHED_MONITOR_IPANEMA_IDLE_BALANCING
static struct dentry *ipanema_idle_balance_dir_debugfs;
DEFINE_PER_CPU(struct idle_balance_stats, ipanema_idle_balance_stats);
#endif	/* SCHED_MONITOR_IPANEMA_IDLE_BALANCING */

#endif	/* CONFIG_SCHED_MONITOR_IPANEMA */

#ifdef CONFIG_SCHED_MONITOR_IDLE
DEFINE_PER_CPU(struct idle_stats, idle_stats);
bool sched_monitor_idle_enabled;
DECLARE_PER_CPU(u64, last_sched);
static struct dentry *idle_dir_debugfs;
#endif	/* CONFIG_SCHED_MONITOR_IDLE */

#ifdef CONFIG_SCHED_MONITOR_IDLE_WC
struct wc_stats wc_stats;
#endif	/* CONFIG_SCHED_MONITOR_IDLE_WC */

#ifdef CONFIG_SCHED_MONITOR_TRACER
static struct dentry *tracer_dir_debugfs;
bool sched_monitor_tracer_enabled;
DEFINE_PER_CPU(struct sched_tracer_log, sched_tracer_log);
#endif	/* CONFIG_SCHED_MONITOR_TRACER */


void reset_stats(void)
{
	int cpu;
	struct rq_flags rf;

#if defined(CONFIG_SCHED_MONITOR_FAIR) || defined(CONFIG_SCHED_MONITOR_IPANEMA)
	struct sched_stats *s;
#endif

#if defined(CONFIG_SCHED_MONITOR_FAIR_IDLE_BALANCING) || defined(CONFIG_SCHED_MONITOR_IPANEMA_IDLE_BALANCING)
	struct idle_balance_stats *ibs;
#endif

#ifdef CONFIG_SCHED_MONITOR_IDLE
	struct idle_stats *i;
#endif

	for_each_possible_cpu(cpu) {
		rq_lock(cpu_rq(cpu), &rf);
#ifdef CONFIG_SCHED_MONITOR_FAIR
		s = per_cpu_ptr(&fair_stats, cpu);
		memset(s, 0, sizeof(struct sched_stats));
#ifdef CONFIG_SCHED_MONITOR_FAIR_IDLE_BALANCING
		ibs = per_cpu_ptr(&fair_idle_balance_stats, cpu);
		memset(ibs, 0, sizeof(struct idle_balance_stats));
#endif
#endif

#ifdef CONFIG_SCHED_MONITOR_IPANEMA
		s = per_cpu_ptr(&ipanema_stats, cpu);
		memset(s, 0, sizeof(struct sched_stats));
#ifdef CONFIG_SCHED_MONITOR_IPANEMA_IDLE_BALANCING
		ibs = per_cpu_ptr(&ipanema_idle_balance_stats, cpu);
		memset(ibs, 0, sizeof(struct idle_balance_stats));
#endif
#endif

#ifdef CONFIG_SCHED_MONITOR_IDLE
		i = per_cpu_ptr(&idle_stats, cpu);
		i->time = i->hits = 0;
		*per_cpu_ptr(&last_sched, cpu) = cpu_clock(cpu);
#endif

#ifdef CONFIG_SCHED_MONITOR_CORE
		per_cpu(sched_time, cpu) = 0;
#endif

		rq_unlock(cpu_rq(cpu), &rf);
	}

#ifdef CONFIG_SCHED_MONITOR_IDLE_WC
	atomic64_set(&(wc_stats.time), 0);
#endif
}


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

#ifdef CONFIG_SCHED_MONITOR_FAIR
	if (!strncmp(parent->d_iname, "fair_stats", 10))
		file->private_data = (void *)&fair_stats;
#endif
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	if (!strncmp(parent->d_iname, "ipanema_stats", 13))
		file->private_data = (void *)&ipanema_stats;
#endif
#ifdef CONFIG_SCHED_MONITOR_IDLE
	if (!strncmp(parent->d_iname, "idle_stats", 10))
		file->private_data = (void *)&idle_stats;
#endif

	return 0;
}

ssize_t sched_monitor_sched_class_stats_read(struct file *file,
					     char __user *user_buf,
					     size_t count, loff_t *ppos)
{
	int ret, cpu;
	size_t n = 0;
	char *buf;
#if defined(CONFIG_SCHED_MONITOR_FAIR) || defined(CONFIG_SCHED_MONITOR_IPANEMA)
	struct sched_stats *s;
	int i;
#endif
#ifdef CONFIG_SCHED_MONITOR_IDLE
	struct idle_stats *is;
#endif

	if (*ppos != 0)
		return 0;

	ret = kstrtoint(F_DENTRY(file)->d_name.name, 10, &cpu);
	if (ret)
		return ret;

	buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	pr_info("%s:%d: \n", __FUNCTION__, __LINE__);

#ifdef CONFIG_SCHED_MONITOR_IDLE
	if (file->private_data == &idle_stats) {
		pr_info("%s:%d: \n", __FUNCTION__, __LINE__);
		is = per_cpu_ptr(file->private_data, cpu);
		n += scnprintf(buf + n, PAGE_SIZE - n,
			       "Idle: %llu ns (%llu hits)\n",
			       is->time, is->hits);
		goto end;
	}
#endif

#if defined(CONFIG_SCHED_MONITOR_FAIR) || defined(CONFIG_SCHED_MONITOR_IPANEMA)
	pr_info("%s:%d: \n", __FUNCTION__, __LINE__);
	s = per_cpu_ptr(file->private_data, cpu);
	for (i = 0; i < NR_EVENTS; i++) {
		n += scnprintf(buf + n, PAGE_SIZE - n,
			       "%19s: %llu ns (%llu hits)\n",
			       evts_names[i], s->time[i], s->hits[i]);
		if (n >= PAGE_SIZE)
			break;
	}
#endif
	// this goto is here to remove a compilation warning with some options..
	goto end;

end:
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

#ifdef CONFIG_SCHED_MONITOR_TRACER

static void *tracer_seq_start(struct seq_file *s, loff_t *pos)
{
	unsigned long cpu = (unsigned long) s->private;
	struct sched_tracer_log *log = per_cpu_ptr(&sched_tracer_log, cpu);
	unsigned long flags;
	void *ret = NULL;

	spin_lock_irqsave(&log->lock, flags);

	if (*pos == 0 && log->dropped) {
		seq_printf(s, "Dropped %llu events!!!!\n", log->dropped);
		log->dropped = 0;
	}

	if (log->consumer == log->producer)
		goto end;

	ret = (void *) &log->events[log->consumer];

end:
	spin_unlock_irqrestore(&log->lock, flags);
	return ret;
}

static void tracer_seq_stop(struct seq_file *s, void *v)
{
}

static void *tracer_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	unsigned long cpu = (unsigned long) s->private;
	struct sched_tracer_log *log = per_cpu_ptr(&sched_tracer_log, cpu);
	unsigned long flags;
	void *ret = NULL;

	spin_lock_irqsave(&log->lock, flags);

	++*pos;
	log->consumer++;
	if (unlikely(log->consumer >= log->size))
		log->consumer = 0;

	if (log->consumer == log->producer)
		goto end;

	ret = (void *) &log->events[log->consumer];

end:
	spin_unlock_irqrestore(&log->lock, flags);
	return ret;
}

static char *sched_tracer_events_str[] = {
	"FORK",
	"EXEC",
	"EXIT",
	"MIGRATE",
	"IDLE_BALANCE",
	"PERIODIC_BALANCE",
};

static int tracer_seq_show(struct seq_file *s, void *v)
{
	struct sched_tracer_event *evt = v;

	seq_printf(s, "%llu %s %d %d %d\n",
		   evt->timestamp, sched_tracer_events_str[evt->event],
		   evt->pid, evt->arg0, evt->arg1);

	return 0;
}

static const struct seq_operations tracer_seq_ops = {
	.start = tracer_seq_start,
	.next  = tracer_seq_next,
	.stop  = tracer_seq_stop,
	.show  = tracer_seq_show
};

static int sched_monitor_tracer_open(struct inode *inode, struct file *file)
{
	int ret;
	unsigned long cpu;
	char *filename = file->f_path.dentry->d_iname;
	struct seq_file *sf;

	ret = seq_open(file, &tracer_seq_ops);
	if (ret != 0)
		return ret;

	if (kstrtoul(filename, 10, &cpu) != 0)
		return -EINVAL;

	sf = (struct seq_file *) file->private_data;
	sf->private = (void *) cpu;

	return 0;
}

static const struct file_operations sched_monitor_tracer_fops = {
	.open    = sched_monitor_tracer_open,
	.llseek  = seq_lseek,
	.read    = seq_read,
	.release = seq_release,
};

static int sched_monitor_tracer_init(void)
{
	int cpu, ret;
	char buf[10];
	struct dentry *tracer_log_dir;
	struct sched_tracer_log *log;
	size_t buffer_size = CONFIG_SCHED_MONITOR_TRACER_BUFFER_SIZE << 20; /* convert MiB -> B */

	/* Allocate per-cpu buffers */
	buffer_size -= (buffer_size % sizeof(struct sched_tracer_event)); /* align buffer_size */
	for_each_possible_cpu(cpu) {
		log = per_cpu_ptr(&sched_tracer_log, cpu);
		log->events = vmalloc(buffer_size);
		if (!log->events) {
			ret = -ENOMEM;
			goto undo;
		}
		log->dropped = log->producer = log->consumer = 0;
		log->size = buffer_size / sizeof(struct sched_tracer_event);
		spin_lock_init(&log->lock);
	}

	/* Create files in /sys/kerel/debug/sched_monitor/tracer */
	tracer_dir_debugfs = debugfs_create_dir("tracer", sched_monitor_dir);
	tracer_log_dir = debugfs_create_dir("logs", tracer_dir_debugfs);
	debugfs_create_bool("enable_tracer", 0666, tracer_dir_debugfs,
			    &sched_monitor_tracer_enabled);

	for_each_possible_cpu(cpu) {
		snprintf(buf, 10, "%d", cpu);

		debugfs_create_file(buf, 0444, tracer_log_dir, NULL,
				    &sched_monitor_tracer_fops);
	}

	return 0;

undo:
	for (cpu = cpu - 1; cpu >= 0; cpu--) {
		log = per_cpu_ptr(&sched_tracer_log, cpu);
		free_pages_exact(log->events, buffer_size);
	}

	pr_err("sched_monitor: tracer initialization failed\n");

	return ret;
}

#else  /* !CONFIG_SCHED_MONITOR_TRACER */

static int sched_monitor_tracer_init(void)
{
	return 0;
}

#endif	/* CONFIG_SCHED_MONITOR_TRACER */

static int __init monitor_debugfs_init(void)
{
	int cpu;
	char buf[10];

	sched_monitor_dir = debugfs_create_dir("sched_monitor", NULL);
	if (!sched_monitor_dir)
		goto exit;

	debugfs_create_bool("enable", 0666, sched_monitor_dir,
			    &sched_monitor_enabled);
	debugfs_create_file("reset", 0222, sched_monitor_dir, NULL,
			    &sched_monitor_reset_fops);

#ifdef CONFIG_SCHED_MONITOR_CORE
	time_dir_debugfs = debugfs_create_dir("sched_time", sched_monitor_dir);
#endif

#ifdef CONFIG_SCHED_MONITOR_FAIR
	debugfs_create_bool("enable_fair", 0666, sched_monitor_dir,
			    &sched_monitor_fair_enabled);
	fair_dir_debugfs = debugfs_create_dir("fair_stats", sched_monitor_dir);
#ifdef CONFIG_SCHED_MONITOR_FAIR_IDLE_BALANCING
	fair_idle_balance_dir_debugfs = debugfs_create_dir("idle_balancing",
							   fair_dir_debugfs);
#endif
#endif

#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	debugfs_create_bool("enable_ipanema", 0666, sched_monitor_dir,
			    &sched_monitor_ipanema_enabled);
	ipanema_dir_debugfs = debugfs_create_dir("ipanema_stats",
						 sched_monitor_dir);
#ifdef CONFIG_SCHED_MONITOR_IPANEMA_IDLE_BALANCING
	ipanema_idle_balance_dir_debugfs = debugfs_create_dir("idle_balancing",
							      ipanema_dir_debugfs);
#endif
#endif

#ifdef CONFIG_SCHED_MONITOR_IDLE
	debugfs_create_bool("enable_idle", 0666, sched_monitor_dir,
			    &sched_monitor_idle_enabled);
	idle_dir_debugfs = debugfs_create_dir("idle_stats",
					      sched_monitor_dir);
#endif

#ifdef CONFIG_SCHED_MONITOR_IDLE_WC
	debugfs_create_atomic64_t("nr_runnable", 0444, idle_dir_debugfs,
				  &(wc_stats.nr_runnable));
	debugfs_create_atomic64_t("nr_busy", 0444, idle_dir_debugfs,
				  &(wc_stats.nr_busy));
	debugfs_create_atomic64_t("time_not_wc", 0444, idle_dir_debugfs,
				  &(wc_stats.time));
#endif

	sched_monitor_tracer_init();

	for_each_possible_cpu(cpu) {
		snprintf(buf, 10, "%d", cpu);
#ifdef CONFIG_SCHED_MONITOR_CORE
		debugfs_create_u64(buf, 0444, time_dir_debugfs,
				   (u64 *)&per_cpu(sched_time, cpu));
#endif

#ifdef CONFIG_SCHED_MONITOR_FAIR
		debugfs_create_file(buf, 0444, fair_dir_debugfs, NULL,
				    &sched_monitor_sched_class_fops);
#ifdef CONFIG_SCHED_MONITOR_FAIR_IDLE_BALANCING
		debugfs_create_u64(buf, 0444, fair_idle_balance_dir_debugfs,
				   (u64 *)&per_cpu_ptr(&fair_idle_balance_stats,
						       cpu)->hits);
#endif
#endif

#ifdef CONFIG_SCHED_MONITOR_IPANEMA
		debugfs_create_file(buf, 0444, ipanema_dir_debugfs, NULL,
				    &sched_monitor_sched_class_fops);
#ifdef CONFIG_SCHED_MONITOR_IPANEMA_IDLE_BALANCING
		debugfs_create_u64(buf, 0444, ipanema_idle_balance_dir_debugfs,
				   (u64 *)&per_cpu_ptr(&ipanema_idle_balance_stats,
						       cpu)->hits);
#endif
#endif

#ifdef CONFIG_SCHED_MONITOR_IDLE
		debugfs_create_file(buf, 0444, idle_dir_debugfs, NULL,
				    &sched_monitor_sched_class_fops);
#endif

#ifdef CONFIG_SCHED_TRACER
#endif
	}

	return 0;
exit:
	return -ENOMEM;
}
late_initcall(monitor_debugfs_init);

#endif /* CONFIG_SCHED_MONITOR */
