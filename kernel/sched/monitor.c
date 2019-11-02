#include <linux/slab.h>
#include <linux/cpumask.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>

#include "sched.h"
#include "ipanema.h"
#include "monitor.h"

#define F_DENTRY(filp) ((filp)->f_path.dentry)

#ifdef CONFIG_SCHED_MONITOR

#if defined(CONFIG_SCHED_MONITOR_FAIR) || defined(CONFIG_SCHED_MONITOR_IPANEMA)
static char *evts_names[] = {
	"enqueue_task", "dequeue_task", "yield_task", "yield_to_task",
	"check_preempt_curr", "pick_next_task", "put_prev_task",
	"select_task_rq", "migrate_task_rq", "task_woken", "rq_online",
	"rq_offline", "set_curr_task", "task_tick", "task_fork", "task_dead",
	"switched_from", "switched_to", "prio_changed", "lb_periodic", "lb_idle"
};
#endif

static struct dentry *sched_monitor_dir;

#ifdef CONFIG_SCHED_MONITOR_CORE
DEFINE_PER_CPU(u64, sched_time);
DEFINE_PER_CPU(u64, sched_time_start);
DEFINE_PER_CPU(bool, sched_monitoring);
DEFINE_PER_CPU(void *, sched_monitoring_fn);
bool sched_monitor_sched_enabled;
EXPORT_SYMBOL(sched_monitor_sched_enabled);
#endif	/* CONFIG_SCHED_MONITOR_CORE */

#ifdef CONFIG_SCHED_MONITOR_FAIR
DEFINE_PER_CPU(struct sched_stats, fair_stats);
bool sched_monitor_fair_enabled;
EXPORT_SYMBOL(sched_monitor_fair_enabled);
#endif	/* CONFIG_SCHED_MONITOR_FAIR */

#ifdef CONFIG_SCHED_MONITOR_IPANEMA
DEFINE_PER_CPU(struct sched_stats, ipanema_stats);
bool sched_monitor_ipanema_enabled;
EXPORT_SYMBOL(sched_monitor_ipanema_enabled);
#endif	/* CONFIG_SCHED_MONITOR_IPANEMA */

#ifdef CONFIG_SCHED_MONITOR_IDLE
DEFINE_PER_CPU(struct idle_stats, idle_stats);
DECLARE_PER_CPU(u64, last_sched);
bool sched_monitor_idle_enabled;
EXPORT_SYMBOL(sched_monitor_idle_enabled);
#endif	/* CONFIG_SCHED_MONITOR_IDLE */

#ifdef CONFIG_SCHED_MONITOR_TRACER
DEFINE_PER_CPU(struct sched_tracer_log, sched_tracer_log);
EXPORT_SYMBOL(sched_tracer_log);
bool sched_monitor_tracer_enabled;
EXPORT_SYMBOL(sched_monitor_tracer_enabled);
#endif	/* CONFIG_SCHED_MONITOR_TRACER */


void reset_stats(void)
{
	int cpu;
	struct rq_flags rf;


#ifdef CONFIG_SCHED_MONITOR_IDLE
	struct idle_stats *i;
#endif

	for_each_possible_cpu(cpu) {
		rq_lock(cpu_rq(cpu), &rf);

#ifdef CONFIG_SCHED_MONITOR_IDLE
		i = per_cpu_ptr(&idle_stats, cpu);
		i->time = i->hits = 0;
		*per_cpu_ptr(&last_sched, cpu) = cpu_clock(cpu);
#endif

		rq_unlock(cpu_rq(cpu), &rf);
	}
}

#ifdef CONFIG_SCHED_MONITOR_CORE
static void reset_sched(void)
{
	int cpu;
	struct rq_flags rf;

	for_each_possible_cpu(cpu) {
		rq_lock_irqsave(cpu_rq(cpu), &rf);
		per_cpu(sched_time, cpu) = 0;
		rq_unlock_irqrestore(cpu_rq(cpu), &rf);
	}
}
#endif/* CONFIG_SCHED_MONITOR_CORE */

#ifdef CONFIG_SCHED_MONITOR_FAIR
static void reset_fair(void)
{
	int cpu;
	struct rq_flags rf;
	struct sched_stats *s;

	for_each_possible_cpu(cpu) {
		rq_lock_irqsave(cpu_rq(cpu), &rf);
		s = per_cpu_ptr(&fair_stats, cpu);
		memset(s, 0, sizeof(struct sched_stats));
		rq_unlock_irqrestore(cpu_rq(cpu), &rf);
	}
}
#endif/* CONFIG_SCHED_MONITOR_FAIR */

#ifdef CONFIG_SCHED_MONITOR_IPANEMA
static void reset_ipanema(void)
{
	int cpu;
	struct rq_flags rf;
	struct sched_stats *s;

	for_each_possible_cpu(cpu) {
		rq_lock_irqsave(cpu_rq(cpu), &rf);
		s = per_cpu_ptr(&ipanema_stats, cpu);
		memset(s, 0, sizeof(struct sched_stats));
		rq_unlock_irqrestore(cpu_rq(cpu), &rf);
	}
}
#endif/* CONFIG_SCHED_MONITOR_IPANEMA */

#ifdef CONFIG_SCHED_MONITOR_IDLE
static void reset_idle(void)
{
	int cpu;
	struct rq_flags rf;
	struct idle_stats *i;

	for_each_possible_cpu(cpu) {
		rq_lock_irqsave(cpu_rq(cpu), &rf);
		i = per_cpu_ptr(&idle_stats, cpu);
		i->time = i->hits = 0;
		*per_cpu_ptr(&last_sched, cpu) = cpu_clock(cpu);
		rq_unlock_irqrestore(cpu_rq(cpu), &rf);
	}
}
#endif/* CONFIG_SCHED_MONITOR_IDLE */

#ifdef CONFIG_SCHED_MONITOR_TRACER
static void reset_tracer(void)
{
	int cpu;
	unsigned long flags;
	struct sched_tracer_log *log;

	for_each_possible_cpu(cpu) {
		log = per_cpu_ptr(&sched_tracer_log, cpu);

		spin_lock_irqsave(&log->lock, flags);
		log->consumer = log->producer;
		log->dropped = 0;
		spin_unlock_irqrestore(&log->lock, flags);
	}
}
#endif	/* CONFIG_SCHED_MONITOR_TRACER */

ssize_t sched_monitor_reset_write(struct file *file,
				  const char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	struct dentry *parent = F_DENTRY(file)->d_parent;

	if (!parent)
		return -EACCES;

#ifdef CONFIG_SCHED_MONITOR_CORE
	if (!strncmp(parent->d_iname, "sched", 6)) {
		reset_sched();
		return count;
	}
#endif
#ifdef CONFIG_SCHED_MONITOR_FAIR
	if (!strncmp(parent->d_iname, "fair", 5)) {
		reset_fair();
		return count;
	}
#endif
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	if (!strncmp(parent->d_iname, "ipanema", 8)) {
		reset_ipanema();
		return count;
	}
#endif
#ifdef CONFIG_SCHED_MONITOR_IDLE
	if (!strncmp(parent->d_iname, "idle", 5)) {
		reset_idle();
		return count;
	}
#endif
#ifdef CONFIG_SCHED_MONITOR_TRACER
	if (!strncmp(parent->d_iname, "tracer", 7)) {
		reset_tracer();
		return count;
	}
#endif

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
	struct dentry *gparent;

	if (!parent)
		return -EACCES;

	gparent = parent->d_parent;
	if (!gparent)
		return -EACCES;

#ifdef CONFIG_SCHED_MONITOR_FAIR
	if (!strncmp(gparent->d_iname, "fair", 5)) {
		file->private_data = (void *)&fair_stats;
		return 0;
	}
#endif
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	if (!strncmp(gparent->d_iname, "ipanema", 8)) {
		file->private_data = (void *)&ipanema_stats;
		return 0;
	}
#endif
#ifdef CONFIG_SCHED_MONITOR_IDLE
	if (!strncmp(gparent->d_iname, "idle", 5)) {
		file->private_data = (void *)&idle_stats;
		return 0;
	}
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

#ifdef CONFIG_SCHED_MONITOR_IDLE
	if (file->private_data == &idle_stats) {
		is = per_cpu_ptr(file->private_data, cpu);
		n += scnprintf(buf + n, PAGE_SIZE - n,
			       "Idle: %llu ns (%llu hits)\n",
			       is->time, is->hits);
		goto end;
	}
#endif

#if defined(CONFIG_SCHED_MONITOR_FAIR) || defined(CONFIG_SCHED_MONITOR_IPANEMA)
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
	if (copy_to_user(user_buf, buf, n)) {
		n = -EFAULT;
		goto memfree;
	}
	*ppos += n;

memfree:
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
	unsigned long cpu = (unsigned long) s->private, flags;
	struct sched_tracer_log *log = per_cpu_ptr(&sched_tracer_log, cpu);
	int i;
	void *ret = NULL;

	spin_lock_irqsave(&log->lock, flags);

	if (*pos == 0 && log->dropped)
		pr_info("cpu%lu dropped %llu schedlog events\n", cpu, log->dropped);

	i = (log->consumer + *pos) % log->size;
	if (i == log->producer)
		goto end;

	ret = (void *) &log->events[i];

end:
	spin_unlock_irqrestore(&log->lock, flags);
	return ret;
}

static void tracer_seq_stop(struct seq_file *s, void *v)
{
}

static void *tracer_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	unsigned long cpu = (unsigned long) s->private, flags;
	struct sched_tracer_log *log = per_cpu_ptr(&sched_tracer_log, cpu);
	int i;
	void *ret = NULL;

	spin_lock_irqsave(&log->lock, flags);

	++*pos;
	i = (log->consumer + *pos) % log->size;
	if (i == log->producer)
		goto end;

	ret = (void *) &log->events[i];

end:
	spin_unlock_irqrestore(&log->lock, flags);
	return ret;
}

static char *sched_tracer_events_str[] = {
	"EXEC",	      /* timestamp EXEC pid */
	"EXIT",	      /* timestamp EXIT pid */
	"WAKEUP",     /* timestamp WAKEUP pid */
	"WAKEUP_NEW", /* timestamp WAKEUP_NEW pid */
	"BLOCK",      /* timestamp BLOCK pid */
	"BLOCK_IO",   /* timestamp BLOCK_IO pid */
	"FORK",	      /* timestamp FORK pid ppid fork */
	"TICK",       /* timestamp TICK pid need_resched */
	"CTX_SWITCH", /* timestamp CTX_SWITCH pid next */
	"MIGRATE",    /* timestamp MIGRATE pid old_cpu new_cpu */
	"RQ_SIZE",    /* timestamp RQ_SIZE current size count */
	"IDL_BLN_FAIR_BEG", /* timestamp IDL_BLN_FAIR_BEG pid sched_domain_addr */
	"IDL_BLN_FAIR_END", /* timestamp IDL_BLN_FAIR_END pid sched_group_addr */
	"PER_BLN_FAIR_BEG", /* timestamp PER_BLN_FAIR_BEG pid sched_domain_addr */
	"PER_BLN_FAIR_END", /* timestamp PER_BLN_FAIR_END pid sched_group_addr */
	"IDL_BLN_IPA_BEG", /* timestamp IDL_BLN_BEG pid sched_domain_addr */
	"IDL_BLN_IPA_END", /* timestamp IDL_BLN_END pid sched_group_addr */
	"PER_BLN_IPA_BEG", /* timestamp PER_BLN_BEG pid sched_domain_addr */
	"PER_BLN_IPA_END", /* timestamp PER_BLN_END pid sched_group_addr */
	"WAIT_FUTEX",	  /* timestamp WAIT_FUTEX pid addr */
	"WAKE_FUTEX",	  /* timestamp WAKE_FUTEX pid addr */
	"WAKER_FUTEX",	  /* timestamp WAKER_FUTEX pid addr */
	"UNBLOCK_PREPARE_IPA_BEG", /* timestamp UNBLOCK_PREPARE_IPA_BEG pid */
	"UNBLOCK_PREPARE_IPA_END", /* timestamp UNBLOCK_PREPARE_IPA_END pid */
	"USER_EVT", /* timestamp USER_EVT pid */
	"WAIT_PID", /* timestamp WAIT_PID pid waited_pid */
	"DEBUG_EVT",
};

static int tracer_seq_show(struct seq_file *s, void *v)
{
	struct sched_tracer_event *evt = v;

	/* text output */
	switch (evt->event) {
	/* no args */
	case EXEC_EVT:
	case EXIT_EVT:
	case WAKEUP:
	case WAKEUP_NEW:
	case BLOCK:
	case BLOCK_IO:
		seq_printf(s, "%llu %s %d\n",
			   evt->timestamp, sched_tracer_events_str[evt->event],
			   evt->pid);
		break;
	/* one pointer arg */
	case IDL_BLN_FAIR_BEG:
	case IDL_BLN_FAIR_END:
	case PER_BLN_FAIR_BEG:
	case PER_BLN_FAIR_END:
	case IDL_BLN_IPA_BEG:
	case IDL_BLN_IPA_END:
	case PER_BLN_IPA_BEG:
	case PER_BLN_IPA_END:
	case WAIT_FUTEX:
	case WAKE_FUTEX:
	case WAKER_FUTEX:
		seq_printf(s, "%llu %s %d 0x%p\n",
			   evt->timestamp, sched_tracer_events_str[evt->event],
			   evt->pid, (void *)evt->addr);
		break;
	/* one int arg */
	case FORK_EVT:
	case TICK_EVT:
	case CTX_SWITCH:
	case WAIT_PID:
		seq_printf(s, "%llu %s %d %d\n",
			   evt->timestamp, sched_tracer_events_str[evt->event],
			   evt->pid, evt->arg0);
		break;
	/* two int args */
	case MIGRATE_EVT:
	case RQ_SIZE:
		seq_printf(s, "%llu %s %d %d %d\n",
			   evt->timestamp, sched_tracer_events_str[evt->event],
			   evt->pid, evt->arg0, evt->arg1);
		break;
	default:
		seq_printf(s, "%llu UNKNOWN %d\n",
			   evt->timestamp, evt->pid);
	}

	return 0;
}

static int tracer_seq_show_raw(struct seq_file *s, void *v)
{
	struct sched_tracer_event *evt = v;

	/* binary output */
	seq_write(s, evt, sizeof(struct sched_tracer_event));

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

static const struct seq_operations tracer_seq_ops_raw = {
	.start = tracer_seq_start,
	.next  = tracer_seq_next,
	.stop  = tracer_seq_stop,
	.show  = tracer_seq_show_raw
};

static int sched_monitor_tracer_open_raw(struct inode *inode, struct file *file)
{
	int ret;
	unsigned long cpu;
	char *filename = file->f_path.dentry->d_iname;
	struct seq_file *sf;

	ret = seq_open(file, &tracer_seq_ops_raw);
	if (ret != 0)
		return ret;

	if (kstrtoul(filename, 10, &cpu) != 0)
		return -EINVAL;

	sf = (struct seq_file *) file->private_data;
	sf->private = (void *) cpu;

	return 0;
}

static const struct file_operations sched_monitor_tracer_fops_raw = {
	.open    = sched_monitor_tracer_open_raw,
	.llseek  = seq_lseek,
	.read    = seq_read,
	.release = seq_release,
};

static void *monitor_proc_start(struct seq_file *s, loff_t *pos)
{
	if (*pos >= SCHED_MONITOR_TRACER_NR_EVENTS)
		return NULL;
	return pos;
}

static void *monitor_proc_next(struct seq_file *s, void *v, loff_t *pos)
{
	*pos = *pos + 1;
	if (*pos >= SCHED_MONITOR_TRACER_NR_EVENTS)
		return NULL;
	return pos;
}

static void monitor_proc_stop(struct seq_file *s, void *v)
{}

static int monitor_proc_show(struct seq_file *s, void *v)
{
	loff_t *pos = v;

	seq_printf(s, "%lld %s\n", *pos, sched_tracer_events_str[*pos]);

	return 0;
}

static const struct seq_operations monitor_proc_seq_ops = {
	.start = monitor_proc_start,
	.next  = monitor_proc_next,
	.stop  = monitor_proc_stop,
	.show  = monitor_proc_show
};

static int monitor_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &monitor_proc_seq_ops);
}

static const struct file_operations sched_monitor_events_fops = {
	.open = monitor_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};

ssize_t sched_monitor_user_event_write(struct file *file,
				  const char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	u64 val;
	size_t size = min(sizeof(val), count);
	if(copy_from_user(&val,user_buf,size))
		goto out;
	// pr_info("%llu\n", val);
	sched_monitor_trace(USER_EVT, task_cpu(current), current,
			    val>>32,
			    val & 0x00000000ffffffff);
out:
	return count;
}

static const struct file_operations sched_monitor_user_event_fops = {
	.open   = simple_open,
	.llseek = default_llseek,
	.write  = sched_monitor_user_event_write,
};

bool sched_monitor_tracer_event_enabled[SCHED_MONITOR_TRACER_NR_EVENTS];
EXPORT_SYMBOL(sched_monitor_tracer_event_enabled);

static int sched_monitor_tracer_init(void)
{
	int cpu, ret, i;
	char buf[10];
	struct dentry *tracer_dir, *tracer_log_dir, *events_dir, *raw_dir;
	struct sched_tracer_log *log;
	size_t buffer_size = CONFIG_SCHED_MONITOR_TRACER_BUFFER_SIZE << 20;

	/* Allocate per-cpu buffers */
	buffer_size -= (buffer_size % sizeof(struct sched_tracer_event));
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
	tracer_dir = debugfs_create_dir("tracer", sched_monitor_dir);
	debugfs_create_bool("enable", 0666, tracer_dir,
			    &sched_monitor_tracer_enabled);
	debugfs_create_file("reset", 0666, tracer_dir, NULL,
			    &sched_monitor_reset_fops);

	events_dir = debugfs_create_dir("events", tracer_dir);
	for (i = 0; i < SCHED_MONITOR_TRACER_NR_EVENTS; i++) {
		sched_monitor_tracer_event_enabled[i] = false;
		debugfs_create_bool(sched_tracer_events_str[i], 0666,
				    events_dir,
				    sched_monitor_tracer_event_enabled + i);
	}

	tracer_log_dir = debugfs_create_dir("logs", tracer_dir);
	raw_dir = debugfs_create_dir("raw", tracer_dir);
	for_each_possible_cpu(cpu) {
		snprintf(buf, 10, "%d", cpu);

		debugfs_create_file(buf, 0444, tracer_log_dir, NULL,
				    &sched_monitor_tracer_fops);
		debugfs_create_file(buf, 0444, raw_dir, NULL,
				    &sched_monitor_tracer_fops_raw);
	}

	/* Create the /proc/sched_monitor_events file */
	proc_create("sched_monitor_events", 0444, NULL,
		    &sched_monitor_events_fops);


	debugfs_create_file("user_event", 0666, tracer_dir, NULL,
			    &sched_monitor_user_event_fops);

	return 0;

undo:
	for (cpu = cpu - 1; cpu >= 0; cpu--) {
		log = per_cpu_ptr(&sched_tracer_log, cpu);
		free_pages_exact(log->events, buffer_size);
	}

	pr_err("sched_monitor: tracer initialization failed\n");

	return ret;
}

#endif	/* CONFIG_SCHED_MONITOR_TRACER */

#ifdef CONFIG_SCHED_MONITOR_CORE

void sched_monitor_sched_init(void)
{
	int cpu;
	char buf[10];
	struct dentry *sched_dir, *sched_log_dir;

	sched_dir = debugfs_create_dir("sched", sched_monitor_dir);
	debugfs_create_bool("enable", 0666, sched_dir,
			    &sched_monitor_sched_enabled);
	debugfs_create_file("reset", 0666, sched_dir, NULL,
			    &sched_monitor_reset_fops);
	sched_log_dir = debugfs_create_dir("logs", sched_dir);

	for_each_possible_cpu(cpu) {
		snprintf(buf, 10, "%d", cpu);
		debugfs_create_u64(buf, 0444, sched_log_dir,
				   (u64 *)&per_cpu(sched_time, cpu));
	}
}

#endif	/* CONFIG_SCHED_MONITOR_CORE */

#ifdef CONFIG_SCHED_MONITOR_FAIR

void sched_monitor_fair_init(void)
{
	int cpu;
	char buf[10];
	struct dentry *fair_dir, *fair_log_dir;

	fair_dir = debugfs_create_dir("fair", sched_monitor_dir);
	debugfs_create_bool("enable", 0666, fair_dir,
			    &sched_monitor_fair_enabled);
	debugfs_create_file("reset", 0666, fair_dir, NULL,
			    &sched_monitor_reset_fops);
	fair_log_dir = debugfs_create_dir("logs", fair_dir);

	for_each_possible_cpu(cpu) {
		snprintf(buf, 10, "%d", cpu);
		debugfs_create_file(buf, 0444, fair_log_dir, NULL,
				    &sched_monitor_sched_class_fops);
	}
}

#endif	/* CONFIG_SCHED_MONITOR_FAIR */

#ifdef CONFIG_SCHED_MONITOR_IPANEMA

void sched_monitor_ipanema_init(void)
{
	int cpu;
	char buf[10];
	struct dentry *ipanema_dir, *ipanema_log_dir;

	ipanema_dir = debugfs_create_dir("ipanema", sched_monitor_dir);
	debugfs_create_bool("enable", 0666, ipanema_dir,
			    &sched_monitor_ipanema_enabled);
	debugfs_create_file("reset", 0666, ipanema_dir, NULL,
			    &sched_monitor_reset_fops);
	ipanema_log_dir = debugfs_create_dir("logs", ipanema_dir);

	for_each_possible_cpu(cpu) {
		snprintf(buf, 10, "%d", cpu);
		debugfs_create_file(buf, 0444, ipanema_log_dir, NULL,
				    &sched_monitor_sched_class_fops);
	}
}

#endif	/* CONFIG_SCHED_MONITOR_IPANEMA */

#ifdef CONFIG_SCHED_MONITOR_IDLE

void sched_monitor_idle_init(void)
{
	int cpu;
	char buf[10];
	struct dentry *idle_dir, *idle_log_dir;

	idle_dir = debugfs_create_dir("idle", sched_monitor_dir);
	debugfs_create_bool("enable", 0666, idle_dir,
			    &sched_monitor_idle_enabled);
	debugfs_create_file("reset", 0666, idle_dir, NULL,
			    &sched_monitor_reset_fops);
	idle_log_dir = debugfs_create_dir("logs", idle_dir);

	for_each_possible_cpu(cpu) {
		snprintf(buf, 10, "%d", cpu);
		debugfs_create_file(buf, 0444, idle_log_dir, NULL,
				    &sched_monitor_sched_class_fops);
	}
}

#endif	/* CONFIG_SCHED_MONITOR_IPANEMA */

static int __init monitor_debugfs_init(void)
{
	sched_monitor_dir = debugfs_create_dir("sched_monitor", NULL);
	if (!sched_monitor_dir)
		goto exit;

#ifdef CONFIG_SCHED_MONITOR_CORE
	sched_monitor_sched_init();
#endif

#ifdef CONFIG_SCHED_MONITOR_FAIR
	sched_monitor_fair_init();
#endif

#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	sched_monitor_ipanema_init();
#endif

#ifdef CONFIG_SCHED_MONITOR_IDLE
	sched_monitor_idle_init();
#endif

#ifdef CONFIG_SCHED_MONITOR_TRACER
	sched_monitor_tracer_init();
#endif

	return 0;
exit:
	return -ENOMEM;
}
late_initcall(monitor_debugfs_init);

#endif /* CONFIG_SCHED_MONITOR */
