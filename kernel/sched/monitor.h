#ifndef _SCHED_MONITOR_H_
#define _SCHED_MONITOR_H_

#include <linux/sched/clock.h>

/* Sched class events */
enum sched_class_event {
	ENQUEUE, DEQUEUE, YIELD, YIELD_TO, CHECK_PREEMPT_CURR, PICK_NEXT,
	PUT_PREV, SELECT_RQ, MIGRATE, WOKEN, RQ_ONLINE, RQ_OFFLINE, SET_CURR,
	TICK, FORK, DEAD, SWITCHED_FROM, SWITCHED_TO, PRIO_CHANGED, LB_PERIOD,
	LB_IDLE,
	NR_EVENTS    /* keep last in enum */
};

struct sched_stats {
	u64 time[NR_EVENTS];
	u64 hits[NR_EVENTS];
};

#ifdef CONFIG_SCHED_MONITOR_CORE

DECLARE_PER_CPU(u64, sched_time);
DECLARE_PER_CPU(u64, sched_time_start);
DECLARE_PER_CPU(bool, sched_monitoring);
DECLARE_PER_CPU(void *, sched_monitoring_fn);
extern bool sched_monitor_sched_enabled;

#endif	/* CONFIG_SCHED_MONITOR_CORE */

#ifdef CONFIG_SCHED_MONITOR_FAIR

DECLARE_PER_CPU(struct sched_stats, fair_stats);
extern bool sched_monitor_fair_enabled;

#endif /* CONFIG_SCHED_MONITOR_FAIR */

#ifdef CONFIG_SCHED_MONITOR_IPANEMA

DECLARE_PER_CPU(struct sched_stats, ipanema_stats);
extern bool sched_monitor_ipanema_enabled;

#endif /* CONFIG_SCHED_MONITOR_IPANEMA */

#ifdef CONFIG_SCHED_MONITOR_IDLE

struct idle_stats {
	u64 time, hits;
};

DECLARE_PER_CPU(struct idle_stats, idle_stats);
extern bool sched_monitor_idle_enabled;

#endif /* CONFIG_SCHED_MONITOR_IDLE */

#ifdef CONFIG_SCHED_MONITOR_TRACER

struct sched_tracer_event {
	u64 timestamp;
	pid_t pid;
	int event;
	union {
		struct {
			s32 arg0, arg1;
		};
		u64 addr;
	};
};

struct sched_tracer_log {
	struct sched_tracer_event *events;
	loff_t consumer, producer;
	u64 dropped;
	spinlock_t lock;
	size_t size;
};

enum sched_tracer_events {
	EXEC_EVT,    /* timestamp EXEC pid */
	EXIT_EVT,    /* timestamp EXIT pid */
	WAKEUP,      /* timestamp WAKEUP pid */
	WAKEUP_NEW,  /* timestamp WAKEUP_NEW pid */
	BLOCK,       /* timestamp BLOCK pid */
	BLOCK_IO,    /* timestamp BLOCK_IO pid */
	FORK_EVT,    /* timestamp FORK pid ppid */
	TICK_EVT,    /* timestamp TICK pid need_resched */
	CTX_SWITCH,  /* timestamp CTX_SWITCH pid next */
	MIGRATE_EVT, /* timestamp MIGRATE pid old_cpu new_cpu */
	RQ_SIZE,     /* timestamp RQ_SIZE current size count */
	IDL_BLN_FAIR_BEG, /* timestamp IDL_BLN_FAIR_BEG pid sched_domain_addr */
	IDL_BLN_FAIR_END, /* timestamp IDL_BLN_FAIR_END pid sched_group_addr */
	PER_BLN_FAIR_BEG, /* timestamp PER_BLN_FAIR_BEG pid sched_domain_addr */
	PER_BLN_FAIR_END, /* timestamp PER_BLN_FAIR_END pid sched_group_addr */
	IDL_BLN_IPA_BEG,  /* timestamp IDL_BLN_IPA_BEG pid sched_domain_addr */
	IDL_BLN_IPA_END,  /* timestamp IDL_BLN_IPA_END pid sched_group_addr */
	PER_BLN_IPA_BEG,  /* timestamp PER_BLN_IPA_BEG pid sched_domain_addr */
	PER_BLN_IPA_END,  /* timestamp PER_BLN_IPA_END pid sched_group_addr */
	WAIT_FUTEX,	  /* timestamp WAIT_FUTEX pid addr */
	WAKE_FUTEX,	  /* timestamp WAKE_FUTEX pid addr */
	WAKER_FUTEX,	  /* timestamp WAKER_FUTEX pid addr */
	UNBLOCK_PREPARE_IPA_BEG, /* timestamp UNBLOCK_PREPARE_IPA_BEG pid */
	SCHED_MONITOR_TRACER_NR_EVENTS,	/* keep last */
};
DECLARE_PER_CPU(struct sched_tracer_log, sched_tracer_log);
extern bool sched_monitor_tracer_enabled;
extern bool sched_monitor_tracer_event_enabled[SCHED_MONITOR_TRACER_NR_EVENTS];

#endif /* CONFIG_SCHED_MONITOR_TRACER */


void reset_stats(void);

#ifdef CONFIG_SCHED_MONITOR_CORE

#define sched_monitor_start(fn)						\
	do {								\
		if (likely(!sched_monitor_sched_enabled))		\
			break;						\
		if (this_cpu_read(sched_monitoring))			\
			break;						\
		this_cpu_write(sched_monitoring, true);			\
		this_cpu_write(sched_monitoring_fn, fn);		\
		this_cpu_write(sched_time_start, local_clock());	\
	} while (0)

#define sched_monitor_stop(fn)						\
	do {								\
		if (likely(!sched_monitor_sched_enabled))		\
			break;						\
		if (!this_cpu_ptr(&sched_monitoring))			\
			break;						\
		if (this_cpu_read(sched_monitoring_fn) != fn)		\
			break;						\
		this_cpu_add(sched_time,				\
			     local_clock() - this_cpu_read(sched_time_start)); \
		this_cpu_write(sched_monitoring, false);		\
		this_cpu_write(sched_monitoring_fn, NULL);		\
	} while (0)

#define sched_monitor_test()						\
	do {								\
		if (likely(!sched_monitor_sched_enabled))		\
			break;						\
		if (!this_cpu_read(sched_monitoring)) {			\
			pr_err("%s(): sched_monitor didn't catch me!\n", \
			       __func__);				\
			dump_stack();					\
		}							\
	} while (0)

#else  /* !CONFIG_SCHED_MONITOR_CORE */

#define sched_monitor_start(fn)
#define sched_monitor_stop(fn)
#define sched_monitor_test()

#endif	/* CONFIG_SCHED_MONITOR_CORE */

#ifdef CONFIG_SCHED_MONITOR_FAIR

#define sched_monitor_fair_start(start)				\
	do {							\
		if (unlikely(sched_monitor_fair_enabled))	\
			start = local_clock();			\
	} while (0)

#define sched_monitor_fair_stop(evt, start)				\
	do {								\
		if (unlikely(sched_monitor_fair_enabled && start != 0)) { \
			u64 delta = local_clock() - start;		\
			this_cpu_ptr(&fair_stats)->time[evt] += delta;	\
			this_cpu_ptr(&fair_stats)->hits[evt]++;		\
		}							\
	} while (0)

#else  /* !CONFIG_SCHED_MONITOR_FAIR */

#define sched_monitor_fair_start(start)
#define sched_monitor_fair_stop(evt, start)

#endif	/* CONFIG_SCHED_MONITOR_FAIR */


#ifdef CONFIG_SCHED_MONITOR_IPANEMA

#define sched_monitor_ipanema_start(start)			\
	do {							\
		if (unlikely(sched_monitor_ipanema_enabled))	\
			start = local_clock();			\
	} while (0)

#define sched_monitor_ipanema_stop(evt, start)				\
	do {								\
		if (unlikely(sched_monitor_ipanema_enabled && start != 0)) { \
			u64 delta = local_clock() - start;		\
			this_cpu_ptr(&ipanema_stats)->time[evt] += delta; \
			this_cpu_ptr(&ipanema_stats)->hits[evt]++;	\
		}							\
	} while (0)

#else  /* !CONFIG_SCHED_MONITOR_IPANEMA */

#define sched_monitor_ipanema_start(start)
#define sched_monitor_ipanema_stop(evt, start)

#endif	/* CONFIG_SCHED_MONITOR_IPANEMA */


#ifdef CONFIG_SCHED_MONITOR_IDLE

#define sched_monitor_idle_start()					\
	do {								\
		if (unlikely(sched_monitor_idle_enabled))		\
			this_cpu_write(last_sched, local_clock());	\
	} while (0)

#define sched_monitor_idle_stop()					\
	do {								\
		if (unlikely(sched_monitor_idle_enabled)) {		\
			u64 delta = local_clock() - this_cpu_read(last_sched); \
			this_cpu_ptr(&idle_stats)->time += delta;	\
			this_cpu_ptr(&idle_stats)->hits++;		\
		}							\
	} while (0)

#else  /* !CONFIG_SCHED_MONITOR_IDLE */

#define sched_monitor_idle_start()
#define sched_monitor_idle_stop()

#endif	/* CONFIG_SCHED_MONITOR_IDLE */


#ifdef CONFIG_SCHED_MONITOR_TRACER

static inline void __sched_monitor_trace(enum sched_tracer_events evt, int cpu,
					 struct task_struct *p,
					 int arg0, int arg1)
{
	struct sched_tracer_log *log = per_cpu_ptr(&sched_tracer_log, cpu);
	struct sched_tracer_event *v;
	unsigned long flags;

	if (!sched_monitor_tracer_event_enabled[evt])
		return;

	spin_lock_irqsave(&log->lock, flags);

	v = &log->events[log->producer];
	v->timestamp = local_clock();
	v->pid = p->pid;
	v->event = evt;
	v->arg0 = arg0;
	v->arg1 = arg1;

	log->producer++;
	if (unlikely(log->producer >= log->size))
		log->producer = 0;

	if (unlikely(log->producer == log->consumer)) {
		log->consumer++;
		if (unlikely(log->consumer >= log->size))
			log->consumer = 0;
		log->dropped++;
	}

	spin_unlock_irqrestore(&log->lock, flags);
}

#define sched_monitor_trace(evt, cpu, task, arg0, arg1)			\
	do {								\
		if (unlikely(sched_monitor_tracer_enabled))		\
			__sched_monitor_trace(evt, cpu, task, arg0, arg1); \
	} while (0)

#else  /* !CONFIG_SCHED_MONITOR_TRACER */

#define sched_monitor_trace(evt, cpu, task, arg0, arg1)

#endif	/* CONFIG_SCHED_MONITOR_TRACER */

#endif	/* _SCHED_MONITOR_H_ */
