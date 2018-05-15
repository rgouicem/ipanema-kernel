#ifndef _SCHED_MONITOR_H_
#define _SCHED_MONITOR_H_

/* Events */
#define ENQUEUE    0
#define DEQUEUE    1
#define YIELD      2
#define PICK_NEXT  3
#define PUT_PREV   4
#define SELECT_RQ  5
#define LB_PERIOD  6
#define NR_EVENTS  (LB_PERIOD + 1)

struct sched_stats {
	u64 time[NR_EVENTS];
	u64 hits[NR_EVENTS];
};

struct idle_stats {
	u64 time, hits;
	u64 no_wc_time, no_wc_hits;
};

DECLARE_PER_CPU(struct sched_stats, fair_stats);
DECLARE_PER_CPU(struct sched_stats, ipanema_stats);
DECLARE_PER_CPU(struct idle_stats, idle_stats);


void reset_stats(void);

extern int ipanema_sched_class_time;

extern bool sched_monitor_enabled;
DECLARE_PER_CPU(u64, sched_time);
DECLARE_PER_CPU(u64, sched_time_start);
DECLARE_PER_CPU(bool, sched_monitoring);
DECLARE_PER_CPU(void *, sched_monitoring_fn);

#define sched_monitor_start(fn)						\
	do {								\
		if (!sched_monitor_enabled)				\
			break;						\
		if (this_cpu_read(sched_monitoring))			\
			break;						\
		this_cpu_write(sched_monitoring, true);			\
		this_cpu_write(sched_monitoring_fn, fn);		\
		this_cpu_write(sched_time_start, local_clock());	\
	} while (0)

#define sched_monitor_stop(fn)						\
	do {								\
		if (!sched_monitor_enabled)				\
			break;						\
		if (!this_cpu_ptr(&sched_monitoring))			\
			break;						\
		if (this_cpu_read(sched_monitoring_fn) != fn)		\
			break;						\
		this_cpu_add(sched_time,				\
			     local_clock() - this_cpu_read(sched_time_start));	\
		this_cpu_write(sched_monitoring, false);		\
		this_cpu_write(sched_monitoring_fn, NULL);		\
	} while (0)

#define sched_monitor_test()						\
	do {								\
		if (sched_monitor_enabled &&				\
		    !this_cpu_read(sched_monitoring)) {			\
			pr_err("%s(): sched_monitor didn't catch me!\n", \
			       __FUNCTION__);				\
			dump_stack();					\
		}							\
	} while (0)

#define sched_monitor_fair_start(start)		\
	do {						\
		if (unlikely(ipanema_sched_class_time))	\
			start = local_clock();		\
	} while (0)

#define sched_monitor_fair_stop(evt, start)				\
	do {								\
		if (unlikely(ipanema_sched_class_time)) {		\
			u64 delta = local_clock() - start;		\
			this_cpu_ptr(&fair_stats)->time[evt] += delta;	\
			this_cpu_ptr(&fair_stats)->hits[evt]++;		\
		}							\
	} while (0)

#define sched_monitor_ipanema_start(start) (sched_monitor_fair_start(start))

#define sched_monitor_ipanema_stop(evt, start)				\
	do {								\
		if (unlikely(ipanema_sched_class_time)) {		\
			u64 delta = local_clock() - start;		\
			this_cpu_ptr(&ipanema_stats)->time[evt] += delta; \
			this_cpu_ptr(&ipanema_stats)->hits[evt]++;	\
		}							\
	} while (0)

#endif	/* _SCHED_MONITOR_H_ */
