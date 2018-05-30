#ifndef _SCHED_MONITOR_H_
#define _SCHED_MONITOR_H_

/* Events */
#define ENQUEUE            0
#define DEQUEUE            1
#define YIELD              2
#define YIELD_TO           3
#define CHECK_PREEMPT_CURR 4
#define PICK_NEXT          5
#define PUT_PREV           6
#define SELECT_RQ          7
#define MIGRATE            8
#define WOKEN              9
#define RQ_ONLINE         10
#define RQ_OFFLINE        11
#define SET_CURR          12
#define TICK              13
#define FORK              14
#define DEAD              15
#define SWITCHED_FROM     16
#define SWITCHED_TO       17
#define PRIO_CHANGED      18
#define LB_PERIOD         19
#define NR_EVENTS         LB_PERIOD + 1

struct sched_stats {
	u64 time[NR_EVENTS];
	u64 hits[NR_EVENTS];
};

#if defined(CONFIG_SCHED_MONITOR_FAIR_IDLE_BALANCING) || defined(CONFIG_SCHED_MONITOR_IPANEMA_IDLE_BALANCING)

struct idle_balance_stats {
	u64 time, hits;
};

#endif

#ifdef CONFIG_SCHED_MONITOR_CORE

DECLARE_PER_CPU(u64, sched_time);
DECLARE_PER_CPU(u64, sched_time_start);
DECLARE_PER_CPU(bool, sched_monitoring);
DECLARE_PER_CPU(void *, sched_monitoring_fn);
extern bool sched_monitor_enabled;

#endif	/* CONFIG_SCHED_MONITOR_CORE */

#ifdef CONFIG_SCHED_MONITOR_FAIR

DECLARE_PER_CPU(struct sched_stats, fair_stats);
extern bool sched_monitor_fair_enabled;

#ifdef CONFIG_SCHED_MONITOR_FAIR_IDLE_BALANCING

DECLARE_PER_CPU(struct idle_balance_stats, fair_idle_balance_stats);

#endif	/* SCHED_MONITOR_FAIR_IDLE_BALANCING */

#endif	/* CONFIG_SCHED_MONITOR_FAIR */


#ifdef CONFIG_SCHED_MONITOR_IPANEMA

DECLARE_PER_CPU(struct sched_stats, ipanema_stats);
extern bool sched_monitor_ipanema_enabled;

#ifdef CONFIG_SCHED_MONITOR_IPANEMA_IDLE_BALANCING

DECLARE_PER_CPU(struct idle_balance_stats, ipanema_idle_balance_stats);

#endif	/* SCHED_MONITOR_IPANEMA_IDLE_BALANCING */

#endif	/* CONFIG_SCHED_MONITOR_IPANEMA */


#ifdef CONFIG_SCHED_MONITOR_IDLE

struct idle_stats {
	u64 time, hits;
};

DECLARE_PER_CPU(struct idle_stats, idle_stats);
extern bool sched_monitor_idle_enabled;

#endif	/* CONFIG_SCHED_MONITOR_IDLE */

#ifdef CONFIG_SCHED_MONITOR_IDLE_WC

extern struct wc_stats {
	atomic64_t nr_runnable, nr_busy;
	atomic64_t time;
} wc_stats;

#endif	/* CONFIG_SCHED_MONITOR_IDLE_WC */


void reset_stats(void);

#ifdef CONFIG_SCHED_MONITOR_CORE

#define sched_monitor_start(fn)						\
	do {								\
		if (likely(!sched_monitor_enabled))			\
			break;						\
		if (this_cpu_read(sched_monitoring))			\
			break;						\
		this_cpu_write(sched_monitoring, true);			\
		this_cpu_write(sched_monitoring_fn, fn);		\
		this_cpu_write(sched_time_start, local_clock());	\
	} while (0)

#define sched_monitor_stop(fn)						\
	do {								\
		if (likely(!sched_monitor_enabled))			\
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
		if (likely(!sched_monitor_enabled))			\
			break;						\
		if (!this_cpu_read(sched_monitoring)) {			\
			pr_err("%s(): sched_monitor didn't catch me!\n", \
			       __FUNCTION__);				\
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

#ifdef CONFIG_SCHED_MONITOR_FAIR_IDLE_BALANCING

#define sched_monitor_fair_idle_balance()				\
	do {								\
		if (unlikely(sched_monitor_fair_enabled))		\
			this_cpu_ptr(&fair_idle_balance_stats)->hits++;	\
	} while (0)

#else  /* !CONFIG_SCHED_MONITOR_FAIR_IDLE_BALANCING */

#define sched_monitor_fair_idle_balance()

#endif	/* CONFIG_SCHED_MONITOR_FAIR_IDLE_BALANCING */

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

#ifdef CONFIG_SCHED_MONITOR_IPANEMA_IDLE_BALANCING

#define sched_monitor_ipanema_idle_balance()				\
	do {								\
		if (unlikely(sched_monitor_ipanema_enabled))		\
			this_cpu_ptr(&ipanema_idle_balance_stats)->hits++; \
	} while (0)

#else  /* !CONFIG_SCHED_MONITOR_IPANEMA_IDLE_BALANCING */

#define sched_monitor_ipanema_idle_balance()

#endif	/* CONFIG_SCHED_MONITOR_IPANEMA_IDLE_BALANCING */

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


#ifdef CONFIG_SCHED_MONITOR_IDLE_WC

#define sched_monitor_nr_runnable_inc(v)		\
	(atomic64_add(v, &(wc_stats.nr_runnable)))
#define sched_monitor_nr_runnable_dec(v)		\
	(atomic64_sub(v, &(wc_stats.nr_runnable)))
#define sched_monitor_nr_busy_inc(v) (atomic64_add(v, &(wc_stats.nr_busy)))
#define sched_monitor_nr_busy_dec(v) (atomic64_sub(v, &(wc_stats.nr_busy)))

static inline bool is_wc(void)
{
	long nr_run = atomic64_read(&(wc_stats.nr_runnable));
	long nr_busy = atomic64_read(&(wc_stats.nr_busy));

	return min(nr_run, (long)num_possible_cpus()) == nr_busy;
}

#else  /* !CONFIG_SCHED_MONITOR_IDLE_WC */

#define sched_monitor_nr_runnable_inc(v)
#define sched_monitor_nr_runnable_dec(v)
#define sched_monitor_nr_busy_inc(v)
#define sched_monitor_nr_busy_dec(v)
static inline bool is_wc(void)
{
	return true;
}

#endif	/* CONFIG_SCHED_MONITOR_IDLE_WC */

#endif	/* _SCHED_MONITOR_H_ */
