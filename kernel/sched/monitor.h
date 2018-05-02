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
};

DECLARE_PER_CPU(struct sched_stats, fair_stats);
DECLARE_PER_CPU(struct sched_stats, ipanema_stats);
DECLARE_PER_CPU(struct idle_stats, idle_stats);


void reset_stats(void);

extern int ipanema_sched_class_time;

#endif	/* _SCHED_MONITOR_H_ */
