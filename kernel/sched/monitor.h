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

static char *evts_names[] = {
	"enqueue",
	"dequeue",
	"yield",
	"pick_next",
	"put_prev",
	"select_rq",
	"lb_period"
};

struct sched_stats {
	ktime_t time[NR_EVENTS];
	u64 hits[NR_EVENTS];
};

DECLARE_PER_CPU(struct sched_stats, fair_stats);
DECLARE_PER_CPU(struct sched_stats, ipanema_stats);

void reset_stats(void);

extern int ipanema_sched_class_time;

#endif	/* _SCHED_MONITOR_H_ */
