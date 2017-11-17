#ifndef IPANEMA_COMMON_H
#define IPANEMA_COMMON_H

#include <linux/ipanema.h>
#include <linux/ipanema_rbtree.h>
#include <linux/latencytop.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/cpuidle.h>
#include <linux/profile.h>
#include <linux/interrupt.h>
#include <linux/mempolicy.h>
#include <linux/migrate.h>
#include <linux/task_work.h>
#include <linux/proc_fs.h>
#include <linux/sort.h>

struct ipanema_policy;

struct ipanema_routines {
	int (*order_process)(struct task_struct *a, struct task_struct *b);
	int (*get_metric)(struct task_struct *a);

	int (*new_prepare)(struct process_event *e);
	void (*new_place)(struct process_event *e);
	void (*new_end)(struct process_event *e);

	void (*tick)(struct process_event *e);
	void (*yield)(struct process_event *e);
	void (*block)(struct process_event *e);

	int (*unblock_prepare)(struct process_event *e);
	void (*unblock_place)(struct process_event *e);
	void (*unblock_end)(struct process_event *e);

	void (*terminate)(struct process_event *e);
	void (*schedule)(struct ipanema_policy *policy, int cpu);
	void (*init)(void);
	void (*balancing_select)(void);

	void (*core_entry)(struct ipanema_policy *policy_p, int core);
	void (*core_exit)(struct ipanema_policy *policy_p, int core);
};

extern struct ipanema_routines ipanema_routines;

extern struct ipanema_module *ipanema_modules[];
extern int num_ipanema_modules;

extern struct list_head ipanema_policies;
extern int num_ipanema_policies;

void ipanema_create_dev(void);
void ipanema_create_procs(void);
void debug_ipanema(void);

int ipanema_set_policy(char *policies_str);

extern rwlock_t ipanema_rwlock;

/* Variables exposed by the sysfs interface */
extern int ipanema_fsm_check;
extern int ipanema_fsm_log;
extern int ipanema_sched_class_log;

#endif
