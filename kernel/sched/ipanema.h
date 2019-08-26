#ifndef IPANEMA_H
#define IPANEMA_H

#include <linux/ipanema.h>
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


extern struct list_head ipanema_modules;
extern struct list_head ipanema_policies;

int ipanema_set_policy(char *policies_str);

extern rwlock_t ipanema_rwlock;

/* Variables exposed by the sysfs interface */
extern int ipanema_fsm_check;
extern int ipanema_fsm_log;
extern int ipanema_sched_class_log;

#ifdef CONFIG_CGROUP_IPANEMA
struct ipanema_group {
	struct cgroup_subsys_state css;

	struct ipanema_policy *policy;
};

#define ipanema_group_of(css) (container_of(css, struct ipanema_group, css))
#endif	/* CONFIG_CGROUP_IPANEMA */

#endif	/* IPANEMA_H */
