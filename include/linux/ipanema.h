#ifndef __IPANEMA_H
#define __IPANEMA_H

#include <linux/sched.h>
#include <linux/kref.h>

#include "sched.h"

#define ESYNTAX					1000
#define EBOUNDS					1001
#define EOVERLAP				1002
#define EINVALIDDEFAULT				1003
#define EMODULENOTFOUND				1004
#define EMODULEINUSE				1005
#define ETOOMANYMODULES				1006
#define ETOOMANYPOLICIES			1007

#define MAX_IPANEMA_MODULES			64

#ifdef __KERNEL__

#define policy_metadata(t) (t)->ipanema_metadata.policy_metadata

#ifndef IPA_DBG
/* Prone to deadlocks if rq lock is held. */
#define IPA_DBG(msg, args...)						       \
do {									       \
	if (ipanema_debug)						       \
		printk("CPU %02d %s %04d " msg, smp_processor_id(),	       \
		       __FUNCTION__, __LINE__, ##args);			       \
} while(0)
#endif

#ifndef IPA_DBG_SAFE
/* Safe to use when the rq lock is held. */
#define IPA_DBG_SAFE(msg, args...)					       \
do {									       \
	if (ipanema_debug)						       \
		printk_deferred("CPU %02d %s %04d " msg,		       \
				smp_processor_id(), __FUNCTION__,	       \
				__LINE__, ##args);			       \
} while(0)
#endif

#ifndef IPA_EMERG_SAFE
/* For messages that will be displayed no matter what. */
#define IPA_EMERG_SAFE(msg, args...)					       \
do {									       \
	printk_deferred(KERN_EMERG "CPU %02d %s %04d " msg,		       \
			smp_processor_id(), __FUNCTION__, __LINE__, ##args);   \
} while(0)
#endif

enum ipanema_core_state { IPANEMA_ACTIVE_CORE, IPANEMA_IDLE_CORE };

struct ipanema_rq {
	unsigned int cpu;
	struct rb_root root;
	enum ipanema_state state;
	unsigned int nr_tasks;
};

extern int ipanema_debug;
extern DEFINE_PER_CPU(struct task_struct *, ipanema_current);

extern int nb_topology_levels;
extern DEFINE_PER_CPU(struct topology_level*, topology_levels);

struct ipanema_runtime_metadata;

struct process_event {
	struct task_struct *target;
	int cpu;
};

struct core_event {
	unsigned int target; // Ipanema core
};

struct ipanema_module;

struct ipanema_policy {
	cpumask_t allowed_cores;
	__u32 id;
	char *name;
	struct ipanema_module *module;
	struct list_head list;
	void *data;
	struct kref refcount;
};

struct ipanema_module_routines {
	int (*order_process)(struct ipanema_policy *policy,
			     struct task_struct *a, struct task_struct *b);
	enum ipanema_core_state (*get_core_state)(struct ipanema_policy *policy,
						  struct core_event *e);

	int (*new_prepare)(struct ipanema_policy *policy,
			   struct process_event *e);
	void (*new_place)(struct ipanema_policy *policy,
			  struct process_event *e);
	void (*new_end)(struct ipanema_policy *policy,
			struct process_event *e);
	
	void (*tick)(struct ipanema_policy *policy, struct process_event *e);
	void (*yield)(struct ipanema_policy *policy, struct process_event *e);
	void (*block)(struct ipanema_policy *policy, struct process_event *e);

	int (*unblock_prepare)(struct ipanema_policy *policy,
			       struct process_event *e);
	void (*unblock_place)(struct ipanema_policy *policy,
			      struct process_event *e);
	void (*unblock_end)(struct ipanema_policy *policy,
			    struct process_event *e);

	void (*terminate)(struct ipanema_policy *policy,
			  struct process_event *e);
	void (*schedule)(struct ipanema_policy *policy, unsigned int cpu);

	void (*newly_idle)(struct ipanema_policy *policy, struct core_event *e);
	void (*enter_idle)(struct ipanema_policy *policy, struct core_event *e);
	void (*exit_idle)(struct ipanema_policy *policy, struct core_event *e);

	void (*balancing_select)(struct ipanema_policy *policy,
				 struct core_event *e);

	void (*core_entry)(struct ipanema_policy *policy, struct core_event *e);
	void (*core_exit)(struct ipanema_policy *policy,
			  struct core_event *e);

	int (*init)(struct ipanema_policy *policy);
	int (*free_metadata)(struct ipanema_policy *policy);

	int (*can_be_default)(struct ipanema_policy *policy);
	bool (*attach)(struct ipanema_policy *policy, struct task_struct *task,
		       char *command);
};

struct ipanema_module {
	char *name;
	struct ipanema_module_routines *routines;
	struct module *kmodule;
	/* refcount ? */
};

/* topology level types, used as flags in struct topology_level */
#define DOMAIN_SMT   0x1      	/* cpus share computing units (simultaneous multi-threading) */
#define DOMAIN_CACHE 0x2	/* cpus share a hardware cache */
#define DOMAIN_NUMA  0x4	/* cpus may be on different NUMA nodes */

struct topology_level {
	cpumask_t cores;
	int flags;
	struct topology_level *next;
};

void change_state(struct task_struct *p, enum ipanema_state next_state,
		  unsigned int next_cpu, struct ipanema_rq *next_rq);
struct task_struct *ipanema_first_of_state(enum ipanema_state state,
					   unsigned int cpu);

struct task_struct *ipanema_get_task_of(void *proc);

int ipanema_add_module(struct ipanema_module *module);
int ipanema_remove_module(struct ipanema_module *module);

int count(enum ipanema_state state, unsigned int cpu);

#define ipanema_rq_lock(p)         (&task_rq(p)->lock)
#define ipanema_task_state(p)      ((p)->ipanema_metadata.state)
#define ipanema_task_rq(p)         ((p)->ipanema_metadata.rq)
#define ipanema_task_policy(p)     ((p)->ipanema_metadata.policy)

/*
 * Accessors used in policy modules
 */
#define ipanema_core(cpu)          (per_cpu(core, (cpu)))
#define ipanema_state(cpu)         (per_cpu(state_info, (cpu)))


extern void ipanema_lock_core(unsigned int id);
extern int ipanema_trylock_core(unsigned int id);
extern void ipanema_unlock_core(unsigned int id);

extern int ipanema_just_queued(struct task_struct *p);

#endif /* __KERNEL__ */

#endif /* __IPANEMA_H */
