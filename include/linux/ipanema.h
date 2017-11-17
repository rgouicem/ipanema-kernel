#ifndef __IPANEMA_H
#define __IPANEMA_H

#include <linux/sched.h>
#include <linux/kref.h>

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

void init_sched_ipanema_late(void);

struct ipanema_runtime_metadata;

struct process_event {
	struct task_struct *target;
};

struct core_event {
	int target; // Ipanema core
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
	int (*get_metric)(struct ipanema_policy *policy, struct task_struct *a);

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
	void (*schedule)(struct ipanema_policy *policy, int cpu);

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

struct topology_level {
	const cpumask_t *cores;
};

void change_state(struct task_struct *p, enum ipanema_state next_state,
		  int next_cpu, struct ipanema_rq *next_rq);
struct task_struct* ipanema_first_of_state(enum ipanema_state state, int cpu);

struct task_struct *ipanema_get_task_of(void *proc);

int ipanema_add_module(struct ipanema_module *module);
int ipanema_remove_module(struct ipanema_module *module);

int count(enum ipanema_state state, int cpu);

#define ipanema_rq_lock(p)         (&task_rq(p)->lock)
#define ipanema_task_state(p)      ((p)->ipanema_metadata.state)
#define ipanema_task_rq(p)         ((p)->ipanema_metadata.rq)
#define ipanema_task_policy(p)     ((p)->ipanema_metadata.policy)

/*
 * Accessors used in policy modules
 */
#define ipanema_policy_state_info(cpu)   (per_cpu(state_info, (cpu)))


extern bool ipanema_trylock_migration(struct task_struct *task,
				      unsigned long *spinflags,
				      raw_spinlock_t **lock,
				      int core);
extern void ipanema_unlock_migration(struct task_struct *task,
				     unsigned long spinflags,
				     raw_spinlock_t *lock);

extern int ipanema_trylock_cores(int c1, int c2);
extern void ipanema_unlock_cores(int c1, int c2);
extern void ipanema_lock_core(int c);
extern int ipanema_trylock_core(int c);
extern void ipanema_unlock_core(int c);
extern int ipanema_just_queued(struct task_struct *p);

#endif /* __KERNEL__ */

#endif /* __IPANEMA_H */
