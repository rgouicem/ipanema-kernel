#ifndef __IPANEMA_H
#define __IPANEMA_H

#include <linux/sched.h>
#include <linux/kref.h>

#include "sched.h"

#define MAX_POLICY_NAME_LEN     32

#ifdef __KERNEL__

enum ipanema_core_state { IPANEMA_ACTIVE_CORE, IPANEMA_IDLE_CORE };

enum ipanema_rq_type { RBTREE, LIST, FIFO };

struct ipanema_rq {
	enum ipanema_rq_type type;
	union {
		struct rb_root root;
		struct list_head head;
	};
	unsigned int cpu;
	enum ipanema_state state;
	unsigned int nr_tasks;
	int (*order_fn)(struct task_struct *a, struct task_struct *b);
};

void init_ipanema_rq(struct ipanema_rq *rq, enum ipanema_rq_type type,
		     unsigned int cpu, enum ipanema_state state,
		     int (*order_fn)(struct task_struct *a,
				     struct task_struct *b));

int ipanema_add_task(struct ipanema_rq *rq, struct task_struct *data);
struct task_struct *ipanema_remove_task(struct ipanema_rq *rq,
					struct task_struct *data);
struct task_struct *ipanema_first_task(struct ipanema_rq *rq);


struct task_struct *get_ipanema_current(int cpu);

extern int nb_topology_levels;
DECLARE_PER_CPU(struct topology_level*, topology_levels);

struct ipanema_runtime_metadata;

struct process_event {
	struct task_struct *target;
	int cpu;
};

struct core_event {
	unsigned int target; // Ipanema core
};

struct ipanema_policy {
	struct module *kmodule;
	struct list_head list;
	struct ipanema_module_routines *routines;
	void *data;
	s64 id;
	char name[MAX_POLICY_NAME_LEN];
};

struct ipanema_module_routines {
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

	bool (*checkparam_attr)(const struct sched_attr *attr);
	void (*setparam_attr)(struct task_struct *p,
			      const struct sched_attr *attr);
	void (*getparam_attr)(struct task_struct *p,
			      struct sched_attr *attr);
	bool (*attr_changed)(struct task_struct *p,
			     const struct sched_attr *attr);

	int (*init)(struct ipanema_policy *policy);
	int (*free_metadata)(struct ipanema_policy *policy);

	int (*can_be_default)(struct ipanema_policy *policy);
	bool (*attach)(struct ipanema_policy *policy, struct task_struct *task,
		       char *command);
};

extern struct proc_dir_entry *ipa_procdir;

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

int ipanema_add_policy(struct ipanema_policy *policy);
int ipanema_remove_policy(struct ipanema_policy *policy);

int count(enum ipanema_state state, unsigned int cpu);

#define ipanema_rq_lock(p)         (&task_rq(p)->lock)
#define policy_metadata(t)         ((t)->ipanema.policy_metadata)
#define ipanema_task_state(p)      ((p)->ipanema.state)
#define ipanema_task_rq(p)         ((p)->ipanema.rq)
#define ipanema_task_policy(p)     ((p)->ipanema.policy)

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
