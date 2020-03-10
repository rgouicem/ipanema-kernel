// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) "ipanema[" KBUILD_MODNAME "]: " fmt

#include <linux/delay.h>
#include <linux/ipanema.h>
#include <linux/ktime.h>
#include <linux/lockdep.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/threads.h>

#include "../monitor.h"

#define ipanema_assert(x)				\
	do {						\
		if (!(x))				\
			panic("Error in " #x "\n");	\
	} while (0)
#define time_to_ticks(x) (ktime_to_ns(x) * HZ / 1000000000)
#define ticks_to_time(x) (ns_to_ktime(x * 1000000000 / HZ))

static char *name = KBUILD_MODNAME;
static struct ipanema_policy *policy;

#define SCHED_SLICE 200
#define SCHED_SLICE_MIN_DIVISOR 8
static const u64 penalty_fork = 666;
#define INTERRUPT   1
#define REGULAR     2
#define INTERACTIVE 4
#define L2_CACHE  1
#define L3_CACHE  2

struct ule_wwc_ipa_process;
struct ule_wwc_ipa_core;
struct ule_wwc_ipa_sched_domain;
struct ule_wwc_ipa_sched_group;

struct ule_wwc_ipa_process {
	struct task_struct *task; // Internal
	struct task_struct *parent; //system
	int prio;
	u64 order;
	int last_core;
	int slice;
	ktime_t rtime;
	ktime_t slptime;
	ktime_t last_blocked;
	ktime_t last_schedule;
	int load;
};

struct state_info {
	struct ule_wwc_ipa_process *current_0; /* private / unshared */
	struct ipanema_rq realtime;  /* public / shared */
	struct ipanema_rq timeshare; /* public / shared */
};
DEFINE_PER_CPU_SHARED_ALIGNED(struct state_info, state_info);

static struct core_state_info {
	cpumask_t active_cores;
	cpumask_t idle_cores;
} cstate_info;

struct ule_wwc_ipa_core {
	enum ipanema_core_state state; // Internal
	cpumask_t *cpuset; // Internal
	int id; // System
	int cload;
	struct ule_wwc_ipa_sched_domain *sd;
	u64 order;
};
DEFINE_PER_CPU(struct ule_wwc_ipa_core, core);

struct ule_wwc_ipa_sched_group {
	cpumask_t cores;
	int sharing_level;
};

/*
 * Example of topology:
 *
 *    O----------[0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15]
 *    |           /         |              |          \
 *    O----[0 1 2 3]-----[4 5 6 7]----[8 9 10 11]-----[12 13 14 15]
 *    |    /      \      /      \      /       \        /        \
 *    O--[0 1]--[2 3]--[4 5]--[6 7]--[8 9]--[10 11]--[12 13]--[14 15]
 *    |
 *   ule_wwc_ipa_topology
 */
struct ule_wwc_ipa_sched_domain {
	struct list_head siblings;  // Internal, link domains of the same level
	struct ule_wwc_ipa_sched_domain *parent; // Internal
	int ___sched_group_idx; // Internal
	spinlock_t lock; // Internal
	int flags; // Internal
	cpumask_t cores; // Internal
	struct ule_wwc_ipa_sched_group *groups;
};

static struct list_head *ule_wwc_ipa_topology;
static unsigned int ule_wwc_ipa_nr_topology_levels;

int ipanema_ule_wwc_order_process(struct task_struct *a,
				  struct task_struct *b)
{
	struct ule_wwc_ipa_process *pa = policy_metadata(a);
	struct ule_wwc_ipa_process *pb = policy_metadata(b);
	int prio_order = pb->prio - pa->prio;

	if (prio_order == 0) {
		if (pa->order > pb->order)
			return 1;
		if (pa->order < pb->order)
			return -1;
		return 0;
	}
	return prio_order;
}

static void ipa_change_curr(struct ule_wwc_ipa_core *c,
			    struct ule_wwc_ipa_process *p)
{
	BUG_ON(c->id != task_cpu(p->task));

	ipanema_state(c->id).current_0 = p;
	change_state(p->task, IPANEMA_RUNNING, c->id, NULL);
}

static void ipa_change_queue(struct ule_wwc_ipa_process *p,
			     struct ipanema_rq *rq, enum ipanema_state state,
			     unsigned int cpu)
{
	struct ule_wwc_ipa_core *c = &ipanema_core(task_cpu(p->task));

	BUG_ON(rq && rq->cpu != cpu);

	if (ipanema_state(c->id).current_0 == p)
		ipanema_state(c->id).current_0 = NULL;
	change_state(p->task, state, cpu, rq);
}

static void set_active_core(struct ule_wwc_ipa_core *core, cpumask_t *cores,
			    int state)
{
	core->state = state;
	if (core->cpuset)
		cpumask_clear_cpu(core->id, core->cpuset);
	cpumask_set_cpu(core->id, cores);
	core->cpuset = cores;
}

static void set_sleeping_core(struct ule_wwc_ipa_core *core,
			      cpumask_t *cores, int state)
{
	core->state = state;
	if (core->cpuset)
		cpumask_clear_cpu(core->id, core->cpuset);
	cpumask_set_cpu(core->id, cores);
	core->cpuset = cores;
}

static enum ipanema_core_state
ipanema_ule_wwc_get_core_state(struct ipanema_policy *policy,
			       struct core_event *e)
{
	return ipanema_core(e->target).state;
}

static int migrate_from_to(struct ule_wwc_ipa_core *busiest,
			   struct ule_wwc_ipa_core *thief)
{
	struct task_struct *pos, *n;
	LIST_HEAD(tasks);
	struct sched_ipanema_entity *imd;
	struct ule_wwc_ipa_process *t;
	int dbg_cpt = 0, ret, thief_cload;
	unsigned long flags;

	/* Remove tasks from busiest */
	local_irq_save(flags);
	ipanema_lock_core(busiest->id);

	thief_cload = thief->cload;
	// go through realtime rq
	rbtree_postorder_for_each_entry_safe(pos, n,
					     &ipanema_state(busiest->id).realtime.root,
					     ipanema.node_runqueue) {
		t = policy_metadata(pos);
		if (pos->on_cpu)
			continue;

		if (!cpumask_test_cpu(thief->id, &pos->cpus_allowed))
			continue;

		if (busiest->cload - thief_cload >= 2) {
			list_add(&pos->ipanema.ipa_tasks, &tasks);
			ipa_change_queue(t, NULL, IPANEMA_MIGRATING,
					 thief->id);
			dbg_cpt = dbg_cpt + 1;
			busiest->cload -= t->load;
			thief_cload += t->load;

			goto unlock_busiest;
		}
	}
	// go through timeshare rq
	rbtree_postorder_for_each_entry_safe(pos, n,
					     &ipanema_state(busiest->id).timeshare.root,
					     ipanema.node_runqueue) {
		t = policy_metadata(pos);
		if (pos->on_cpu)
			continue;

		if (!cpumask_test_cpu(thief->id, &pos->cpus_allowed))
			continue;

		if (busiest->cload - thief_cload >= 2) {
			list_add(&pos->ipanema.ipa_tasks, &tasks);
			ipa_change_queue(t, NULL, IPANEMA_MIGRATING,
					 thief->id);
			dbg_cpt = dbg_cpt + 1;
			busiest->cload -= t->load;
			thief_cload += t->load;

			break;
		}
	}

unlock_busiest:
	ipanema_unlock_core(busiest->id);
	ret = dbg_cpt;

	/* Add them to my queue */
	ipanema_lock_core(thief->id);
	while (!list_empty(&tasks)) {
		imd = list_first_entry(&tasks, struct sched_ipanema_entity,
				       ipa_tasks);
		pos = container_of(imd, struct task_struct, ipanema);
		t = policy_metadata(pos);
		t->order = thief->order++;
		if (t->prio == REGULAR)
			ipa_change_queue(t, &ipanema_state(thief->id).timeshare,
					 IPANEMA_READY, thief->id);
		else
			ipa_change_queue(t, &ipanema_state(thief->id).realtime,
					 IPANEMA_READY, thief->id);
		thief->cload += t->load;
		list_del_init(&imd->ipa_tasks);
		dbg_cpt--;
	}
	ipanema_unlock_core(thief->id);
	local_irq_restore(flags);

	if (dbg_cpt != 0)
		pr_info("Some tasks (%d) were lost on a migration from %d to %d\n",
			       dbg_cpt, busiest->id, thief->id);

	return ret;
}

static bool can_steal_core(struct ule_wwc_ipa_core *tgt,
			   struct ule_wwc_ipa_core *thief)
{
	return tgt->cload - thief->cload >= 2;
}

static struct ule_wwc_ipa_core *select_core(struct ipanema_policy *policy,
					    struct ule_wwc_ipa_sched_group *sg,
					    cpumask_t *stealable_cores)
{
	struct ule_wwc_ipa_core *c, *victim = NULL;
	int max_cload = 0;
	int cpu;

	for_each_cpu(cpu, stealable_cores) {
		c = &ipanema_core(cpu);
		if (c->cload > max_cload) {
			victim = c;
			max_cload = c->cload;
		}
	}

	return victim;
}

DEFINE_SPINLOCK(lb_lock);

static void steal_for_dom(struct ipanema_policy *policy,
			  struct ule_wwc_ipa_core *core_31,
			  struct ule_wwc_ipa_sched_domain *sd)
{
	cpumask_t stealable_cores;
	struct ule_wwc_ipa_core *selected, *c;
	int i;

	/* init bitmaps */
	cpumask_clear(&stealable_cores);

	/* Step 1: can_steal_core() */
	for_each_cpu(i, &cstate_info.active_cores) {
		c = &ipanema_core(i);
		if (c == core_31)
			continue;
		if (can_steal_core(c, core_31))
			cpumask_set_cpu(i, &stealable_cores);
	}
	if (cpumask_empty(&stealable_cores))
		return;

	/* Step 2: select_core() */
	do {
		selected = select_core(policy, NULL, &stealable_cores);
		if (!selected)
			return;
		cpumask_clear_cpu(selected->id, &stealable_cores);

		/* Step 3: steal_thread() */
		migrate_from_to(selected, core_31);
	} while (core_31->cload == 0 && cpumask_weight(&stealable_cores));
}

static int ipanema_ule_wwc_new_prepare(struct ipanema_policy *policy,
				       struct process_event *e)
{
	struct ule_wwc_ipa_process *tgt, *parent;
	struct ule_wwc_ipa_core *c, *idlest = NULL;
	struct task_struct *task_15;
	int cpu;
	/* static int next_cpu = 0; */

	task_15 = e->target;
	tgt = kzalloc(sizeof(struct ule_wwc_ipa_process), GFP_ATOMIC);
	if (!tgt)
		return -1;

	policy_metadata(task_15) = tgt;
	tgt->task = task_15;
	if (task_15->parent->policy != SCHED_IPANEMA)
		tgt->parent = NULL;
	else
		tgt->parent = task_15->parent;

	/* find idlest core on machine */
	c = &ipanema_core(task_cpu(task_15));
	idlest = c;
	for_each_cpu(cpu, &task_15->cpus_allowed) {
		c = &ipanema_core(cpu);
		if (c->cload < idlest->cload)
			idlest = c;
	}

	tgt->load = 1;
	if (tgt->parent) {
		parent = policy_metadata(tgt->parent);
		parent->rtime += ticks_to_time(penalty_fork);
		tgt->prio = parent->prio;
	} else {
		tgt->prio = REGULAR;
	}
	tgt->last_core = idlest->id;

	return idlest->id;
}

static void ipanema_ule_wwc_new_place(struct ipanema_policy *policy,
				      struct process_event *e)
{
	struct ule_wwc_ipa_process *tgt = policy_metadata(e->target);
	int idlecore_10 = task_cpu(e->target);
	struct ule_wwc_ipa_core *c = &ipanema_core(idlecore_10);

	c->cload += tgt->load;
	tgt->order = c->order++;
	/* Memory barrier for proofs */
	smp_wmb();
	if (tgt->prio == REGULAR)
		ipa_change_queue(tgt, &ipanema_state(c->id).timeshare,
				 IPANEMA_READY, c->id);
	else
		ipa_change_queue(tgt, &ipanema_state(c->id).realtime,
				 IPANEMA_READY, c->id);
}

static void ipanema_ule_wwc_new_end(struct ipanema_policy *policy,
				    struct process_event *e)
{
	pr_info("[%d] post new on core %d\n",
		       e->target->pid, e->target->cpu);
}

static void ipanema_ule_wwc_detach(struct ipanema_policy *policy,
				   struct process_event *e)
/* need to free the process metadata memory */
{
	struct ule_wwc_ipa_process *tgt = policy_metadata(e->target);
	struct ule_wwc_ipa_core *c = &ipanema_core(task_cpu(tgt->task));

	ipa_change_queue(tgt, NULL, IPANEMA_TERMINATED, c->id);
	/* Memory barrier for proofs */
	smp_wmb();
	c->cload -= tgt->load;
	/* Memory barrier for proofs */
	smp_wmb();
	kfree(tgt);
}

static void update_rtime(struct ule_wwc_ipa_process *t)
{
	t->rtime = ktime_sub(ktime_get(), t->last_schedule);
}

static void ipanema_ule_wwc_tick(struct ipanema_policy *policy,
				 struct process_event *e)
{
	struct ule_wwc_ipa_process *tgt = policy_metadata(e->target);
	struct ule_wwc_ipa_core *c = &ipanema_core(task_cpu(e->target));
	int old_load = tgt->load;

	tgt->slice--;
	if (tgt->slice <= 0) {
		update_rtime(tgt);
		tgt->order = c->order++;
		c->cload += (tgt->load - old_load);
		/* Memory barrier for proofs */
		smp_wmb();
		if (tgt->prio == REGULAR)
			ipa_change_queue(tgt,
					 &ipanema_state(task_cpu(tgt->task)).timeshare,
					 IPANEMA_READY_TICK, c->id);
		else
			ipa_change_queue(tgt,
					 &ipanema_state(task_cpu(tgt->task)).realtime,
					 IPANEMA_READY_TICK, c->id);
	}
}

static void ipanema_ule_wwc_yield(struct ipanema_policy *policy,
				  struct process_event *e)
{
	struct ule_wwc_ipa_process *tgt = policy_metadata(e->target);
	struct ule_wwc_ipa_core *c = &ipanema_core(task_cpu(e->target));
	int old_load = tgt->load;

	update_rtime(tgt);
	tgt->order = c->order++;
	c->cload += (tgt->load - old_load);
	/* Memory barrier for proofs */
	smp_wmb();
	if (tgt->prio == REGULAR)
		ipa_change_queue(tgt,
				 &ipanema_state(task_cpu(tgt->task)).timeshare,
				 IPANEMA_READY, c->id);
	else
		ipa_change_queue(tgt,
				 &ipanema_state(task_cpu(tgt->task)).realtime,
				 IPANEMA_READY_TICK, c->id);
}

static void ipanema_ule_wwc_block(struct ipanema_policy *policy,
				  struct process_event *e)
{
	struct ule_wwc_ipa_process *tgt = policy_metadata(e->target);
	struct ule_wwc_ipa_core *c = &ipanema_core(task_cpu(e->target));
	int old_load = tgt->load;

	tgt->last_blocked = ktime_get();
	ipa_change_queue(tgt, NULL, IPANEMA_BLOCKED, c->id);
	/* Memory barrier for proofs */
	smp_wmb();
	c->cload -= old_load;
	/* Memory barrier for proofs */
	smp_wmb();
}

static struct ule_wwc_ipa_core *pickup_core(struct ipanema_policy *policy,
					    struct ule_wwc_ipa_process *t)
{
	struct ule_wwc_ipa_core *c = &ipanema_core(task_cpu(t->task));
	struct ule_wwc_ipa_core *idlest = &ipanema_core(t->last_core);
	struct ule_wwc_ipa_sched_domain *sd = c->sd;
	int cpu;

	/* Run interrupt threads on their core */
	if (t->prio == INTERRUPT)
		return idlest;

	/* Pick up an idle cpu that shares a L2 */
	while (sd) {
		if (sd->flags & DOMAIN_CACHE) {
			for_each_cpu(cpu, &sd->cores) {
				c = &ipanema_core(cpu);
				if (c->cload == 0)
					return c;
			}
		}
		sd = sd->parent;
	}

	/* default */
	for_each_possible_cpu(cpu) {
		c = &ipanema_core(cpu);
		if (c->cload < idlest->cload)
			idlest = c;
	}

	return idlest;
}

static bool update_realtime(struct ule_wwc_ipa_process *t)
{
	/* Computation is more complex in FreeBSD :) */
	if (t->prio == INTERRUPT) {
		/* do not update */
	} else if (ktime_after(t->slptime, t->rtime)) {
		t->prio = INTERACTIVE;
	} else {
		t->prio = REGULAR;
	}

	return (t->prio == INTERACTIVE) || (t->prio == INTERRUPT);
}

static int ipanema_ule_wwc_unblock_prepare(struct ipanema_policy *policy,
					   struct process_event *e)
{
	struct task_struct *task_15 = e->target;
	struct ule_wwc_ipa_process *p = policy_metadata(task_15);
	struct ule_wwc_ipa_core *idlest = NULL;

	idlest = pickup_core(policy, p);

	/* if thread cannot be on this cpu, choose any good cpu */
	if (!cpumask_test_cpu(idlest->id, &task_15->cpus_allowed))
		idlest = &ipanema_core(cpumask_any(&task_15->cpus_allowed));

	p->slptime = ktime_sub(ktime_get(), p->last_blocked);

	return idlest->id;
}

static void ipanema_ule_wwc_unblock_place(struct ipanema_policy *policy,
					  struct process_event *e)
{
	struct ule_wwc_ipa_process *tgt = policy_metadata(e->target);
	int idlecore_11 = task_cpu(e->target);
	struct ule_wwc_ipa_core *c = &ipanema_core(idlecore_11);

	c->cload += tgt->load;
	tgt->order = c->order++;
	/* Memory barrier for proofs */
	smp_wmb();
	if (update_realtime(tgt))
		ipa_change_queue(tgt, &ipanema_state(idlecore_11).realtime,
				 IPANEMA_READY, c->id);
	else
		ipa_change_queue(tgt, &ipanema_state(idlecore_11).timeshare,
				 IPANEMA_READY, c->id);
}

static void ipanema_ule_wwc_unblock_end(struct ipanema_policy *policy,
					struct process_event *e)
{
	pr_info("[%d] post unblock on core %d\n", e->target->pid,
		       e->target->cpu);
}

static int get_slice(struct ule_wwc_ipa_process *t)
{
	int nb_threads = (&ipanema_core(task_cpu(t->task)))->cload;

	if (nb_threads > SCHED_SLICE_MIN_DIVISOR)
		return SCHED_SLICE / SCHED_SLICE_MIN_DIVISOR;
	if (nb_threads == 0)
		nb_threads++;
	return SCHED_SLICE / nb_threads;
}

static void ipanema_ule_wwc_schedule(struct ipanema_policy *policy,
				     unsigned int cpu)
{
	struct task_struct *task_20 = NULL;
	struct ule_wwc_ipa_process *p;
	struct ipanema_rq *rq = &ipanema_state(cpu).realtime;

	task_20 = ipanema_first_task(rq);
	if (!task_20) {
		rq = &ipanema_state(cpu).timeshare;
		task_20 = ipanema_first_task(rq);
		if (!task_20)
			return;
	}

	p = policy_metadata(task_20);
	p->last_schedule = ktime_get();
	p->last_core = cpu;
	p->slice = get_slice(p);

	if (task_cpu(task_20) != cpu ||
	    task_cpu(task_20) != rq->cpu ||
	    cpu != rq->cpu)
		pr_warn("%s(pid=%d): task_cpu()=%d ; cpu=%d ; rq->cpu=%d\n",
			__func__, task_20->pid, task_cpu(task_20), cpu,
			rq->cpu);

	ipa_change_curr(&ipanema_core(cpu), p);
}

static void ipanema_ule_wwc_core_entry(struct ipanema_policy *policy,
				       struct core_event *e)
{
	struct ule_wwc_ipa_core *tgt = &per_cpu(core, e->target);

	set_active_core(tgt, &cstate_info.active_cores, IPANEMA_ACTIVE_CORE);
}

static void ipanema_ule_wwc_core_exit(struct ipanema_policy *policy,
				      struct core_event *e)
{
	struct ule_wwc_ipa_core *tgt = &per_cpu(core, e->target);

	set_sleeping_core(tgt, &cstate_info.idle_cores, IPANEMA_IDLE_CORE);
}

static void ipanema_ule_wwc_newly_idle(struct ipanema_policy *policy,
				       struct core_event *e)
{
}

static void ipanema_ule_wwc_enter_idle(struct ipanema_policy *policy,
				       struct core_event *e)
{
	struct ule_wwc_ipa_core *tgt = &per_cpu(core, e->target);

	set_sleeping_core(tgt, &cstate_info.idle_cores, IPANEMA_IDLE_CORE);
}

static void ipanema_ule_wwc_exit_idle(struct ipanema_policy *policy,
				      struct core_event *e)
{
	struct ule_wwc_ipa_core *tgt = &per_cpu(core, e->target);

	set_active_core(tgt, &cstate_info.active_cores, IPANEMA_ACTIVE_CORE);
}

static void ipanema_ule_wwc_balancing(struct ipanema_policy *policy,
				      struct core_event *e)
{
	struct ule_wwc_ipa_core *c;
	int cpu;
	unsigned long flags;

	/* Generated if synchronized keyword is used */
	if (!spin_trylock_irqsave(&lb_lock, flags))
		return;

	for_each_possible_cpu(cpu) {
		c = &ipanema_core(cpu);
		sched_monitor_trace(PER_BLN_IPA_BEG, c->id, current, 0, 0);
		steal_for_dom(policy, c, NULL);
		sched_monitor_trace(PER_BLN_IPA_END, c->id, current, 0, 0);
	}

	/* Generated if synchronized keyword is used */
	spin_unlock_irqrestore(&lb_lock, flags);
}

static int ipanema_ule_wwc_init(struct ipanema_policy *policy)
{
	return 0;
}

static bool ipanema_ule_wwc_attach(struct ipanema_policy *policy,
				   struct task_struct *_fresh_14, char *command)
{
	return true;
}

int ipanema_ule_wwc_free_metadata(struct ipanema_policy *policy)
{
	kfree(policy->data);
	return 0;
}

int ipanema_ule_wwc_can_be_default(struct ipanema_policy *policy)
{
	return 1;
}

struct ipanema_module_routines ipanema_ule_wwc_routines = {
	.get_core_state = ipanema_ule_wwc_get_core_state,
	.new_prepare = ipanema_ule_wwc_new_prepare,
	.new_place = ipanema_ule_wwc_new_place,
	.new_end = ipanema_ule_wwc_new_end,
	.tick    = ipanema_ule_wwc_tick,
	.yield   = ipanema_ule_wwc_yield,
	.block   = ipanema_ule_wwc_block,
	.unblock_prepare
		 = ipanema_ule_wwc_unblock_prepare,
	.unblock_place
		 = ipanema_ule_wwc_unblock_place,
	.unblock_end
		 = ipanema_ule_wwc_unblock_end,
	.terminate
		 = ipanema_ule_wwc_detach,
	.schedule = ipanema_ule_wwc_schedule,
	.newly_idle
		 = ipanema_ule_wwc_newly_idle,
	.enter_idle
		 = ipanema_ule_wwc_enter_idle,
	.exit_idle
		 = ipanema_ule_wwc_exit_idle,
	.balancing_select
		 = ipanema_ule_wwc_balancing,
	.core_entry
		 = ipanema_ule_wwc_core_entry,
	.core_exit
		 = ipanema_ule_wwc_core_exit,
	.init    = ipanema_ule_wwc_init,
	.free_metadata
		 = ipanema_ule_wwc_free_metadata,
	.can_be_default
		 = ipanema_ule_wwc_can_be_default,
	.attach  = ipanema_ule_wwc_attach
};

static int init_topology(void)
{
	struct topology_level *t = per_cpu(topology_levels, 0);
	size_t size;
	int i;

	ule_wwc_ipa_nr_topology_levels = 0;

	while (t) {
		ule_wwc_ipa_nr_topology_levels++;
		t = t->next;
	}

	size = ule_wwc_ipa_nr_topology_levels * sizeof(struct list_head);
	ule_wwc_ipa_topology = kzalloc(size, GFP_KERNEL);
	if (!ule_wwc_ipa_topology) {
		ule_wwc_ipa_nr_topology_levels = 0;
		return -ENOMEM;
	}

	for (i = 0; i < ule_wwc_ipa_nr_topology_levels; i++) {
		INIT_LIST_HEAD(ule_wwc_ipa_topology + i);
	}

	return 0;
}

static void destroy_scheduling_domains(void)
{
	struct ule_wwc_ipa_sched_domain *sd, *tmp;
	int i;

	for (i = 0; i < ule_wwc_ipa_nr_topology_levels; i++) {
		list_for_each_entry_safe(sd, tmp, ule_wwc_ipa_topology + i,
					 siblings) {
			list_del(&sd->siblings);
			kfree(sd->groups);
			kfree(sd);
		}
	}

	kfree(ule_wwc_ipa_topology);
}

static int create_scheduling_domains(unsigned int cpu)
{
	struct topology_level *t = per_cpu(topology_levels, cpu);
	struct ule_wwc_ipa_core *c = &ipanema_core(cpu);
	size_t sd_size = sizeof(struct ule_wwc_ipa_sched_domain);
	unsigned int level = 0;
	struct ule_wwc_ipa_sched_domain *sd, *lower_sd = NULL;
	bool seen;

	c->sd = NULL;

	while (t) {
		/* if cpu is present in current level */
		seen = false;
		list_for_each_entry(sd, ule_wwc_ipa_topology + level, siblings) {
			if (cpumask_test_cpu(cpu, &sd->cores)) {
				seen = true;
				break;
			}
		}
		if (!seen) {
			sd = kzalloc(sd_size, GFP_KERNEL);
			if (!sd)
				goto err;
			INIT_LIST_HEAD(&sd->siblings);
			sd->parent = NULL;
			sd->___sched_group_idx = 0;
			sd->groups = NULL;
			cpumask_copy(&sd->cores, &t->cores);
			sd->flags = t->flags;
			spin_lock_init(&sd->lock);
			list_add_tail(&sd->siblings,
				      ule_wwc_ipa_topology + level);
		}
		if (lower_sd)
			lower_sd->parent = sd;
		else
			c->sd = sd;

		if (seen)
			break;

		lower_sd = sd;
		t = t->next;
		level++;
	}

	return 0;

err:
	destroy_scheduling_domains();
	return -ENOMEM;
}

static int build_groups(struct ule_wwc_ipa_sched_domain *sd,
			unsigned int lvl)
{
	struct ule_wwc_ipa_sched_domain *sdl;
	struct ule_wwc_ipa_sched_group *sg = NULL;
	int n = 0;

	list_for_each_entry(sdl, &ule_wwc_ipa_topology[lvl - 1], siblings) {
		if (cpumask_subset(&sdl->cores, &sd->cores)) {
			n++;
			sg = krealloc(sg,
				      n * sizeof(struct ule_wwc_ipa_sched_group),
				      GFP_KERNEL);
			if (!sg)
				goto err;

			cpumask_copy(&sg[n - 1].cores, &sdl->cores);
		}
	}

	sd->___sched_group_idx = n;
	sd->groups = sg;

	return 0;

err:
	destroy_scheduling_domains();
	return -ENOMEM;
}

static int build_lower_groups(struct ule_wwc_ipa_sched_domain *sd)
{
	int cpu, n, i = 0;

	n = cpumask_weight(&sd->cores);
	sd->groups = kzalloc(n * sizeof(struct ule_wwc_ipa_sched_group),
			     GFP_KERNEL);
	if (!sd->groups)
		goto fail;
	sd->___sched_group_idx = n;

	for_each_cpu(cpu, &sd->cores) {
		cpumask_clear(&sd->groups[i].cores);
		cpumask_set_cpu(cpu, &sd->groups[i].cores);
		i++;
	}

	return 0;

fail:
	destroy_scheduling_domains();
	return -ENOMEM;
}

/* Scheduling domains must be up to date for all CPUs */
static int create_scheduling_groups(void)
{
	struct ule_wwc_ipa_sched_domain *sd = NULL;
	int i, ret;

	for (i = ule_wwc_ipa_nr_topology_levels - 1; i > 0; i--) {
		list_for_each_entry(sd, &ule_wwc_ipa_topology[i], siblings) {
			ret = build_groups(sd, i);
			if (ret)
				goto fail;
		}
	}

	list_for_each_entry(sd, ule_wwc_ipa_topology, siblings) {
		ret = build_lower_groups(sd);
		if (ret)
			goto fail;
	}

	return 0;

fail:
	destroy_scheduling_domains();
	return -ENOMEM;
}

static void build_hierarchy(void)
{
	int cpu;

	init_topology();

	/* if unicore, don't build hierarchy */
	if (!ule_wwc_ipa_nr_topology_levels)
		return;

	/* create hierarchy for all cpus */
	for_each_possible_cpu(cpu) {
		create_scheduling_domains(cpu);
	}
	create_scheduling_groups();
}

static int proc_show(struct seq_file *s, void *p)
{
	long cpu = (long) s->private;
	struct task_struct *pos, *n;
	struct ule_wwc_ipa_process *pr, *curr_proc;
	struct ule_wwc_ipa_sched_domain *sd = ipanema_core(cpu).sd;
	int load_sum = 0, i;

	ipanema_lock_core(cpu);
	pr = ipanema_state(cpu).current_0;
	seq_printf(s, "CPU: %ld\n", cpu);
	seq_printf(s, "RUNNING (policy): %d (%d)\n",
		   pr ? pr->task->pid : -1,
		   pr ? pr->load : -1);
	n = get_ipanema_current(cpu);
	seq_printf(s, "RUNNING (runtime): %d\n", n ? n->pid : -1);
	load_sum += pr ? pr->load : 0;
	seq_printf(s, "-------------------------------\n");
	seq_printf(s, "READY[realtime]:\n");
	seq_printf(s, "rq: ");
	rbtree_postorder_for_each_entry_safe(pos, n,
					     &(ipanema_state(cpu).realtime).root,
					     ipanema.node_runqueue) {
		curr_proc = (struct ule_wwc_ipa_process *)policy_metadata(pos);
		load_sum += curr_proc->load;
		seq_printf(s, "%d (%d) -> ", pos->pid, curr_proc->load);
	}
	seq_printf(s, "\n");
	seq_printf(s, "nr_tasks = %d\n",
		   ipanema_state(cpu).realtime.nr_tasks);

	seq_printf(s, "-------------------------------\n");
	seq_printf(s, "READY[timeshare]:\n");
	seq_printf(s, "rq: ");
	rbtree_postorder_for_each_entry_safe(pos, n,
					     &(ipanema_state(cpu).timeshare).root,
					     ipanema.node_runqueue) {
		curr_proc = (struct ule_wwc_ipa_process *)policy_metadata(pos);
		load_sum += curr_proc->load;
		seq_printf(s, "%d (%d) -> ", pos->pid, curr_proc->load);
	}
	seq_printf(s, "\n");
	seq_printf(s, "nr_tasks = %d\n",
		   ipanema_state(cpu).timeshare.nr_tasks);

	seq_printf(s, "-------------------------------\n");
	seq_printf(s, "cload = %d\n", ipanema_core(cpu).cload);
	seq_printf(s, "cload_sum = %d\n", load_sum);

	seq_printf(s, "\nTopology:\n");
	while (sd) {
		seq_printf(s, "[%*pbl]: ", cpumask_pr_args(&sd->cores));
		for (i = 0; i < sd->___sched_group_idx; i++)
			seq_printf(s, "{%*pbl}",
				   cpumask_pr_args(&sd->groups[i].cores));
		seq_printf(s, "\n");
		sd = sd->parent;
	}

	ipanema_unlock_core(cpu);

	return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
	long cpu;

	if (!kstrtol(file->f_path.dentry->d_iname, 10, &cpu))
		return single_open(file, proc_show, (void *)cpu);
	return -ENOENT;
}

static struct file_operations proc_fops = {
	.owner   = THIS_MODULE,
	.open    = proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release
};

static int proc_topo_show(struct seq_file *s, void *p)
{
	int i;
	struct ule_wwc_ipa_sched_domain *sd;

	for (i = 0; i < ule_wwc_ipa_nr_topology_levels; i++) {
		seq_printf(s, "Level %d: ", i);
		list_for_each_entry(sd, ule_wwc_ipa_topology + i, siblings) {
			seq_printf(s, "[%*pbl]", cpumask_pr_args(&sd->cores));
		}
		seq_printf(s, "\n");
	}

	return 0;
}

static int proc_topo_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_topo_show, NULL);
}

static struct file_operations proc_topo_fops = {
	.owner   = THIS_MODULE,
	.open    = proc_topo_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

static int __init my_init_module(void)
{
	int res, cpu;
	struct proc_dir_entry *procdir = NULL;
	char procbuf[10];

	/* Initialize scheduler variables with non-const value (function call) */
	for_each_possible_cpu(cpu) {
		ipanema_core(cpu).id = cpu;
		/* FIXME init of core variables of the user */
		ipanema_core(cpu).cload = 0;
		/* allocation of ipanema rqs */
		init_ipanema_rq(&ipanema_state(cpu).realtime, RBTREE, cpu,
				IPANEMA_READY, ipanema_ule_wwc_order_process);
		init_ipanema_rq(&ipanema_state(cpu).timeshare, RBTREE, cpu,
				IPANEMA_READY, ipanema_ule_wwc_order_process);
	}

	/* build hierarchy with topology */
	build_hierarchy();

	/* Allocate & setup the ipanema_module */
	policy = kzalloc(sizeof(struct ipanema_policy), GFP_KERNEL);
	if (!policy) {
		res = -ENOMEM;
		goto end;
	}
	strncpy(policy->name, name, MAX_POLICY_NAME_LEN);
	policy->routines = &ipanema_ule_wwc_routines;
	policy->kmodule = THIS_MODULE;

	/* Register module to the runtime */
	res = ipanema_add_policy(policy);
	if (res)
		goto clean_policy;

	/*
	 * Create /proc//ipanema/cfs/ files
	 * If file creation fails, module insertion does not
	 */
	procdir = proc_mkdir(name, ipa_procdir);
	if (!procdir)
		pr_err("%s: /proc/ipanema/%s creation failed\n", name, name);
	for_each_possible_cpu(cpu) {
		scnprintf(procbuf, 10, "%d", cpu);
		if (!proc_create(procbuf, 0444, procdir, &proc_fops))
			pr_err("%s: /proc/ipanema/%s/%s creation failed\n",
			       name, name, procbuf);
	}
	if (!proc_create("topology", 0444, procdir, &proc_topo_fops))
		pr_err("%s: /proc/ipanema/%s/topology creation failed\n",
		       name, name);

	return 0;

clean_policy:
	kfree(policy);
end:
	return res;
}

static void __exit my_cleanup_module(void)
{
	int res;

	remove_proc_subtree(name, ipa_procdir);

	res = ipanema_remove_policy(policy);
	if (res) {
		pr_err("Cleanup failed (%d)\n", res);
		return;
	}

	destroy_scheduling_domains();
	kfree(policy);
}

module_init(my_init_module);
module_exit(my_cleanup_module);

MODULE_AUTHOR("RedhaCC");
MODULE_DESCRIPTION(KBUILD_MODNAME"_v4 scheduling policy");
MODULE_LICENSE("GPL");
