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

#define ipanema_assert(x)				\
	do {                                            \
		if (!(x))                               \
			panic("Error in " #x "\n");     \
	} while (0)
#define time_to_ticks(x) (ktime_to_ns(x) * HZ / 1000000000)
#define ticks_to_time(x) (ns_to_ktime(x * 1000000000 / HZ))

static char *name = KBUILD_MODNAME;
static struct ipanema_policy *policy;

static const int max_quanta_ms = 10;
static ktime_t max_quanta;

struct cfs_ipa_process {
	struct task_struct *task; // Internal
	ktime_t vruntime;
	ktime_t last_sched;
	int load;
};

struct state_info {
	struct cfs_ipa_process *current_0; /* private / unshared */
	struct ipanema_rq ready; /* public / shared */
};
DEFINE_PER_CPU_SHARED_ALIGNED(struct state_info, state_info);

static struct core_state_info {
	cpumask_t active_cores;
	cpumask_t idle_cores;
} cstate_info;


struct cfs_ipa_sched_domain;
struct cfs_ipa_sched_group;

struct cfs_ipa_core {
	enum ipanema_core_state state; // Internal
	cpumask_t *cpuset; // Internal
	int id; // System
	int cload;
	ktime_t min_vruntime;
	struct cfs_ipa_sched_domain *sd;
};
DEFINE_PER_CPU(struct cfs_ipa_core, core);

struct cfs_ipa_sched_group {
	cpumask_t cores;
	int capacity;
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
 *   cfs_ipa_topology
 */
struct cfs_ipa_sched_domain {
	struct list_head siblings;  // link domains of the same level
	struct cfs_ipa_sched_domain *parent;
	int ___sched_group_idx; // Internal
	struct cfs_ipa_sched_group *groups;
	cpumask_t cores;
	spinlock_t lock;
	int flags; // Internal
	ktime_t next_balance;
	unsigned int count;
};

static struct list_head *cfs_ipa_topology;
static unsigned int cfs_ipa_nr_topology_levels;

static inline void update_thread(struct cfs_ipa_process *p)
{
	ktime_t now = ktime_get();
	ktime_t used_time = ktime_sub(now, p->last_sched);

	p->vruntime = ktime_add(p->vruntime, used_time);
}

/*
 * Instant load:
 *   q = now - last_sched = time since p was scheduled
 *
 *       iload = 1024 - (1024 * (max_quanta - q)) / max_quanta
 *
 * Load:
 *   load(p) = 80% p->load + 20% iload
 *           = (8 * p->load + 2 * iload) / 10
 *
 * We also check that 0 > p->load > 1024
 */
static inline void update_load(struct cfs_ipa_process *p)
{
	ktime_t now = ktime_get();
	ktime_t q = ktime_sub(now, p->last_sched);
	int load = 1024 - (1024 * (max_quanta - q)) / max_quanta;

	p->load = (8 * p->load + 2 * load) / 10;
	if (!p->load)
		p->load = 1;
}

int ipanema_cfs_order_process(struct task_struct *a,
			      struct task_struct *b)
{
	struct cfs_ipa_process *pa = policy_metadata(a);
	struct cfs_ipa_process *pb = policy_metadata(b);

	return pa->vruntime - pb->vruntime;
}

static void ipa_change_curr(struct cfs_ipa_core *c,
			    struct cfs_ipa_process *p)
{
	BUG_ON(c->id != task_cpu(p->task));
	ipanema_state(c->id).current_0 = p;
	change_state(p->task, IPANEMA_RUNNING, c->id, NULL);
}

static void ipa_change_queue(struct cfs_ipa_process *p, struct ipanema_rq *rq,
			     enum ipanema_core_state state, unsigned int cpu)
{
	struct cfs_ipa_core *c = &ipanema_core(task_cpu(p->task));

	BUG_ON(rq && rq->cpu != cpu);

	if (ipanema_state(c->id).current_0 == p)
		ipanema_state(c->id).current_0 = NULL;
	change_state(p->task, state, cpu, rq);
}

static void set_active_core(struct cfs_ipa_core *core, cpumask_t *cores,
			    int state)
{
	core->state = state;
	if (core->cpuset)
		cpumask_clear_cpu(core->id, core->cpuset);
	cpumask_set_cpu(core->id, cores);
	core->cpuset = cores;
}

static void set_sleeping_core(struct cfs_ipa_core *core, cpumask_t *cores,
			      int state)
{
	core->state = state;
	if (core->cpuset)
		cpumask_clear_cpu(core->id, core->cpuset);
	cpumask_set_cpu(core->id, cores);
	core->cpuset = cores;
}

static enum ipanema_core_state
ipanema_cfs_get_core_state(struct ipanema_policy *policy, struct core_event *e)
{
	return ipanema_core(e->target).state;
}

static int migrate_from_to(struct cfs_ipa_core *busiest,
			   struct cfs_ipa_core *thief)
{
	struct task_struct *pos, *n;
	LIST_HEAD(tasks);
	struct sched_ipanema_entity *imd;
	struct cfs_ipa_process *t;
	int dbg_cpt = 0, ret, thief_cload;
	unsigned long flags;
	struct ipanema_rq *rq;

	/* Remove tasks from busiest */
	local_irq_save(flags);
	ipanema_lock_core(busiest->id);
	/* check if busiest is still stealable */
	if (ipanema_state(busiest->id).ready.nr_tasks +
	    ((&ipanema_state(busiest->id).current_0 == NULL) ? 0 : 1) <= 1)
		goto abort;

	thief_cload = thief->cload;
	rq = &ipanema_state(busiest->id).ready;
	rbtree_postorder_for_each_entry_safe(pos, n, &rq->root,
					     ipanema.node_runqueue) {
		t = policy_metadata(pos);
		if (pos->on_cpu)
			continue;

		if (!cpumask_test_cpu(thief->id, &pos->cpus_allowed))
			continue;

		if (busiest->cload - thief_cload > t->load) {
			list_add(&pos->ipanema.ipa_tasks, &tasks);
			t->vruntime -= busiest->min_vruntime;
			ipa_change_queue(t, NULL, IPANEMA_MIGRATING,
					 thief->id);
			dbg_cpt = dbg_cpt + 1;
			busiest->cload = busiest->cload - t->load;
			thief_cload = thief_cload + t->load;
		}
		/* Ensure migration cond. and stop cond. use the same ids ! */
		if (busiest->cload == thief_cload)
			break;
	}
abort:
	ipanema_unlock_core(busiest->id);
	ret = dbg_cpt;

	/* Add them to my queue */
	ipanema_lock_core(thief->id);
	while (!list_empty(&tasks)) {
		imd = list_first_entry(&tasks, struct sched_ipanema_entity,
				       ipa_tasks);
		pos = container_of(imd, struct task_struct, ipanema);
		t = policy_metadata(pos);
		t->vruntime += thief->min_vruntime;
		ipa_change_queue(t, &ipanema_state(thief->id).ready,
				 IPANEMA_READY, thief->id);
		thief->cload = thief->cload + t->load;
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

static struct cfs_ipa_core *
find_busiest_cpu(struct ipanema_policy *policy, cpumask_t *stealable_cores)
{
	int cpu;
	unsigned int max_load = 0;
	struct cfs_ipa_core *c = NULL, *busiest = NULL;

	for_each_cpu(cpu, stealable_cores) {
		c = &ipanema_core(cpu);
		if (c->cload > max_load) {
			max_load = c->cload;
			busiest = c;
		}
	}

	return busiest;
}

static inline int runnable(struct cfs_ipa_core *c)
{
	int nr_threads = 0;

	nr_threads += ipanema_state(c->id).ready.nr_tasks;
	nr_threads += ipanema_state(c->id).current_0 ? 1 : 0;

	return nr_threads;
}

static bool can_steal_core(struct cfs_ipa_core *tgt, struct cfs_ipa_core *thief)
{
	return runnable(tgt) > 1;
}

static struct cfs_ipa_core *select_core(struct ipanema_policy *policy,
					cpumask_t *stealable_cores)
{
	return find_busiest_cpu(policy, stealable_cores);
}

DEFINE_SPINLOCK(lb_lock);

static void steal_for_cpu(struct ipanema_policy *policy,
			  struct cfs_ipa_core *c)
{
	cpumask_t stealable_cores;
	int cpu;
	struct cfs_ipa_core *t, *selected;

	/* init bitmaps */
	cpumask_clear(&stealable_cores);

	/* Step 1: can_steal_core() */
	for_each_possible_cpu(cpu) {
		t = &ipanema_core(cpu);
		if (t == c)
			continue;
		if (can_steal_core(t, c))
			cpumask_set_cpu(cpu, &stealable_cores);
	}

	do {
		/* Step 2: select_core() */
		selected = select_core(policy, &stealable_cores);
		if (!selected)
			return;

		/* Step 3: steal_thread() */
		migrate_from_to(selected, c);

		cpumask_clear_cpu(selected->id, &stealable_cores);
	} while (runnable(c) == 0 && cpumask_weight(&stealable_cores) > 0);
}

static int ipanema_cfs_new_prepare(struct ipanema_policy *policy,
				   struct process_event *e)
{
	struct cfs_ipa_process *tgt;
	struct cfs_ipa_core *c, *idlest;
	struct task_struct *task_15;
	int cpu;

	task_15 = e->target;
	tgt = kzalloc(sizeof(struct cfs_ipa_process), GFP_ATOMIC);
	if (!tgt)
		return -1;

	policy_metadata(task_15) = tgt;
	tgt->task = task_15;

	/* find idlest CPU on the machine */
	idlest = &ipanema_core(task_cpu(task_15));
	for_each_cpu(cpu, &task_15->cpus_allowed) {
		c = &ipanema_core(cpu);
		if (c->cload < idlest->cload)
			idlest = c;
	}

	tgt->vruntime = idlest->min_vruntime;
	tgt->load = 1024;
	tgt->last_sched = ktime_get();

	return idlest->id;
}

static void ipanema_cfs_new_place(struct ipanema_policy *policy,
				   struct process_event *e)
{
	struct cfs_ipa_process *tgt = policy_metadata(e->target);
	int idlecore_10 = task_cpu(e->target);
	struct cfs_ipa_core *c = &ipanema_core(idlecore_10);

	c->cload += tgt->load;
	/* Memory barrier for proofs */
	smp_wmb();
	ipa_change_queue(tgt, &ipanema_state(task_cpu(tgt->task)).ready,
			 IPANEMA_READY, c->id);
}

static void ipanema_cfs_new_end(struct ipanema_policy *policy,
				 struct process_event *e)
{
	pr_info("[%d] post new on core %d\n", e->target->pid, e->target->cpu);
}

static void ipanema_cfs_detach(struct ipanema_policy *policy,
			       struct process_event *e)
/* need to free the process metadata memory */
{
	struct cfs_ipa_process *tgt = policy_metadata(e->target);
	struct cfs_ipa_core *c = &ipanema_core(task_cpu(tgt->task));

	ipa_change_queue(tgt, NULL, IPANEMA_TERMINATED, c->id);
	/* Memory barrier for proofs */
	smp_wmb();
	c->cload -= tgt->load;
	/* Memory barrier for proofs */
	smp_wmb();
	kfree(tgt);
}

static void ipanema_cfs_tick(struct ipanema_policy *policy,
			     struct process_event *e)
{
	struct cfs_ipa_process *tgt = policy_metadata(e->target);
	struct cfs_ipa_core *c = &ipanema_core(task_cpu(e->target));
	ktime_t now = ktime_get();
	ktime_t delta = ktime_sub(now, tgt->last_sched);
	int old_load = tgt->load;

	if (ktime_after(delta, max_quanta)) {
		update_thread(tgt);
		update_load(tgt);
		c->cload += (tgt->load - old_load);
		/* Memory barrier for proofs */
		smp_wmb();
		ipa_change_queue(tgt, &ipanema_state(task_cpu(tgt->task)).ready,
				 IPANEMA_READY_TICK, c->id);
	}
}

static void ipanema_cfs_yield(struct ipanema_policy *policy,
			      struct process_event *e)
{
	struct cfs_ipa_process *tgt = policy_metadata(e->target);
	struct cfs_ipa_core *c = &ipanema_core(task_cpu(e->target));
	int old_load = tgt->load;

	update_thread(tgt);
	update_load(tgt);
	c->cload += (tgt->load - old_load);
	/* Memory barrier for proofs */
	smp_wmb();
	ipa_change_queue(tgt, &ipanema_state(task_cpu(tgt->task)).ready,
			 IPANEMA_READY, c->id);
}

static void ipanema_cfs_block(struct ipanema_policy *policy,
			      struct process_event *e)
{
	struct cfs_ipa_process *tgt = policy_metadata(e->target);
	struct cfs_ipa_core *c = &ipanema_core(task_cpu(e->target));
	int old_load = tgt->load;

	update_thread((struct cfs_ipa_process *)tgt);
	update_load((struct cfs_ipa_process *)tgt);
	ipa_change_queue(tgt, NULL, IPANEMA_BLOCKED, c->id);

	tgt->vruntime -= c->min_vruntime;

	/* Memory barrier for proofs */
	smp_wmb();
	c->cload -= old_load;
	/* Memory barrier for proofs */
	smp_wmb();
}

static int ipanema_cfs_unblock_prepare(struct ipanema_policy *policy,
				       struct process_event *e)
{
	struct task_struct *task_15 = e->target;
	struct cfs_ipa_process *p = policy_metadata(task_15);
	struct cfs_ipa_core *c, *idlest;
	int cpu;

	idlest = &ipanema_core(task_cpu(task_15));

	/* Search for the idlest core on the machine */
	for_each_cpu(cpu, &task_15->cpus_allowed) {
		c = &ipanema_core(cpu);
		if (c->cload < idlest->cload)
			idlest = c;
	}

	/* add min_vruntime from new cpu */
	p->vruntime += idlest->min_vruntime;

	return idlest->id;
}

static void ipanema_cfs_unblock_place(struct ipanema_policy *policy,
				       struct process_event *e)
{
	struct cfs_ipa_process *tgt = policy_metadata(e->target);
	int idlecore_11 = task_cpu(e->target);
	struct cfs_ipa_core *c = &ipanema_core(idlecore_11);

	c->cload += tgt->load;
	/* Memory barrier for proofs */
	smp_wmb();
	ipa_change_queue(tgt, &ipanema_state(idlecore_11).ready,
			 IPANEMA_READY, c->id);
}

static void ipanema_cfs_unblock_end(struct ipanema_policy *policy,
				     struct process_event *e)
{
	pr_info("[%d] post unblock on core %d\n", e->target->pid,
		e->target->cpu);
}

static void ipanema_cfs_schedule(struct ipanema_policy *policy,
				 unsigned int cpu)
{
	struct task_struct *task_20 = NULL;
	struct cfs_ipa_process *p;
	struct cfs_ipa_core *c = &ipanema_core(cpu);

	task_20 = ipanema_first_task(&ipanema_state(cpu).ready);
	if (!task_20)
		return;

	p = policy_metadata(task_20);
	p->last_sched = ktime_get();

	c->min_vruntime = p->vruntime;

	ipa_change_curr(c, p);
}

static void ipanema_cfs_core_entry(struct ipanema_policy *policy,
				    struct core_event *e)
{
	struct cfs_ipa_core *tgt = &per_cpu(core, e->target);

	tgt->min_vruntime = 0;
	set_active_core(tgt, &cstate_info.active_cores, IPANEMA_ACTIVE_CORE);
}

static void ipanema_cfs_core_exit(struct ipanema_policy *policy,
				  struct core_event *e)
{
	struct cfs_ipa_core *tgt = &per_cpu(core, e->target);

	set_sleeping_core(tgt, &cstate_info.idle_cores, IPANEMA_IDLE_CORE);
}

static void ipanema_cfs_newly_idle(struct ipanema_policy *policy,
				   struct core_event *e)
{
	struct cfs_ipa_core *c = &per_cpu(core, e->target);
	unsigned long flags;

	/* Generated if synchronized keyword is used */
	if (!spin_trylock_irqsave(&lb_lock, flags))
		return;

	steal_for_cpu(policy, c);

	/* Generated if synchronized keyword is used */
	spin_unlock_irqrestore(&lb_lock, flags);
}

static void ipanema_cfs_enter_idle(struct ipanema_policy *policy,
				   struct core_event *e)
{
	struct cfs_ipa_core *tgt = &per_cpu(core, e->target);

	set_sleeping_core(tgt, &cstate_info.idle_cores, IPANEMA_IDLE_CORE);
}

static void ipanema_cfs_exit_idle(struct ipanema_policy *policy,
				  struct core_event *e)
{
	struct cfs_ipa_core *tgt = &per_cpu(core, e->target);

	set_active_core(tgt, &cstate_info.active_cores, IPANEMA_ACTIVE_CORE);
}

static void ipanema_cfs_balancing(struct ipanema_policy *policy,
				  struct core_event *e)
{
	struct cfs_ipa_core *c = &ipanema_core(e->target), *thief;
	struct cfs_ipa_sched_domain *sd;
	ktime_t now = ktime_get();
	u64 interval = ms_to_ktime(num_possible_cpus());
	int cpu;
	unsigned long flags;

	/* Generated if synchronized keyword is used */
	if (!spin_trylock_irqsave(&lb_lock, flags))
		return;

	sd = c->sd;
	while (sd->parent)
		sd = sd->parent;

	if (ktime_before(sd->next_balance, now)) {
		for_each_possible_cpu(cpu) {
			thief = &ipanema_core(cpu);
			steal_for_cpu(policy, thief);
		}
		sd->count++;
		sd->next_balance = ktime_add(ktime_get(), interval);
	}

	/* Generated if synchronized keyword is used */
	spin_unlock_irqrestore(&lb_lock, flags);
}

static int ipanema_cfs_init(struct ipanema_policy *policy)
{
	return 0;
}

static bool ipanema_cfs_attach(struct ipanema_policy *policy,
			       struct task_struct *_fresh_14, char *command)
{
	return true;
}

int ipanema_cfs_free_metadata(struct ipanema_policy *policy)
{
	kfree(policy->data);
	return 0;
}

int ipanema_cfs_can_be_default(struct ipanema_policy *policy)
{
	return 1;
}

struct ipanema_module_routines ipanema_cfs_routines = {
	.get_core_state = ipanema_cfs_get_core_state,
	.new_prepare
		 = ipanema_cfs_new_prepare,
	.new_place
		 = ipanema_cfs_new_place,
	.new_end = ipanema_cfs_new_end,
	.tick    = ipanema_cfs_tick,
	.yield   = ipanema_cfs_yield,
	.block   = ipanema_cfs_block,
	.unblock_prepare
		 = ipanema_cfs_unblock_prepare,
	.unblock_place
		 = ipanema_cfs_unblock_place,
	.unblock_end
		 = ipanema_cfs_unblock_end,
	.terminate
		 = ipanema_cfs_detach,
	.schedule = ipanema_cfs_schedule,
	.newly_idle
		 = ipanema_cfs_newly_idle,
	.enter_idle
		 = ipanema_cfs_enter_idle,
	.exit_idle
		 = ipanema_cfs_exit_idle,
	.balancing_select
		 = ipanema_cfs_balancing,
	.core_entry
		 = ipanema_cfs_core_entry,
	.core_exit
		 = ipanema_cfs_core_exit,
	.init    = ipanema_cfs_init,
	.free_metadata
		 = ipanema_cfs_free_metadata,
	.can_be_default
		 = ipanema_cfs_can_be_default,
	.attach  = ipanema_cfs_attach
};

static int init_topology(void)
{
	struct topology_level *t = per_cpu(topology_levels, 0);
	size_t size;
	int i;

	cfs_ipa_nr_topology_levels = 0;

	while (t) {
		cfs_ipa_nr_topology_levels++;
		t = t->next;
	}

	size = cfs_ipa_nr_topology_levels * sizeof(struct list_head);
	cfs_ipa_topology = kzalloc(size, GFP_KERNEL);
	if (!cfs_ipa_topology) {
		cfs_ipa_nr_topology_levels = 0;
		return -ENOMEM;
	}

	for (i = 0; i < cfs_ipa_nr_topology_levels; i++)
		INIT_LIST_HEAD(cfs_ipa_topology + i);

	return 0;
}

static void destroy_scheduling_domains(void)
{
	struct cfs_ipa_sched_domain *sd, *tmp;
	int i;

	for (i = 0; i < cfs_ipa_nr_topology_levels; i++) {
		list_for_each_entry_safe(sd, tmp, cfs_ipa_topology + i,
					 siblings) {
			list_del(&sd->siblings);
			kfree(sd->groups);
			kfree(sd);
		}
	}

	kfree(cfs_ipa_topology);
}

static int create_scheduling_domains(unsigned int cpu)
{
	struct topology_level *t = per_cpu(topology_levels, cpu);
	struct cfs_ipa_core *c = &ipanema_core(cpu);
	size_t sd_size = sizeof(struct cfs_ipa_sched_domain);
	unsigned int level = 0;
	struct cfs_ipa_sched_domain *sd, *lower_sd = NULL;
	bool seen;

	c->sd = NULL;

	while (t) {
		/* if cpu is present in current level */
		seen = false;
		list_for_each_entry(sd, cfs_ipa_topology + level, siblings) {
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
			sd->next_balance = 0;
			sd->count = 0;
			spin_lock_init(&sd->lock);
			list_add_tail(&sd->siblings, cfs_ipa_topology + level);
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

static int build_groups(struct cfs_ipa_sched_domain *sd,
			unsigned int lvl)
{
	struct cfs_ipa_sched_domain *sdl;
	struct cfs_ipa_sched_group *sg = NULL;
	int n = 0;

	list_for_each_entry(sdl, &cfs_ipa_topology[lvl - 1], siblings) {
		if (cpumask_subset(&sdl->cores, &sd->cores)) {
			n++;
			sg = krealloc(sg,
				      n * sizeof(struct cfs_ipa_sched_group),
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

static int build_lower_groups(struct cfs_ipa_sched_domain *sd)
{
	int cpu, n, i = 0;

	n = cpumask_weight(&sd->cores);
	sd->groups = kcalloc(n, sizeof(struct cfs_ipa_sched_group),
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
	struct cfs_ipa_sched_domain *sd = NULL;
	int i, ret;

	for (i = cfs_ipa_nr_topology_levels - 1; i > 0; i--) {
		list_for_each_entry(sd, &cfs_ipa_topology[i], siblings) {
			ret = build_groups(sd, i);
			if (ret)
				goto fail;
		}
	}

	list_for_each_entry(sd, cfs_ipa_topology, siblings) {
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
	if (!cfs_ipa_nr_topology_levels)
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
	struct cfs_ipa_process *pr, *curr_proc;
	struct cfs_ipa_sched_domain *sd = ipanema_core(cpu).sd;
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
	seq_puts(s, "READY: ");
	rbtree_postorder_for_each_entry_safe(pos, n,
					     &(ipanema_state(cpu).ready).root,
					     ipanema.node_runqueue) {
		curr_proc = (struct cfs_ipa_process *)policy_metadata(pos);
		load_sum += curr_proc->load;
		seq_printf(s, "%d (%d) -> ", pos->pid, curr_proc->load);
	}

	seq_puts(s, "\n");
	seq_printf(s, "COUNT(READY) = %d\n", count(IPANEMA_READY, cpu));
	seq_printf(s, "load = %d\n", ipanema_core(cpu).cload);
	seq_printf(s, "load_sum = %d\n", load_sum);

	seq_puts(s, "\nTopology:\n");
	while (sd) {
		seq_printf(s, "[%*pbl]: ", cpumask_pr_args(&sd->cores));
		for (i = 0; i < sd->___sched_group_idx; i++)
			seq_printf(s, "{%*pbl}",
				   cpumask_pr_args(&sd->groups[i].cores));
		seq_puts(s, "\n");
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

static const struct file_operations proc_fops = {
	.owner   = THIS_MODULE,
	.open    = proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release
};

static int proc_topo_show(struct seq_file *s, void *p)
{
	int i;
	struct cfs_ipa_sched_domain *sd;

	for (i = 0; i < cfs_ipa_nr_topology_levels; i++) {
		seq_printf(s, "Level %d: ", i);
		list_for_each_entry(sd, cfs_ipa_topology + i, siblings) {
			seq_printf(s, "[%*pbl]", cpumask_pr_args(&sd->cores));
		}
		seq_puts(s, "\n");
	}

	return 0;
}

static int proc_topo_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_topo_show, NULL);
}

static const struct file_operations proc_topo_fops = {
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

	max_quanta = ms_to_ktime(max_quanta_ms);

	/* Initialize scheduler variables with non-const value */
	for_each_possible_cpu(cpu) {
		ipanema_core(cpu).id = cpu;
		/* FIXME init of core variables of the user */
		ipanema_core(cpu).cload = 0;
		/* allocation of ipanema rqs */
		init_ipanema_rq(&ipanema_state(cpu).ready, RBTREE, cpu,
				IPANEMA_READY, ipanema_cfs_order_process);
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
	policy->routines = &ipanema_cfs_routines;
	policy->kmodule = THIS_MODULE;

	/* Register module to the runtime */
	res = ipanema_add_policy(policy);
	if (res)
		goto clean_policy;

	/*
	 * Create /proc/ipanema/cfs_wwc_flat/ files
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
MODULE_DESCRIPTION(KBUILD_MODNAME"_v2 scheduling policy");
MODULE_LICENSE("GPL");
