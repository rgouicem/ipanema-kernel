#define pr_fmt(fmt) "ipanema[" KBUILD_MODNAME "]: " fmt

#include <linux/delay.h>
#include <linux/ipanema.h>
#include <linux/ipanema_rq.h>
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
#include <uapi/linux/sched/types.h>
#include <linux/uaccess.h>

#include "../kernel/sched/monitor.h"


#define ipanema_assert(x) do{if(!(x)) panic("Error in " #x "\n");} while(0)

static char *name = "batch";
static struct ipanema_module *module;

struct batch_ipa_process;
struct batch_ipa_core;
struct batch_ipa_sched_domain;
struct batch_ipa_sched_group;

/* definition of protocol states */
struct state_info {
	struct batch_ipa_process *curr; /* private / unshared */
	struct ipanema_rq normal; /* public / shared */
};


// At least a READY queue is often shared.
// Optimization: use DEFINE_PER_CPU_ALIGNED(type, name) otherwise.
// See include/linux/percpu-defs.h for more information.
DEFINE_PER_CPU_SHARED_ALIGNED(struct state_info, state_info);


struct batch_ipa_process {
	enum ipanema_state state; // Internal
	struct ipanema_rq *rq; // Internal
	struct rb_node node; // Internal
	struct task_struct *task; // Internal
	ktime_t start;
	ktime_t runtime;
	/* list_head for balancing */
	struct list_head list;
};

struct batch_ipa_core {
	enum ipanema_core_state state; // Internal
	cpumask_t *cpuset; // Internal
	int id; // System
	struct batch_ipa_sched_domain *sd;
};

struct batch_ipa_sched_group {
	cpumask_t cores;
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
 *   batch_ipa_topology
 */
struct batch_ipa_sched_domain {
	/* domain attributes
	 *  specified by the scheduling policy
	 *  in the domain = {...} declaration
	 */
	struct list_head siblings;  // link domains of the same level
	struct batch_ipa_sched_domain *parent;
	int ___sched_group_idx; // Internal
	struct batch_ipa_sched_group *groups;
	cpumask_t cores;
	spinlock_t lock;
	int flags; // Internal
	ktime_t next_balance;
	unsigned int count;
};

static struct list_head *batch_ipa_topology;
static unsigned int batch_ipa_nr_topology_levels;

DEFINE_PER_CPU(struct batch_ipa_core, core);

static int ipanema_batch_order_process(struct task_struct *a,
				      struct task_struct *b)
{
	struct batch_ipa_process *pa = policy_metadata(a);
	struct batch_ipa_process *pb = policy_metadata(b);

	return ktime_compare(pa->runtime, pb->runtime);
}

static void ipa_change_proc(struct batch_ipa_process *proc,
			    struct batch_ipa_process **dst,
			    enum ipanema_state state)
{
	*dst = proc;
	proc->state = state;
	proc->rq = NULL;
	change_state(proc->task, state, task_cpu(proc->task), NULL);
}

static void ipa_change_queue(struct batch_ipa_process *proc,
			     struct ipanema_rq *rq,
			     enum ipanema_state state)
{
	if (proc->state == IPANEMA_RUNNING)
		ipanema_state(task_cpu(proc->task)).curr = NULL;
	proc->state = state;
	proc->rq = rq;
	change_state(proc->task, state, task_cpu(proc->task), rq);
}


static void ipa_change_queue_and_core(struct batch_ipa_process *proc,
				      struct ipanema_rq *rq,
				      enum ipanema_state state,
				      struct batch_ipa_core *core)
{
	if (proc->state == IPANEMA_RUNNING)
		ipanema_state(task_cpu(proc->task)).curr = NULL;
	proc->state = state;
	proc->rq = rq;
	change_state(proc->task, state, core->id, rq);
}

static enum ipanema_core_state
ipanema_batch_get_core_state(struct ipanema_policy *policy, struct core_event *e)
{
	return ipanema_core(e->target).state;
}

static unsigned int detach_tasks(struct ipanema_rq *rq, int nr,
				 struct list_head *list,
				 int next_cpu)
{
	struct task_struct *p, *n;
	struct batch_ipa_process *tgt;
	unsigned int nr_detached = 0;

	ipanema_lock_core(rq->cpu);
	rbtree_postorder_for_each_entry_safe(p, n, &rq->root,
					     ipanema.node_runqueue) {
		if (p->on_cpu)
			continue;
		if (ipanema_task_state(p) != IPANEMA_READY)
			continue;

		tgt = policy_metadata(p);

		list_add_tail(&tgt->list, list);
		tgt->rq = NULL;
		change_state(p, IPANEMA_MIGRATING, next_cpu, NULL);
		nr_detached++;

		if (nr == nr_detached)
			break;
	}
	ipanema_unlock_core(rq->cpu);

	return nr_detached;
}

static unsigned int attach_tasks(struct ipanema_rq *rq, struct list_head *list)
{
	struct task_struct *p = NULL;
	struct batch_ipa_process *tgt;
	unsigned int nr_attached = 0;

	ipanema_lock_core(rq->cpu);
	while (!list_empty(list)) {
		tgt = list_first_entry(list, struct batch_ipa_process, list);
		p = tgt->task;
		tgt->rq = rq;
		change_state(p, IPANEMA_READY, rq->cpu, rq);
		list_del_init(&tgt->list);
		nr_attached++;
	}
	ipanema_unlock_core(rq->cpu);

	return nr_attached;
}

static void balance_cpus(struct batch_ipa_core *victim,
			 struct batch_ipa_core *thief)
{
	LIST_HEAD(stolen_tasks);
	struct ipanema_rq *victim_n_rq, *thief_n_rq;
	unsigned int nr;
	unsigned long flags;

	/* Compute number of tasks to steal in order to balance */
	victim_n_rq = &ipanema_state(victim->id).normal;
	thief_n_rq = &ipanema_state(thief->id).normal;
	if (victim_n_rq->nr_tasks <= thief_n_rq->nr_tasks + 1)
		return;
	nr = (victim_n_rq->nr_tasks - thief_n_rq->nr_tasks) / 2;

	local_irq_save(flags);

	/* Remove tasks from victim's normal rq */
	detach_tasks(victim_n_rq, nr, &stolen_tasks, thief->id);

	/* Add them to my queue */
	nr = attach_tasks(thief_n_rq, &stolen_tasks);

	local_irq_restore(flags);
}

static inline struct batch_ipa_core *
find_idlest_cpu(struct ipanema_policy *policy, struct batch_ipa_sched_domain *sd)
{
	unsigned int min_nr = UINT_MAX;
	int cpu;
	struct ipanema_rq *rq;
	struct batch_ipa_core *idlest = NULL;

	for_each_cpu_and(cpu, &sd->cores, &policy->allowed_cores) {
		rq = &ipanema_state(cpu).normal;
		if (rq->nr_tasks < min_nr) {
			min_nr = rq->nr_tasks;
			idlest = &ipanema_core(cpu);
		}
	}

	return idlest;
}

static int ipanema_batch_new_prepare(struct ipanema_policy *policy,
				    struct process_event *e)
{
	struct batch_ipa_process *tgt;
	struct batch_ipa_sched_domain *sd;
	struct batch_ipa_core *c, *idlest = NULL;
	struct task_struct *task_15;

	task_15 = e->target;
	tgt = kzalloc(sizeof(struct batch_ipa_process), GFP_ATOMIC);
	if (!tgt)
		return -1;

	policy_metadata(task_15) = tgt;
	tgt->task = task_15;
	tgt->rq = NULL;

	/* find idlest group in highest domain, then idlest core */
	c = &ipanema_core(task_cpu(task_15));
	sd = c->sd;
	while (sd) {
		if (!sd->parent)
			break;
		sd = sd->parent;
	}
	idlest = find_idlest_cpu(policy, sd);

	/* should never happen ? */
	if (!idlest)
		idlest = c;
	tgt->start = ktime_get();
	tgt->runtime = ms_to_ktime(0);

	return idlest->id;
}

static void ipanema_batch_new_place(struct ipanema_policy *policy,
				   struct process_event *e)
{
	struct task_struct *p = e->target;
	struct batch_ipa_process *tgt = policy_metadata(p);
	struct batch_ipa_core *c = &ipanema_core(task_cpu(p));
	struct ipanema_rq *rq = &ipanema_state(c->id).normal;

	ipa_change_queue_and_core(tgt, rq, IPANEMA_READY, c);
}

static void ipanema_batch_new_end(struct ipanema_policy *policy,
				 struct process_event *e)
{
	pr_info("[%d] post new on core %d\n",
		       e->target->pid, e->target->cpu);
}

static void ipanema_batch_detach(struct ipanema_policy *policy,
				struct process_event *e)
/* need to free the process metadata memory */
{
	struct batch_ipa_process *tgt = policy_metadata(e->target);

	ipa_change_queue(tgt, NULL, IPANEMA_TERMINATED);
	kfree(tgt);
}

static inline void update_runtime(struct batch_ipa_process *p)
{
	ktime_t delta = ktime_sub(ktime_get(), p->start);
	p->runtime = ktime_add(p->runtime, delta);
}

static void ipanema_batch_tick(struct ipanema_policy *policy,
			      struct process_event *e)
{
}

static void ipanema_batch_yield(struct ipanema_policy *policy,
			       struct process_event *e)
{
	struct batch_ipa_process *tgt = policy_metadata(e->target);
	struct batch_ipa_core *c = &ipanema_core(task_cpu(e->target));
	struct ipanema_rq *rq = &ipanema_state(c->id).normal;

	update_runtime(tgt);
	ipa_change_queue(tgt, rq, IPANEMA_READY);
}

static void ipanema_batch_block(struct ipanema_policy *policy,
			       struct process_event *e)
{
	struct batch_ipa_process *tgt = policy_metadata(e->target);

	update_runtime(tgt);
	ipa_change_queue(tgt, NULL, IPANEMA_BLOCKED);
}

static int ipanema_batch_unblock_prepare(struct ipanema_policy *policy,
					struct process_event *e)
{
	struct task_struct *task_15 = e->target;
	struct batch_ipa_sched_domain *sd;
	struct batch_ipa_core *c, *idlest = NULL;

	/* remove min_vruntime from previous cpu */
	c = &ipanema_core(task_cpu(task_15));

	/* if c is idle, choose it */
	if (c->state == IPANEMA_IDLE_CORE) {
		idlest = c;
		goto end;
	}
	/* Search for the closest idle core sharing cache */
	sd = c->sd;
	while (sd) {
		if (!sd->parent)
			break;
		sd = sd->parent;
	}
	idlest = find_idlest_cpu(policy, sd);

	/* if no core found, wake up on previous core */
	if (!idlest)
		idlest = c;

end:
	return idlest->id;
}

static void ipanema_batch_unblock_place(struct ipanema_policy *policy,
				       struct process_event *e)
{
	struct task_struct *p = e->target;
	struct batch_ipa_process *tgt = policy_metadata(p);
	struct batch_ipa_core *c = &ipanema_core(task_cpu(p));
	struct ipanema_rq *rq = &ipanema_state(c->id).normal;

	ipa_change_queue_and_core(tgt, rq, IPANEMA_READY, c);
}

static void ipanema_batch_unblock_end(struct ipanema_policy *policy,
				     struct process_event *e)
{
	pr_info("[%d] post unblock on core %d\n", e->target->pid,
		       e->target->cpu);
}

static void ipanema_batch_schedule(struct ipanema_policy *policy,
				  unsigned int cpu)
{
	struct task_struct *task_20 = NULL;
	struct batch_ipa_process *p;

	task_20 = ipanema_first_task(&ipanema_state(cpu).normal);
	if (!task_20)
		return;

	p = policy_metadata(task_20);
	p->start = ktime_get();

	ipa_change_proc(p, &ipanema_state(cpu).curr, IPANEMA_RUNNING);
}

static void ipanema_batch_core_entry(struct ipanema_policy *policy,
				    struct core_event *e)
{
	struct batch_ipa_core *c = &ipanema_core(e->target);

	c->state = IPANEMA_ACTIVE_CORE;
}

static void ipanema_batch_core_exit(struct ipanema_policy *policy,
				   struct core_event *e)
{
	struct batch_ipa_core *c = &ipanema_core(e->target);

	c->state = IPANEMA_IDLE_CORE;
}

static inline struct batch_ipa_core *
find_busiest_cpu(struct ipanema_policy *policy,
		 struct batch_ipa_sched_domain *sd)
{
	unsigned int max_nr = 0;
	int cpu;
	struct ipanema_rq *rq;
	struct batch_ipa_core *busiest = NULL;

	for_each_cpu_and(cpu, &sd->cores, &policy->allowed_cores) {
		rq = &ipanema_state(cpu).normal;
		if (rq->nr_tasks > max_nr) {
			max_nr = rq->nr_tasks;
			busiest = &ipanema_core(cpu);
		}
	}

	return busiest;
}

static void ipanema_batch_newly_idle(struct ipanema_policy *policy,
				    struct core_event *e)
{
	struct batch_ipa_core *c = &ipanema_core(e->target), *tgt;
	struct batch_ipa_sched_domain *sd = c->sd;

	while (sd) {
		tgt = find_busiest_cpu(policy, sd);
		if (!tgt || tgt == c)
			goto next;
		balance_cpus(tgt, c);
		if (ipanema_state(c->id).normal.nr_tasks)
			break;
	next:
		sd = sd->parent;
	}
}

static void ipanema_batch_enter_idle(struct ipanema_policy *policy,
				    struct core_event *e)
{
	struct batch_ipa_core *c = &ipanema_core(e->target);

	c->state = IPANEMA_IDLE_CORE;
}

static void ipanema_batch_exit_idle(struct ipanema_policy *policy,
				   struct core_event *e)
{
	struct batch_ipa_core *c = &ipanema_core(e->target);

	c->state = IPANEMA_ACTIVE_CORE;
}

static void ipanema_batch_balancing(struct ipanema_policy *policy,
				   struct core_event *e)
{
	struct batch_ipa_core *c = &ipanema_core(e->target), *victim;
	struct batch_ipa_sched_domain *sd;
	ktime_t now = ktime_get();
	unsigned long flags;
	u64 delta;

	local_irq_save(flags);

	sd = c->sd;
	while (sd) {
		if (ktime_before(sd->next_balance, now)) {
			victim = find_busiest_cpu(policy, sd);
			if (!victim || victim == c)
				goto next;
			balance_cpus(victim, c);
			delta = cpumask_weight(&sd->cores);
			sd->next_balance = ktime_add(now, ms_to_ktime(delta));
		}
	next:
		sd = sd->parent;
	}

	local_irq_restore(flags);
}

static int ipanema_batch_init(struct ipanema_policy * policy)
{
	return 0;
}

static bool ipanema_batch_attach(struct ipanema_policy * policy,
				struct task_struct * _fresh_14, char * command)
{
	return true;
}

static int ipanema_batch_free_metadata(struct ipanema_policy *policy)
{
	kfree(policy->data);
	return 0;
}

static int ipanema_batch_can_be_default(struct ipanema_policy *policy)
{
	return 1;
}

struct ipanema_module_routines ipanema_batch_routines =
{
	.get_core_state   = ipanema_batch_get_core_state,
	.new_prepare      = ipanema_batch_new_prepare,
	.new_place        = ipanema_batch_new_place,
	.new_end          = ipanema_batch_new_end,
	.tick             = ipanema_batch_tick,
	.yield            = ipanema_batch_yield,
	.block            = ipanema_batch_block,
	.unblock_prepare  = ipanema_batch_unblock_prepare,
	.unblock_place    = ipanema_batch_unblock_place,
	.unblock_end      = ipanema_batch_unblock_end,
	.terminate        = ipanema_batch_detach,
	.schedule         = ipanema_batch_schedule,
	.newly_idle       = ipanema_batch_newly_idle,
	.enter_idle       = ipanema_batch_enter_idle,
	.exit_idle        = ipanema_batch_exit_idle,
	.balancing_select = ipanema_batch_balancing,
	.core_entry       = ipanema_batch_core_entry,
	.core_exit        = ipanema_batch_core_exit,
	.init             = ipanema_batch_init,
	.free_metadata    = ipanema_batch_free_metadata,
	.can_be_default   = ipanema_batch_can_be_default,
	.attach           = ipanema_batch_attach,
};

static int init_topology(void)
{
	struct topology_level *t = per_cpu(topology_levels, 0);
	size_t size;
	int i;

	batch_ipa_nr_topology_levels = 0;

	while (t) {
		batch_ipa_nr_topology_levels++;
		t = t->next;
	}

	size = batch_ipa_nr_topology_levels * sizeof(struct list_head);
	batch_ipa_topology = kzalloc(size, GFP_KERNEL);
	if (!batch_ipa_topology) {
		batch_ipa_nr_topology_levels = 0;
		return -ENOMEM;
	}

	for (i = 0; i < batch_ipa_nr_topology_levels; i++) {
		INIT_LIST_HEAD(batch_ipa_topology + i);
	}

	return 0;
}

static void destroy_scheduling_domains(void)
{
	struct batch_ipa_sched_domain *sd, *tmp;
	int i;

	for (i = 0; i < batch_ipa_nr_topology_levels; i++) {
		list_for_each_entry_safe(sd, tmp, batch_ipa_topology + i,
					 siblings) {
			list_del(&sd->siblings);
			kfree(sd->groups);
			kfree(sd);
		}
	}

	kfree(batch_ipa_topology);
}

static int create_scheduling_domains(unsigned int cpu)
{
	struct topology_level *t = per_cpu(topology_levels, cpu);
	struct batch_ipa_core *c = &ipanema_core(cpu);
	size_t sd_size = sizeof(struct batch_ipa_sched_domain);
	unsigned int level = 0;
	struct batch_ipa_sched_domain *sd, *lower_sd = NULL;
	bool seen;

	c->sd = NULL;

	while (t) {
		/* if cpu is present in current level */
		seen = false;
		list_for_each_entry(sd, batch_ipa_topology + level, siblings) {
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
			list_add_tail(&sd->siblings, batch_ipa_topology + level);
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

static int build_groups(struct batch_ipa_sched_domain *sd,
			unsigned int lvl)
{
	struct batch_ipa_sched_domain *sdl;
	struct batch_ipa_sched_group *sg = NULL;
	int n = 0;

	list_for_each_entry(sdl, &batch_ipa_topology[lvl - 1], siblings) {
		if (cpumask_subset(&sdl->cores, &sd->cores)) {
			n++;
			sg = krealloc(sg,
				      n * sizeof(struct batch_ipa_sched_group),
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

static int build_lower_groups(struct batch_ipa_sched_domain *sd)
{
	int cpu, n, i = 0;

	n = cpumask_weight(&sd->cores);
	sd->groups = kzalloc(n * sizeof(struct batch_ipa_sched_group),
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
	struct batch_ipa_sched_domain *sd = NULL;
	int i, ret;

	for (i = batch_ipa_nr_topology_levels - 1; i > 0; i--) {
		list_for_each_entry(sd, &batch_ipa_topology[i], siblings) {
			ret = build_groups(sd, i);
			if (ret)
				goto fail;
		}
	}

	list_for_each_entry(sd, batch_ipa_topology, siblings) {
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
	if (!batch_ipa_nr_topology_levels)
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
	struct ipanema_rq *rq;
	struct batch_ipa_process *pr;
	struct batch_ipa_sched_domain *sd = ipanema_core(cpu).sd;
	int i;

	ipanema_lock_core(cpu);
	pr = ipanema_state(cpu).curr;
	seq_printf(s, "CPU: %ld\n", cpu);

	seq_printf(s, "RUNNING (policy): %d\n",
		   pr ? pr->task->pid : -1);
	n = per_cpu(ipanema_current, cpu);
	seq_printf(s, "RUNNING (runtime): %d\n", n ? n->pid : -1);

	rq = &(ipanema_state(cpu).normal);
	seq_printf(s, "\nNORMAL: nr_tasks = %d, state = %s\n",
		   rq->nr_tasks, ipanema_state_to_str(rq->state));
	seq_printf(s, " pid  |         state         |    start    \n");
	seq_printf(s, "------+-----------------------+---------------\n");
	rbtree_postorder_for_each_entry_safe(pos, n, &rq->root,
					     ipanema.node_runqueue) {
		pr = policy_metadata(pos);
		seq_printf(s, " %4d | %21s | %lld\n",
			   pos->pid, ipanema_state_to_str(pr->state),
			   pr->start);
	}

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
	struct batch_ipa_sched_domain *sd;

	for (i = 0; i < batch_ipa_nr_topology_levels; i++) {
		seq_printf(s, "Level %d: ", i);
		list_for_each_entry(sd, batch_ipa_topology + i, siblings) {
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

int init_module(void)
{
	int res, cpu;
	struct proc_dir_entry *procdir = NULL;
	char procbuf[10];

	/* Initialize scheduler variables with non-const value (function call) */
	for_each_possible_cpu(cpu) {
		ipanema_core(cpu).id = cpu;
		/* allocation of ipanema rqs */
		init_ipanema_rq(&ipanema_state(cpu).normal, RBTREE, cpu,
				IPANEMA_READY, ipanema_batch_order_process);
	}

	/* build hierarchy with topology */
	build_hierarchy();

	/* Allocate & setup the ipanema_module */
	module = kzalloc(sizeof(struct ipanema_module), GFP_KERNEL);
	if (!module) {
		res = -ENOMEM;
		goto end;
	}
	strncpy(module->name, name, MAX_POLICY_NAME_LEN);
	module->routines = &ipanema_batch_routines;
	module->kmodule = THIS_MODULE;

	/* Register module to the runtime */
	res = ipanema_add_module(module);
	if (res)
		goto clean_module;

	/*
	 * Create /proc/batch/<cpu> files and /proc/batch/topology file
	 * If file creation fails, module insertion does not
	 */
	procdir = proc_mkdir(name, ipa_procdir);
	if (!procdir)
		pr_err("%s: /proc/%s creation failed\n", name, name);
	for_each_possible_cpu(cpu) {
		scnprintf(procbuf, 10, "%d", cpu);
		if (!proc_create(procbuf, 0444, procdir, &proc_fops))
			pr_err("%s: /proc/%s/%s creation failed\n",
			       name, name, procbuf);
	}
	if (!proc_create("topology", 0444, procdir, &proc_topo_fops))
		pr_err("%s: /proc/%s/topology creation failed\n",
		       name, name);

	return 0;

clean_module:
	kfree(module);
end:
	return res;
}

void cleanup_module(void)
{
	int res;

	remove_proc_subtree(name, ipa_procdir);

	res = ipanema_remove_module(module);
	if (res) {
		pr_err("Cleanup failed (%d)\n", res);
		return;
	}

	destroy_scheduling_domains();
	kfree(module);
}

MODULE_AUTHOR("Ipanema Compiler");
MODULE_DESCRIPTION("batch scheduling policy");
MODULE_LICENSE("GPL");
