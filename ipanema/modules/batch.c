#include <linux/delay.h>
#include <linux/ipanema.h>
#include <linux/ipanema_rbtree.h>
#include <linux/ktime.h>
#include <linux/lockdep.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/threads.h>

#define ipanema_assert(x)			\
  do {						\
    if (!(x)) panic("Error in " #x "\n");	\
  } while (0)
#define time_to_ticks(x) (ktime_to_ns(x) * HZ / 1000000000)
#define ticks_to_time(x) (ns_to_ktime(x * 1000000000 / HZ))

/* policy name */
static char *name = "batch";
static struct ipanema_module *module;

/* Helper macros */
#define get_policy_core(cpu)       (per_cpu(core, (cpu)))
#define get_policy_current(cpu)    (get_policy_core((cpu)).curr)
#define get_policy_rq(cpu, name)   (get_policy_core((cpu)).name)

/* Definition of a process */
struct process {
	/* Pointer to ipanema_rq containing process */
        struct ipanema_rq *rq;
	/* Pointer to the corresponding struct task_struct */
        struct task_struct *task;
	/* list_head for balancing */
	struct list_head list;

	u64 runtime;
	u64 last_sched;
};

/* Definition of a core */
struct core {
	/* Current core state */
        int state;
	/* ID of the core */
        int id;

	/* Running process (RUNNING) */
        struct process *curr;
	/* Processes in READY state */
        struct ipanema_rq ready;
};
DEFINE_PER_CPU(struct core, core);

/* cpumask of cores */
static cpumask_var_t active_cores;

/* Globals */
static u64 max_runtime;

/**
 * get_metric() - Return the metric used for process ordering
 * @policy: ipanema policy calling this function
 * @p: the process from which the metric is needed
 *
 * This function may become deprecated if we want to allow multiple runqueues
 * ordered with different metrics...
 *
 * Return: the metric of @p as an integer.
 */
static u64 get_metric(struct ipanema_policy *policy, struct task_struct *p)
{
	struct process *tgt = policy_metadata(p);

	return tgt->runtime;
}

/**
 * order_process() - Compare 2 processes
 * @policy: ipanema policy calling this function
 * @a: the first process to compare
 * @b: the second process to compare
 *
 * Compare two processes. May move from struct ipanema_module_routines to
 * struct ipanema_rq in order to allow runqueues with different ordering
 * criteria.
 *
 * Return: a positive value if a > b, a negative value if a < b, 0 if a == b.
 */
static int order_process(struct ipanema_policy *policy, struct task_struct *a,
			 struct task_struct *b)
{
	u64 m_a = get_metric(policy, a);
	u64 m_b = get_metric(policy, b);

	if (m_a < m_b)
		return -1;
	if (m_a > m_b)
		return 1;
	return 0;
}

/**
 * get_core_state() - Return the state of a core
 * @policy: ipanema policy calling this function
 * @e: core event representing the core exiting @policy
 */
static enum ipanema_core_state get_core_state(struct ipanema_policy *policy,
					      struct core_event *e)
{
	if (cpumask_test_cpu(e->target, active_cores))
		return IPANEMA_ACTIVE_CORE;
	return IPANEMA_IDLE_CORE;
}

static int find_idlest_core(struct ipanema_policy *policy)
{
	int dst = 0, cpu, nr_processes, min_processes = INT_MAX;

	for_each_cpu_and(cpu, &policy->allowed_cores, active_cores) {
		nr_processes = get_policy_rq(cpu, ready).nr_tasks;
		nr_processes += get_policy_current(cpu) ? 1 : 0;
		if (nr_processes < min_processes) {
			min_processes = nr_processes;
			dst = cpu;
		}
	}

	return dst;
}

/**
 * new_prepare() - Allocate a new process and choose the core to wake up on
 * @policy: ipanema policy calling this function
 * @e: process event representing the new process
 *
 * First function of the ipanema new() event, called when a process is created
 * (fork) or registers to @policy (sched_setattr/sched_setscheduler).
 * This should allocate the process structure, initialize it and return the id
 * of the core where the process should be enqueued.
 *
 * Locks held: process.
 * Allowed state change: none.
 *
 * Return: the id of the core where the new process should be placed. Returning
 *         -1 will place the thread on its current core.
 */
static int new_prepare(struct ipanema_policy *policy, struct process_event *e)
{
	struct process *tgt;
	struct task_struct *p = e->target;

	/* allocate process metadata and init internal structs */
	tgt = kzalloc(sizeof(struct process), GFP_ATOMIC);
	if (!tgt)
		BUG();
	policy_metadata(p) = tgt;
	tgt->task = p;
        tgt->rq = NULL;
	INIT_LIST_HEAD(&tgt->list);

	tgt->runtime = max_runtime;

        return find_idlest_core(policy);
}

/**
 * new_place() - Place a newly created process on its core.
 * @policy: ipanema policy calling this function
 * @e: process event representing the new process
 *
 * Second function of the new() event, called after a call to new_prepare(). The
 * chosen wake up core is set in the cpu field of the struct task_struct pointed
 * by @e.
 * This should only place the process on its destination runqueue and modify the
 * core structure if necessary.
 *
 * Locks held: process and core.
 * Allowed state change: IPANEMA_NOT_QUEUED -> IPANEMA_READY, local core
 */
static void new_place(struct ipanema_policy *policy, struct process_event *e)
{
	struct task_struct *p = e->target;
	struct process *tgt = policy_metadata(p);
	int dst = task_cpu(p);

	tgt->rq = &get_policy_rq(dst, ready);
	change_state(p, IPANEMA_READY, dst, tgt->rq);
}

/**
 * new_end() - Post processing for a newly created process.
 * @policy: ipanema policy calling this function
 * @e: process event representing the new process
 *
 * Third function of the new() event, called after a call to new_place().
 * Not implemented yet (never called).
 *
 * Locks held: ???
 * Allowed state change: none.
 */
static void new_end(struct ipanema_policy *policy, struct process_event *e)
{}

/**
 * terminate_event() - Dequeue and destroy a terminating process.
 * @policy: ipanema policy calling this function
 * @e: process event representing the terminating process
 *
 * Called when a process exits or unregisters from @policy.
 * This should remove the process from all the policy specific structures, move
 * it to an IPANEMA_TERMINATED state and free its memory.
 *
 * Locks held: process and core.
 * Allowed state change: IPANEMA_RUNNING -> IPANEMA_TERMINATED
 */
static void terminate_event(struct ipanema_policy *policy,
			    struct process_event *e)
{
	struct task_struct *p = e->target;
	struct process *tgt = policy_metadata(p);

	tgt->rq = NULL;
        change_state(p, IPANEMA_TERMINATED, task_cpu(p), tgt->rq);
        kfree(tgt);
}

/**
 * tick_event() - Called on each tick.
 * @policy: ipanema policy calling this function
 * @e: process event representing the currently running process
 *
 * Called when the tick interrupt happens with a process in @policy running.
 * This event is allowed to move the process of @e to an IPANEMA_READY_TICK
 * state.
 *
 * Locks held: process and core.
 * Allowed state change: IPANEMA_RUNNING -> IPANEMA_READY_TICK (local core)
 */
static void tick_event(struct ipanema_policy *policy, struct process_event *e)
{
}

static void update_runtime(struct process *p)
{
	p->runtime += local_clock() - p->last_sched;
	if (p->runtime > max_runtime)
		max_runtime = p->runtime;
}

/**
 * yield_event() - Called when the running process calls thie yield
 *                 syscall, or when preempted by a higher priority scheduling
 *                 class.
 * @policy: ipanema policy calling this function
 * @e: process event representing the currently running process
 *
 * This function should place the running thread in an IPANEMA_READY state on
 * the current core.
 *
 * Locks held: process and core.
 * Allowed state change: -> IPANEMA_READY (local core)
 */
static void yield_event(struct ipanema_policy *policy, struct process_event *e)
{
	struct task_struct *p = e->target;
	struct process *tgt = policy_metadata(p);

	/* enqueue on local cpu */
	tgt->rq = &get_policy_rq(task_cpu(p), ready);
	get_policy_current(task_cpu(p)) = NULL;
	change_state(p, IPANEMA_READY, task_cpu(p), tgt->rq);

	update_runtime(tgt);
}

/**
 * block_event() - Called when a process is not runnable anymore (ie. waiting on
 *                 a resource).
 * @policy: ipanema policy calling this function
 * @e: process event representing the currently running process
 *
 * This function should place the running thread in an IPANEMA_BLOCKED state on
 * the current core.
 *
 * Locks held: process and core.
 * Allowed state change: -> IPANEMA_BLOCKED (local core)
 */
static void block_event(struct ipanema_policy *policy, struct process_event *e)
{
	struct task_struct *p = e->target;
	struct process *tgt = policy_metadata(p);

	if (get_policy_current(task_cpu(p)) == tgt)
		get_policy_current(task_cpu(p)) = NULL;
	tgt->rq = NULL;
	change_state(p, IPANEMA_BLOCKED, task_cpu(p), NULL);

	update_runtime(tgt);
}

/**
 * unblock_prepare() - Choose the core where an unblocking process will wake up
 * @policy: ipanema policy calling this function
 * @e: process event representing the waking up process
 *
 * First function of the unblock() event, called when a process becomes runnable
 * again.
 * This should choose the CPU where the process will wake up.
 *
 * Locks held: process.
 * Allowed state change: none.
 *
 * Return: the id of the core where the process should be placed. Returning
 *         -1 will place the thread on its current core.
 */
static int unblock_prepare(struct ipanema_policy *policy,
			   struct process_event *e)
{
	return find_idlest_core(policy);
}

/**
 * unblock_place() - Place a waking up process on its core.
 * @policy: ipanema policy calling this function
 * @e: process event representing the waking up process
 *
 * Second function of the unblock() event, called after a call to
 * unblock_prepare(). The chosen wake up core is set in the cpu field of the
 * struct task_struct pointed by @e.
 * This should only place the process on its destination runqueue and modify the
 * core structure if necessary.
 *
 * Locks held: process and core.
 * Allowed state change: IPANEMA_BLOCKED -> IPANEMA_READY, local core
 */
static void unblock_place(struct ipanema_policy *policy,
			  struct process_event *e)
{
	struct task_struct *p = e->target;
	struct process *tgt = policy_metadata(p);
	int dst = task_cpu(p);

	tgt->rq = &get_policy_rq(dst, ready);
	change_state(p, IPANEMA_READY, dst, tgt->rq);
}

/**
 * unblock_end() - Post processing for an unblocking process.
 * @policy: ipanema policy calling this function
 * @e: process event representing the waking up process
 *
 * Third function of the unblock() event, called after a call to unblock_place()
 * Not implemented yet (never called).
 *
 * Locks held: ???
 * Allowed state change: none.
 */
static void unblock_end(struct ipanema_policy *policy, struct process_event *e)
{}

/**
 * schedule_event() - Returns the next process to schedule on the CPU
 * @policy: ipanema policy calling this function
 * @cpu: the id of the CPU looking for a new process to be scheduled
 *
 * At the end of this function, if a task is set as IPANEMA_RUNNING with 
 * change_state(), it will run, else the core will go idle.
 *
 * Locks held: process and core.
 * Allowed state change: IPANEMA_READY -> IPANEMA_RUNNING, local core
 */
static void schedule_event(struct ipanema_policy *policy, unsigned int cpu)
{
	struct task_struct *p;
	struct process *tgt;

	p = ipanema_first_task(&get_policy_rq(cpu, ready));
	if (!p)
		return;

	tgt = policy_metadata(p);
	if (tgt) {
		tgt->last_sched = local_clock();
		get_policy_current(cpu) = tgt;
		tgt->rq = NULL;
		change_state(p, IPANEMA_RUNNING, cpu, NULL);
	}
}

static int find_busiest_core(struct ipanema_policy *policy)
{
	int dst = 0, cpu, nr_processes, max_processes = 0;

	for_each_cpu_and(cpu, &policy->allowed_cores, active_cores) {
		nr_processes = get_policy_rq(cpu, ready).nr_tasks;
		if (nr_processes > max_processes) {
			max_processes = nr_processes;
			dst = cpu;
		}
	}

	return dst;
}

static unsigned int detach_tasks(struct core *c, int nr, struct list_head *list,
				 int next_cpu)
{
	struct task_struct *p = NULL;
	struct process *tgt;
	unsigned int nr_detached = 0;

	ipanema_lock_core(c->id);
	while (nr--) {
		p = ipanema_first_task(&c->ready);
		if (!p)
			break;
		if (ipanema_task_state(p) != IPANEMA_READY)
			break;

		tgt = policy_metadata(p);
		list_add_tail(&tgt->list, list);
		tgt->rq = NULL;
		change_state(p, IPANEMA_MIGRATING, next_cpu, NULL);
		nr_detached++;
	}
	ipanema_unlock_core(c->id);

	return nr_detached;
}

static unsigned int attach_tasks(struct core *c, struct list_head *list)
{
	struct task_struct *p = NULL;
	struct process *tgt;
	unsigned int nr_attached = 0;

	ipanema_lock_core(c->id);
	while (!list_empty(list)) {
		tgt = list_first_entry(list, struct process, list);
		p = ipanema_get_task_of(tgt);
		tgt->rq = &c->ready;
		change_state(p, IPANEMA_READY, c->id, tgt->rq);
		list_del_init(&tgt->list);
		nr_attached++;
	}
	ipanema_unlock_core(c->id);

	return nr_attached;
}

static void balance_cpus(struct ipanema_policy *policy, struct core *thief,
			 struct core *victim)
{
	unsigned int nr_tasks_victim, nr_tasks_thief;
	unsigned int nr_stolen;
	LIST_HEAD(stolen_tasks);
	unsigned long flags;

	/* Compute number of processes to steal */
	nr_tasks_victim = victim->ready.nr_tasks;
	nr_tasks_thief = thief->ready.nr_tasks;
	nr_stolen = (nr_tasks_victim - nr_tasks_thief) / 2;

	local_irq_save(flags);

	/*
	 * Lock the busiest core and steal enough tasks to balance cpu and
	 * busiest
	 */
	detach_tasks(victim, nr_stolen, &stolen_tasks, thief->id);

	/* 
	 * Lock cpu and add tasks to READY runqueue
	 */
	attach_tasks(thief, &stolen_tasks);
	
	local_irq_restore(flags);
}

/**
 * newly_idle() - Called when a CPU becomes idle (ie. a call to schedule
 *                returned NULL)
 * @policy: ipanema policy calling this function
 * @e: core event representing the core
 *
 * Locks held: core.
 */
static void newly_idle(struct ipanema_policy *policy, struct core_event *e)
{
	unsigned int local_cpu = e->target, busiest;

	/* Select the victim core */
	busiest = find_busiest_core(policy);
	if (local_cpu == busiest)
		return;

	balance_cpus(policy, &get_policy_core(local_cpu),
		     &get_policy_core(busiest));
}

/**
 * enter_idle() - Called when a CPU becomes idle (ie. a call to schedule
 *                returned NULL after calling newly_idle())
 * @policy: ipanema policy calling this function
 * @e: core event representing the core
 *
 * Locks held: core.
 */
static void enter_idle(struct ipanema_policy *policy, struct core_event *e)
{
	cpumask_clear_cpu(e->target, active_cores);
}

/**
 * exit_idle() - Called when a CPU becomes non-idle
 * @policy: ipanema policy calling this function
 * @e: core event representing the core
 *
 * Locks held: core.
 */
static void exit_idle(struct ipanema_policy *policy, struct core_event *e)
{
	cpumask_set_cpu(e->target, active_cores);
}

/**
 * core_entry() - Called when a core starts using this policy
 * @policy: ipanema policy calling this function
 * @e: core event representing the core entering @policy
 *
 * This function should place the entering core in an IPANEMA_ACTIVE_CORE state
 *
 * Locks held: core.
 */
static void core_entry(struct ipanema_policy *policy, struct core_event *e)
{
	int cpu = e->target;

	get_policy_core(cpu).state = IPANEMA_ACTIVE_CORE;
	cpumask_set_cpu(cpu, active_cores);
}

/**
 * core_exit() - Called when a core stops using this policy
 * @policy: ipanema policy calling this function
 * @e: core event representing the core exiting @policy
 *
 * This function should place the entering core in an IPANEMA_IDLE_CORE state
 *
 * Locks held: core.
 */
static void core_exit(struct ipanema_policy *policy, struct core_event *e)
{
	int cpu = e->target;

	cpumask_clear_cpu(cpu, active_cores);
	get_policy_core(cpu).state = IPANEMA_IDLE_CORE;
}

/**
 * balancing() - Balance the load between cores
 * @policy: ipanema policy calling this function
 * @e: core event representing the core doing load balancing
 *
 * Called at every tick for load balancing. When locking a core, you MUST
 * disable irqs !!!
 *
 * Locks held: none
 * Interrupts are not masked.
 * Allowed state change: IPANEMA_READY -> IPANEMA_READY, distant core
 */
static void balancing(struct ipanema_policy *policy, struct core_event *e)
{
	unsigned int local_cpu = e->target, busiest;

	/* Select the victim core */
	busiest = find_busiest_core(policy);
	if (local_cpu == busiest)
		return;

	balance_cpus(policy, &get_policy_core(local_cpu),
		     &get_policy_core(busiest));
}

static int init(struct ipanema_policy *policy)
{
	return 0;
}

static bool attach(struct ipanema_policy *policy, struct task_struct *p,
		   char *command)
{
        return true;
}

int free_metadata(struct ipanema_policy *policy)
{
	kfree(policy->data);
        return 0;
}

int can_be_default(struct ipanema_policy *policy)
{
	return 1;
}

struct ipanema_module_routines routines =
{
	.order_process    = order_process,
	.get_core_state   = get_core_state,
        .new_prepare      = new_prepare,
        .new_place        = new_place,
        .new_end          = new_end,
        .tick             = tick_event,
        .yield            = yield_event,
        .block            = block_event,
        .unblock_prepare  = unblock_prepare,
        .unblock_place    = unblock_place,
        .unblock_end      = unblock_end,
        .terminate        = terminate_event,
        .schedule         = schedule_event,
        .newly_idle       = newly_idle,
        .enter_idle       = enter_idle,
        .exit_idle        = exit_idle,
        .balancing_select = balancing,
        .core_entry       = core_entry,
	.core_exit        = core_exit,
        .init             = init,
        .free_metadata    = free_metadata,
        .can_be_default   = can_be_default,
        .attach           = attach
};

int init_module(void)
{
	int res = 0, cpu;

        /* Initialize per-core scheduler variables */
        for_each_possible_cpu(cpu) {
		get_policy_core(cpu).state = IPANEMA_IDLE_CORE;
        	get_policy_core(cpu).id = cpu;

		/* READY rq */
		get_policy_rq(cpu, ready).cpu = cpu;
                get_policy_rq(cpu, ready).nr_tasks = 0;
		get_policy_rq(cpu, ready).root.rb_node = NULL;
		get_policy_rq(cpu, ready).state = IPANEMA_READY;

		/* RUNNING task */
		get_policy_core(cpu).curr = NULL;
        }
        
        /* allocation of the active_cores cpumask, zero-initialised */
        if (!zalloc_cpumask_var(&active_cores, GFP_KERNEL)) {
        	res = -ENOMEM;
                goto clean_cpumask_var;
        }

	/* Allocation of the struct ipanema_module and init */
        module = kmalloc(sizeof(struct ipanema_module), GFP_KERNEL);
        if (!module) {
        	res = -ENOMEM;
                goto clean_cpumask_var;
        }

        module->name = name;
        module->routines = &routines;
	module->kmodule = THIS_MODULE;

	res = ipanema_add_module(module);
        if (res) {
        	switch (res) {
		case -ETOOMANYMODULES:
			pr_err("[IPANEMA] ERROR: too many loaded modules.\n");
			break;
		case -EINVAL:
			pr_err("[IPANEMA] ERROR: unable to load module. A module with the same name is already loaded.\n");
			break;
		default:
			pr_err("[IPANEMA] ERROR: couldn't load module.\n");  
                }
                goto clean_module;
        }

        return 0;
        
 clean_module:
        kfree(module);
 clean_cpumask_var:
        free_cpumask_var(active_cores);

        return res;
}

void cleanup_module(void)
{
	int res;

	res = ipanema_remove_module(module);
	if (!res)
		goto end;
	switch(res) {
	case -EMODULENOTFOUND:
		pr_err("[IPANEMA] ERROR: module not found... Shouldn't happen !\n");
		break;
	case -EMODULEINUSE:
		pr_err("[IPANEMA] ERROR: module in use! Remove all instances from /proc/ipanema_policies. Shouldn't happen\n");
		break;
	default:
		pr_err("[IPANEMA] ERROR: unknown error (%d)\n", res);
	}

end:
        kfree(module);
        free_cpumask_var(active_cores);
}

MODULE_AUTHOR("Redha Gouicem");
MODULE_DESCRIPTION("Ipanema batch scheduler");
MODULE_LICENSE("GPL");
