#include <linux/delay.h>
#include <linux/ipanema.h>
#include <linux/ipanema_rbtree.h>
#include <linux/ktime.h>
#include <linux/lockdep.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
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
static char *name = "ipanema_template";
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

	int id;
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
static cpumask_var_t idle_cores;


/**
 * ipanema_template_order_process() - Compare 2 processes
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
static int ipanema_template_order_process(struct ipanema_policy *policy,
					  struct task_struct *a,
					  struct task_struct *b)
{
	struct process *pa = policy_metadata(a);
	struct process *pb = policy_metadata(b);

	return pa->id - pb->id;
}

/**
 * ipanema_template_get_core_state() - Return the state of a core
 * @policy: ipanema policy calling this function
 * @e: core event representing the core
 *
 * Return: the state of the core (IPANEMA_CORE_ACTIVE, IPANEMA_CORE_INACTIVE).
 */
static enum ipanema_core_state
ipanema_template_get_core_state(struct ipanema_policy *policy,
				struct core_event *e)
{
	return ipanema_core(e->target).state;
}

/**
 * ipanema_template_new_prepare() - Allocate a new process and choose the core
 *                                  to wake up on
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
static int ipanema_template_new_prepare(struct ipanema_policy *policy,
					struct process_event *e)
{
	struct process *tgt;
	struct task_struct *p = e->target;
	int dst;

	/* allocate process metadata and init internal structs */
	tgt = kzalloc(sizeof(struct process), GFP_ATOMIC);
	if (!tgt)
		BUG();
	policy_metadata(p) = tgt;
	tgt->task = p;
        tgt->rq = NULL;
	INIT_LIST_HEAD(&tgt->list);

	/* Init policy specific fields */
	tgt->id = p->pid;

	/* Choose a destination core */
	dst = task_cpu(p);

        return dst;
}

/**
 * ipanema_template_new_place() - Place a newly created process on its core.
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
static void ipanema_template_new_place(struct ipanema_policy *policy,
				       struct process_event *e)
{
	struct task_struct *p = e->target;
	struct process *tgt = policy_metadata(p);
	int dst = task_cpu(p);

	tgt->rq = &get_policy_rq(dst, ready);
	change_state(p, IPANEMA_READY, dst, tgt->rq);
}

/**
 * ipanema_template_new_end() - Post processing for a newly created process.
 * @policy: ipanema policy calling this function
 * @e: process event representing the new process
 *
 * Third function of the new() event, called after a call to new_place().
 * Not implemented yet (never called).
 *
 * Locks held: ???
 * Allowed state change: none.
 */
static void ipanema_template_new_end(struct ipanema_policy *policy,
				     struct process_event *e)
{}

/**
 * ipanema_template_terminate() - Dequeue and destroy a terminating process.
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
static void ipanema_template_terminate(struct ipanema_policy *policy,
				       struct process_event *e)
{
	struct task_struct *p = e->target;
	struct process *tgt = policy_metadata(p);

	tgt->rq = NULL;
        change_state(p, IPANEMA_TERMINATED, task_cpu(p), tgt->rq);
        kfree(tgt);
}

/**
 * ipanema_template_tick() - Called on each tick.
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
static void ipanema_template_tick(struct ipanema_policy *policy,
				  struct process_event *e)
{
}

/**
 * ipanema_template_yield() - Called when the running process calls thie yield
 *                            syscall, or when preempted by a higher priority
 *                            scheduling class.
 * @policy: ipanema policy calling this function
 * @e: process event representing the currently running process
 *
 * This function should place the running thread in an IPANEMA_READY state on
 * the current core.
 *
 * Locks held: process and core.
 * Allowed state change: -> IPANEMA_READY (local core)
 */
static void ipanema_template_yield(struct ipanema_policy *policy,
				   struct process_event *e)
{
	struct task_struct *p = e->target;
	struct process *tgt = policy_metadata(p);

	tgt->rq = &get_policy_rq(task_cpu(p), ready);
	get_policy_current(task_cpu(p)) = NULL;
	change_state(p, IPANEMA_READY, task_cpu(p), tgt->rq);
}

/**
 * ipanema_template_block() - Called when a process is not runnable anymore
 *                            (ie. waiting on a resource).
 * @policy: ipanema policy calling this function
 * @e: process event representing the currently running process
 *
 * This function should place the running thread in an IPANEMA_BLOCKED state on
 * the current core.
 *
 * Locks held: process and core.
 * Allowed state change: -> IPANEMA_BLOCKED (local core)
 */
static void ipanema_template_block(struct ipanema_policy *policy,
				   struct process_event *e)
{
	struct task_struct *p = e->target;
	struct process *tgt = policy_metadata(p);

	if (get_policy_current(task_cpu(p)) == tgt)
		get_policy_current(task_cpu(p)) = NULL;
	tgt->rq = NULL;
	change_state(p, IPANEMA_BLOCKED, task_cpu(p), NULL);
}

/**
 * ipanema_template_unblock_prepare() - Choose the core where an unblocking
 *                                      process will wake up
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
static int ipanema_template_unblock_prepare(struct ipanema_policy *policy,
					    struct process_event *e)
{
	struct task_struct *p = e->target;

	return task_cpu(p);
}

/**
 * ipanema_template_unblock_place() - Place a waking up process on its core.
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
static void ipanema_template_unblock_place(struct ipanema_policy *policy,
					   struct process_event *e)
{
	struct task_struct *p = e->target;
	struct process *tgt = policy_metadata(p);
	int dst = task_cpu(p);

	tgt->rq = &get_policy_rq(dst, ready);
	change_state(p, IPANEMA_READY, dst, tgt->rq);
}

/**
 * ipanema_template_unblock_end() - Post processing for an unblocking process.
 * @policy: ipanema policy calling this function
 * @e: process event representing the waking up process
 *
 * Third function of the unblock() event, called after a call to unblock_place()
 * Not implemented yet (never called).
 *
 * Locks held: ???
 * Allowed state change: none.
 */
static void ipanema_template_unblock_end(struct ipanema_policy *policy,
					 struct process_event *e)
{}

/**
 * ipanema_template_schedule() - Returns the next process to schedule on the CPU
 * @policy: ipanema policy calling this function
 * @cpu: the id of the CPU looking for a new process to be scheduled
 *
 * At the end of this function, if a task is set as IPANEMA_RUNNING with 
 * change_state(), it will run, else the core will go idle.
 *
 * Locks held: process and core.
 * Allowed state change: IPANEMA_READY -> IPANEMA_RUNNING, local core
 */
static void ipanema_template_schedule(struct ipanema_policy *policy,
				      unsigned int cpu)
{
	struct task_struct *p;
	struct process *tgt;

	p = ipanema_first_task(&get_policy_rq(cpu, ready));
	if (!p)
		return;

	tgt = policy_metadata(p);
	if (tgt) {
		get_policy_current(cpu) = tgt;
		tgt->rq = NULL;
		change_state(p, IPANEMA_RUNNING, cpu, NULL);
	}
}

/**
 * ipanema_template_core_entry() - Called when a core starts using this policy
 * @policy: ipanema policy calling this function
 * @e: core event representing the core entering @policy
 *
 * This function should place the entering core in an IPANEMA_ACTIVE_CORE state
 *
 * Locks held: core.
 */
static void ipanema_template_core_entry(struct ipanema_policy *policy,
					struct core_event *e)
{
	int cpu = e->target;

	cpumask_clear_cpu(cpu, idle_cores);
	get_policy_core(cpu).state = IPANEMA_ACTIVE_CORE;
	cpumask_set_cpu(cpu, active_cores);
}

/**
 * ipanema_template_core_exit() - Called when a core stops using this policy
 * @policy: ipanema policy calling this function
 * @e: core event representing the core exiting @policy
 *
 * This function should place the entering core in an IPANEMA_IDLE_CORE state
 *
 * Locks held: core.
 */
static void ipanema_template_core_exit(struct ipanema_policy *policy,
				       struct core_event *e)
{
	int cpu = e->target;

	cpumask_clear_cpu(cpu, active_cores);
	get_policy_core(cpu).state = IPANEMA_IDLE_CORE;
	cpumask_set_cpu(cpu, idle_cores);
}

/**
 * ipanema_template_balancing() - Balance the load between cores
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
static void ipanema_template_balancing(struct ipanema_policy *policy,
				       struct core_event *e)
{
	unsigned int cpu = e->target;
	unsigned int victim, busiest = cpu;
	unsigned int nr_victim, nr_cpu;
	unsigned int nr_busiest = get_policy_rq(cpu, ready).nr_tasks;
	struct task_struct *p = NULL;
	struct process *tgt;
	LIST_HEAD(stolen_tasks);
	unsigned int nr_theft;
	unsigned long flags;

	/* Select the victim core */
	for_each_cpu(victim, active_cores) {
		nr_victim = get_policy_rq(victim, ready).nr_tasks;
		if (nr_victim > nr_busiest + 1) {
			busiest = victim;
			nr_busiest = nr_victim;
		}
	}
	if (cpu == busiest)
		return;

	/*
	 * Lock the busiest core and steal enough tasks to balance cpu and
	 * busiest
	 */
	local_irq_save(flags);
	ipanema_lock_core(busiest);

	nr_busiest = get_policy_rq(busiest, ready).nr_tasks;
	nr_cpu = get_policy_rq(cpu, ready).nr_tasks;
	nr_theft = (nr_busiest - nr_cpu) / 2;
	while (nr_theft--) {
		p = ipanema_first_task(&get_policy_rq(busiest, ready));
		if (!p)
			break;
		if (ipanema_task_state(p) != IPANEMA_READY)
			break;

		tgt = policy_metadata(p);
		list_add_tail(&tgt->list, &stolen_tasks);
		tgt = policy_metadata(p);
		tgt->rq = NULL;
		change_state(p, IPANEMA_MIGRATING, cpu, NULL);
	}
	ipanema_unlock_core(busiest);

	/* 
	 * Lock cpu and add tasks to READY runqueue
	 */
	nr_theft = 0;
	ipanema_lock_core(cpu);
	while (!list_empty(&stolen_tasks)) {
		tgt = list_first_entry(&stolen_tasks, struct process, list);
		p = ipanema_get_task_of(tgt);
		tgt->rq = &get_policy_rq(cpu, ready);
		change_state(p, IPANEMA_READY, cpu, tgt->rq);
		list_del_init(&tgt->list);
		nr_theft++;
	}
	ipanema_unlock_core(cpu);
	local_irq_restore(flags);

	if (nr_theft)
		IPA_EMERG_SAFE("Load-balance on cpu%d (%d tasks stolen) from cpu%d\n",
			       cpu, nr_theft, busiest);
}

static int ipanema_template_init(struct ipanema_policy *policy)
{
	return 0;
}

static bool ipanema_template_attach(struct ipanema_policy *policy,
				    struct task_struct *p, char *command)
{
        return true;
}

int ipanema_template_free_metadata(struct ipanema_policy *policy)
{
	kfree(policy->data);
        return 0;
}

int ipanema_template_can_be_default(struct ipanema_policy *policy)
{
	return 1;
}

struct ipanema_module_routines ipanema_template_routines =
{
	.order_process    = ipanema_template_order_process,
	.get_core_state   = ipanema_template_get_core_state,
        .new_prepare      = ipanema_template_new_prepare,
        .new_place        = ipanema_template_new_place,
        .new_end          = ipanema_template_new_end,
        .tick             = ipanema_template_tick,
        .yield            = ipanema_template_yield,
        .block            = ipanema_template_block,
        .unblock_prepare  = ipanema_template_unblock_prepare,
        .unblock_place    = ipanema_template_unblock_place,
        .unblock_end      = ipanema_template_unblock_end,
        .terminate        = ipanema_template_terminate,
        .schedule         = ipanema_template_schedule,
        .newly_idle       = NULL,
        .enter_idle       = NULL,
        .exit_idle        = NULL,
        .balancing_select = ipanema_template_balancing,
        .core_entry       = ipanema_template_core_entry,
	.core_exit        = ipanema_template_core_exit,
        .init             = ipanema_template_init,
        .free_metadata    = ipanema_template_free_metadata,
        .can_be_default   = ipanema_template_can_be_default,
        .attach           = ipanema_template_attach
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
        if (!zalloc_cpumask_var(&idle_cores, GFP_KERNEL)) {
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
        module->routines = &ipanema_template_routines;
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
        free_cpumask_var(idle_cores);

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
        free_cpumask_var(idle_cores);
}

MODULE_AUTHOR("Redha Gouicem");
MODULE_DESCRIPTION("Ipanema scheduler template");
MODULE_LICENSE("GPL");
