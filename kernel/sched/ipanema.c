// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) "ipanema: " fmt

#include "sched.h"
#include "ipanema.h"
#include "monitor.h"

#include <linux/lockdep.h>
#include <linux/cpufreq.h>
#include <linux/kgdb.h>
#include <uapi/linux/sched/types.h>
#include <linux/spinlock.h>
#include <linux/percpu-rwsem.h>
#include <linux/module.h>
#include <linux/kref.h>

LIST_HEAD(ipanema_policies);
s64 num_ipanema_policies;
s64 ipanema_policies_id;

rwlock_t ipanema_rwlock;

/* Current running task per type */
DEFINE_PER_CPU(struct task_struct *, ipanema_current);

struct task_struct *get_ipanema_current(int cpu)
{
	return per_cpu(ipanema_current, cpu);
}
EXPORT_SYMBOL(get_ipanema_current);

void ipanema_lock_core(unsigned int id)
{
	raw_spin_lock(&cpu_rq(id)->lock);
}
EXPORT_SYMBOL(ipanema_lock_core);

int ipanema_trylock_core(unsigned int id)
{
	return raw_spin_trylock(&cpu_rq(id)->lock);
}
EXPORT_SYMBOL(ipanema_trylock_core);

void ipanema_unlock_core(unsigned int id)
{
	raw_spin_unlock(&cpu_rq(id)->lock);
}
EXPORT_SYMBOL(ipanema_unlock_core);

static bool __ipanema_policy_exists_nolock(struct ipanema_policy *policy)
{
	struct ipanema_policy *p;
	bool ret = false;

	list_for_each_entry(p, &ipanema_policies, list) {
		if (!strcmp(p->name, policy->name)) {
			ret = true;
			break;
		}
	}

	return ret;
}

static bool ipanema_policy_exists(struct ipanema_policy *policy)
{
	bool ret;
	unsigned long flags;

	read_lock_irqsave(&ipanema_rwlock, flags);
	ret = __ipanema_policy_exists_nolock(policy);
	read_unlock_irqrestore(&ipanema_rwlock, flags);

	return ret;
}

int ipanema_add_policy(struct ipanema_policy *policy)
{
	unsigned long flags;
	int ret = 0;

	/* Check if policy exists */
	if (ipanema_policy_exists(policy))
		return -EINVAL;

	/* Check if given policy seems correctly setup */
	if (!policy->routines)
		return -EINVAL;

	/* Let's set this up */
	write_lock_irqsave(&ipanema_rwlock, flags);
	INIT_LIST_HEAD(&policy->list);
	write_unlock_irqrestore(&ipanema_rwlock, flags);

	/* Insert policy to activate it after checking existence again */
	write_lock_irqsave(&ipanema_rwlock, flags);
	if (__ipanema_policy_exists_nolock(policy)) {
		ret = -EINVAL;
		goto end;
	}
	ret = policy->routines->init(policy);
	if (ret)
		goto end;
	policy->id = ipanema_policies_id++;
	list_add_tail(&policy->list, &ipanema_policies);
end:
	write_unlock_irqrestore(&ipanema_rwlock, flags);

	return ret;
}
EXPORT_SYMBOL(ipanema_add_policy);

int ipanema_remove_policy(struct ipanema_policy *policy)
{
	unsigned long flags;
	int ret = 0;

	/* Fail if policy is not inserted */
	write_lock_irqsave(&ipanema_rwlock, flags);
	if (!__ipanema_policy_exists_nolock(policy)) {
		ret = -EINVAL;
		goto end;
	}

	list_del(&policy->list);

end:
	write_unlock_irqrestore(&ipanema_rwlock, flags);

	return ret;
}
EXPORT_SYMBOL(ipanema_remove_policy);

void ipanema_core_entry(struct ipanema_policy *policy, unsigned int core)
{
	struct core_event e = { .target = core };

	WARN(!policy->routines->core_entry,
	     "%s is NULL in policy %s\n", __func__, policy->name);

	policy->routines->core_entry(policy, &e);
}

void ipanema_core_exit(struct ipanema_policy *policy, unsigned int core)
{
	struct core_event e = { .target = core };

	WARN(!policy->routines->core_exit,
	     "%s is NULL in policy %s\n", __func__, policy->name);

	policy->routines->core_exit(policy, &e);
}

enum ipanema_core_state ipanema_get_core_state(struct ipanema_policy *policy,
					       unsigned int core)
{
	struct core_event e = { .target = core };

	WARN(!policy->routines->get_core_state,
	     "%s is NULL in policy %s\n", __func__, policy->name);

	return policy->routines->get_core_state(policy, &e);
}

int ipanema_new_prepare(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct ipanema_policy *policy;
	unsigned long flags;

	/*
	 * we acquire this lock to prevent the policy from being removed before
	 * incrementing the refcount
	 */
	read_lock_irqsave(&ipanema_rwlock, flags);
	policy = ipanema_task_policy(p);
	if (!policy || !try_module_get(policy->kmodule)) {
		read_unlock_irqrestore(&ipanema_rwlock, flags);
		return -1;
	}

	WARN(!policy->routines->new_prepare,
	     "%s is NULL in policy %s\n", __func__, policy->name);

	read_unlock_irqrestore(&ipanema_rwlock, flags);

	return policy->routines->new_prepare(policy, e);
}

void ipanema_new_place(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct ipanema_policy *policy;

	lockdep_assert_held(&task_rq(p)->lock);

	policy = ipanema_task_policy(p);

	WARN(!policy->routines->new_place,
	     "%s is NULL in policy %s\n", __func__, policy->name);

	policy->routines->new_place(policy, e);
}

void ipanema_new_end(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct ipanema_policy *policy;

	policy = ipanema_task_policy(p);

	WARN(!policy->routines->new_end,
	     "%s is NULL in policy %s\n", __func__, policy->name);

	policy->routines->new_end(policy, e);
}

void ipanema_tick(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct rq *rq = task_rq(p);
	struct ipanema_policy *policy;

	/*
	 * Make sure the rq lock is held, because we will need to call
	 * resched_curr() to schedule another thread.
	 */
	lockdep_assert_held(&rq->lock);

	policy = ipanema_task_policy(p);

	WARN(!policy->routines->tick,
	     "%s is NULL in policy %s\n", __func__, policy->name);

	policy->routines->tick(policy, e);
}

void ipanema_yield(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct rq *rq = task_rq(p);
	struct ipanema_policy *policy;

	/*
	 * Make sure the rq lock is held, because we will need to call
	 * resched_curr() to schedule another thread.
	 */
	lockdep_assert_held(&rq->lock);

	policy = ipanema_task_policy(p);

	WARN(!policy->routines->yield,
	     "%s is NULL in policy %s\n", __func__, policy->name);

	policy->routines->yield(policy, e);
}

void ipanema_block(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct rq *rq = task_rq(p);
	struct ipanema_policy *policy;

	/*
	 * Make sure the rq lock is held, because we will need to call
	 * resched_curr() to schedule another thread.
	 */
	lockdep_assert_held(&rq->lock);

	policy = ipanema_task_policy(p);

	WARN(!policy->routines->block,
	     "%s is NULL in policy %s\n", __func__, policy->name);

	policy->routines->block(policy, e);
}

int ipanema_unblock_prepare(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct ipanema_policy *policy;

	lockdep_assert_held(&p->pi_lock);

	policy = ipanema_task_policy(p);

	WARN(!policy->routines->unblock_prepare,
	     "%s is NULL in policy %s\n", __func__, policy->name);

	return policy->routines->unblock_prepare(policy, e);
}

void ipanema_unblock_place(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct ipanema_policy *policy;

	lockdep_assert_held(&task_rq(p)->lock);

	policy = ipanema_task_policy(p);

	WARN(!policy->routines->unblock_place,
	     "%s is NULL in policy %s\n", __func__, policy->name);

	policy->routines->unblock_place(policy, e);
}

void ipanema_unblock_end(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct ipanema_policy *policy;

	lockdep_assert_held(&p->pi_lock);

	policy = ipanema_task_policy(p);

	WARN(!policy->routines->unblock_end,
	     "%s is NULL in policy %s\n", __func__, policy->name);

	policy->routines->unblock_end(policy, e);
}

void ipanema_terminate(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct rq *rq = task_rq(p);
	struct ipanema_policy *policy;

	lockdep_assert_held(&rq->lock);

	policy = ipanema_task_policy(p);

	WARN(!policy->routines->terminate,
	     "%s is NULL in policy %s\n", __func__, policy->name);

	policy->routines->terminate(policy, e);

	ipanema_task_policy(p) = NULL;
	module_put(policy->kmodule);

	/* pr_info("%s: module_put(): policy=%lld module->refcnt=%d\n", */
	/* 	__func__, policy->id, module_refcount(policy->kmodule)); */
}

void ipanema_schedule(struct ipanema_policy *policy, unsigned int core)
{
	struct rq *rq = cpu_rq(core);

	/* IRQs are apparently disabled. */
	WARN_ON(!irqs_disabled());

	/*
	 * We *must* hold the rq lock here, otherwise we can make a ready task
	 * running while another thread is stealing it.
	 */
	lockdep_assert_held(&rq->lock);

	WARN(!policy->routines->schedule,
	     "%s is NULL in policy %s\n", __func__, policy->name);

	policy->routines->schedule(policy, core);
}

void ipanema_newly_idle(struct ipanema_policy *policy, unsigned int core,
			struct rq_flags *rf)
{
	struct core_event e = { .target = core };
	struct rq *rq = cpu_rq(core);

	WARN(!policy->routines->newly_idle,
	     "%s is NULL in policy %s\n", __func__, policy->name);

	/*
	 * When newly_idle() is called by schedule(), the rq->lock is
	 * held. However, the handler may want to lock multiple rq->lock
	 * (idle balancing for example). To allow this, we unpin and
	 * unlock rq->lock before. We will put everything back to normal
	 * upon returning from the handler.
	 */
	rq_unpin_lock(rq, rf);
	raw_spin_unlock(&rq->lock);

	policy->routines->newly_idle(policy, &e);

	raw_spin_lock(&rq->lock);
	rq_repin_lock(rq, rf);
}

void ipanema_enter_idle(struct ipanema_policy *policy, unsigned int core)
{
	struct core_event e = { .target = core };

	WARN(!policy->routines->enter_idle,
	     "%s is NULL in policy %s\n", __func__, policy->name);

	policy->routines->enter_idle(policy, &e);
}

void ipanema_exit_idle(struct ipanema_policy *policy, unsigned int core)
{
	struct core_event e = { .target = core };

	WARN(!policy->routines->exit_idle,
	     "%s is NULL in policy %s\n", __func__, policy->name);

	policy->routines->exit_idle(policy, &e);
}

void ipanema_balancing_select(void)
{
	unsigned int core = smp_processor_id();
	struct ipanema_policy *policy;
	struct core_event e = { .target = core };
	unsigned long flags;

	read_lock_irqsave(&ipanema_rwlock, flags);
	list_for_each_entry(policy, &ipanema_policies, list) {
		if (policy->routines->balancing_select)
			policy->routines->balancing_select(policy, &e);
	}
	read_unlock_irqrestore(&ipanema_rwlock, flags);
}

void ipanema_init(void)
{
}

struct task_struct *ipanema_get_task_of(void *proc)
{
	struct sched_ipanema_entity *ipanema;

	ipanema = container_of(proc, struct sched_ipanema_entity,
			       policy_metadata);
	return container_of(ipanema, struct task_struct, ipanema);
}
EXPORT_SYMBOL(ipanema_get_task_of);

bool __checkparam_ipanema(const struct sched_attr *attr,
			  struct ipanema_policy *policy)
{
	if (policy->routines->checkparam_attr)
		return policy->routines->checkparam_attr(attr);
	return true;
}

void __setparam_ipanema(struct task_struct *p, const struct sched_attr *attr)
{
	struct ipanema_policy *policy = ipanema_task_policy(p);

	if (policy->routines->setparam_attr)
		policy->routines->setparam_attr(p, attr);
}

void __getparam_ipanema(struct task_struct *p, struct sched_attr *attr)
{
	struct ipanema_policy *policy = ipanema_task_policy(p);

	if (policy->routines->getparam_attr)
		policy->routines->getparam_attr(p, attr);
}

bool ipanema_attr_changed(struct task_struct *p, const struct sched_attr *attr)
{
	struct ipanema_policy *policy = ipanema_task_policy(p);

	if (policy->routines->attr_changed)
		return policy->routines->attr_changed(p, attr);
	return false;
}

/*
 * Check the validity of an ipanema transition
 */
static void check_ipanema_transition(struct task_struct *p,
				     enum ipanema_state next_state,
				     unsigned int next_cpu)
{
	enum ipanema_state prev_state = p->ipanema.state;
	unsigned int prev_cpu = p->cpu;

	switch (prev_state) {
	case IPANEMA_NOT_QUEUED:
	case IPANEMA_BLOCKED:
		if (next_state != IPANEMA_READY)
			goto wrong_transition;
		goto no_cpu_check;
	case IPANEMA_READY:
		if (next_state == IPANEMA_MIGRATING)
			goto no_cpu_check;
		if (next_state != IPANEMA_RUNNING)
			goto wrong_transition;
		break;
	case IPANEMA_RUNNING:
		if (next_state == IPANEMA_NOT_QUEUED ||
		    next_state == IPANEMA_MIGRATING)
			goto wrong_transition;
		break;
	case IPANEMA_READY_TICK:
		if (next_state != IPANEMA_READY)
			goto wrong_transition;
		break;
	case IPANEMA_MIGRATING:
		if (next_state != IPANEMA_READY)
			goto wrong_transition;
		break;
	case IPANEMA_TERMINATED:
		goto wrong_transition;
	default:
		goto wrong_transition;
	}

	if (prev_cpu != next_cpu)
		goto wrong_transition;

no_cpu_check:
	return;

wrong_transition:
	pr_warn("[WARN] %s: [pid=%d] Incorrect transition %s[%d] -> %s[%d]\n",
		__func__, p->pid,
		ipanema_state_to_str(prev_state), prev_cpu,
		ipanema_state_to_str(next_state), next_cpu);

#ifdef CONFIG_IPANEMA_PANIC_ON_BAD_TRANSITION
	BUG();
#endif
}

/*
 * Move task p from its current runqueue to the runqueue next_rq with
 * state = next_state
 */
static void change_rq(struct task_struct *p, enum ipanema_state next_state,
		      struct ipanema_rq *next_rq)
{
	struct ipanema_rq *prev_rq = NULL;
	unsigned int prev_cpu, next_cpu;
	enum ipanema_state prev_state;

	prev_rq = ipanema_task_rq(p);
	prev_cpu = task_cpu(p);
	prev_state = ipanema_task_state(p);

	if (prev_rq) {
		lockdep_assert_held(&task_rq(p)->lock);
		p = ipanema_remove_task(prev_rq, p);
		prev_rq->nr_tasks--;
	}

	ipanema_task_rq(p) = next_rq;
	ipanema_task_state(p) = next_state;

	if (next_rq) {
		next_cpu = next_rq->cpu;
		next_state = next_rq->state;
		lockdep_assert_held(&cpu_rq(next_cpu)->lock);
		if (ipanema_add_task(next_rq, p))
			pr_err("[ERR] %s(pid=%d, cpu=%u) failed. Gonna crash soon...\n",
			       __func__, p->pid, next_cpu);
		next_rq->nr_tasks++;
	}
}

/*
 * Main function handling state change of an ipanema task
 */
void change_state(struct task_struct *p, enum ipanema_state next_state,
		  unsigned int next_cpu, struct ipanema_rq *next_rq)
{
	unsigned int prev_cpu;
	enum ipanema_state prev_state;
	struct ipanema_rq *prev_rq = NULL;

	/* Safety checks */
	if (!p) {
		pr_err("[ERR] %s: Called with a null process! Exiting...\n",
		       __func__);
		return;
	}

	/* Get current task fields */
	prev_cpu = task_cpu(p);
	prev_state = ipanema_task_state(p);
	prev_rq = ipanema_task_rq(p);

	/*
	 * Safety checks on parameters, if badly set, use the process'
	 * current values
	 */
	if (next_cpu < 0)
		next_cpu = prev_cpu;
	if (next_state < 0)
		next_state = prev_state;
	if (next_state == IPANEMA_RUNNING ||
	    next_state == IPANEMA_MIGRATING ||
	    next_state == IPANEMA_TERMINATED)
		next_rq = NULL;
	if (next_rq) {
		if (next_cpu != next_rq->cpu ||
		    (next_state != next_rq->state &&
		     next_state != IPANEMA_READY_TICK &&
		     next_rq->state != IPANEMA_READY)) {
			pr_warn("[WARN] %s: Discrepancy in parameters: next_state = %s; next_cpu = %d, next_rq = [cpu=%d, state=%s]. Using next_rq values\n",
				__func__,
				ipanema_state_to_str(next_state),
				next_cpu, next_rq->cpu,
				ipanema_state_to_str(next_rq->state));

#ifdef CONFIG_IPANEMA_PANIC_ON_BAD_TRANSITION
			BUG();
#endif
			next_cpu = next_rq->cpu;
			next_state = next_rq->state;
		}
	}

	/* If no change, return */
	if (prev_cpu == next_cpu &&
	    prev_state == next_state &&
	    prev_rq == next_rq)
		return;

	if (unlikely(ipanema_fsm_log))
		pr_info("[pid=%d] %s[%d] -> %s[%d]\n",
			p->pid, ipanema_state_to_str(prev_state), prev_cpu,
			ipanema_state_to_str(next_state), next_cpu);

	/* Check transition validity if necessary */
	if (unlikely(ipanema_fsm_check))
		check_ipanema_transition(p, next_state, next_cpu);

	/* Do the actual rq change */
	change_rq(p, next_state, next_rq);


	/* Now, let's do transition specific handling */

	/* RUNNING -> x */
	if (prev_state == IPANEMA_RUNNING)
		per_cpu(ipanema_current, prev_cpu) = NULL;

	/* x -> RUNNING */
	if (next_state == IPANEMA_RUNNING) {
		if (per_cpu(ipanema_current, next_cpu))
			pr_warn("[WARN] putting a task in RUNNING but there is already another task! We preempt it to avoid potential bugs. Should not happen !!!\n");

		per_cpu(ipanema_current, next_cpu) = p;
	}

	/* MIGRATING -> READY */
	if (prev_state == IPANEMA_MIGRATING) {
		activate_task(cpu_rq(next_cpu), p, 0);
		p->on_rq = TASK_ON_RQ_QUEUED;
	}

	/* READY -> MIGRATING */
	if (next_state == IPANEMA_MIGRATING) {
		p->on_rq = TASK_ON_RQ_MIGRATING;
		deactivate_task(cpu_rq(prev_cpu), p, 0);
		set_task_cpu(p, next_cpu);
	}

	/* RUNNING -> READY_TICK */
	if (next_state == IPANEMA_READY_TICK)
		resched_curr(cpu_rq(next_cpu));

	/*
	 * Let's check that we have someone RUNNING if not, trigger a resched
	 */
	if (!per_cpu(ipanema_current, prev_cpu) &&
	    cpu_rq(prev_cpu)->nr_running &&
	    prev_cpu == next_cpu)
		resched_curr(cpu_rq(prev_cpu));

	if (task_cpu(p) != next_cpu ||
	    (next_rq && task_cpu(p) != next_rq->cpu)) {
		pr_warn("[WARN] Discrepency with task %d (task_cpu()=%d, next_cpu=%d, next_rq->cpu=%d)\n",
			p->pid, task_cpu(p), next_cpu,
			next_rq ? next_rq->cpu : -1);
		dump_stack();
	}
}
EXPORT_SYMBOL(change_state);

/*
 * Return the number of tasks on the cpu (not only in SCHED_IPANEMA !!!!)
 */
int count(enum ipanema_state state, unsigned int cpu)
{
	if (state == IPANEMA_READY || state == IPANEMA_READY_TICK)
		return cpu_rq(cpu)->nr_running;
	return -1;
}
EXPORT_SYMBOL(count);

static void enqueue_task_ipanema(struct rq *rq,
				 struct task_struct *p,
				 int flags)
{
	struct process_event e = { .target = p, .cpu = smp_processor_id() };
	enum ipanema_core_state cstate;
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [pid=%d, rq=%d]\n",
			__func__, p->pid, rq->cpu);

	/* task has no ipanema policy, just increment rq->nr_running */
	if (!ipanema_task_policy(p)) {
		pr_warn("[WARN] %s: called on a task with no ipanema policy set.\n",
			__func__);
		goto end;
	}

	/*
	 * We are changing attributes of a thread. We don't need to do anything,
	 * just update rq->nr_running/count_ready
	 */
	if (flags & ATTR_CHANGE)
		goto end;

	/*
	 * We are in the middle of a migration. We don't need to do anything,
	 * just update rq->nr_running/count_ready
	 */
	if (task_on_rq_migrating(p) && !(flags & OUSTED))
		goto end;

	/* The thread is switching to SCHED_IPANEMA class,
	 * we must:
	 * - initialize its sched_ipanema_entity
	 * - call its policy's new_prepare() routine to
	 *   initialize the per-policy metadata, but we ignore
	 *   the return value to avoid inconsistency, since it's
	 *   too late to choose a runqueue.
	 */
	if (flags & SWITCHING_CLASS) {
		ipanema_task_state(p) = IPANEMA_NOT_QUEUED;
		ipanema_task_rq(p) = NULL;

		ipanema_new_prepare(&e);
	}

	/*
	 * p->cpu has been set up by ipanema_new_prepare(), we now need to do
	 * the actual enqueueing by calling ipanema_new_place(), thus going
	 * from IPANEMA_NOT_QUEUED to IPANEMA_READY.
	 */
	if (ipanema_task_state(p) == IPANEMA_NOT_QUEUED) {
		/*
		 * If p->cpus_allowed < 2, select_task_rq() is not called on
		 * fork(), and the new_prepare() handler is never called.
		 * We must therefore check if this has been done, and do it
		 * if necessary.
		 * FIXED: in core.c, we always call select_task_rq if in the
		 *        ipanema sched class
		 */
		if (!policy_metadata(p))
			ipanema_new_prepare(&e);

		/*
		 * If new_prepare() chose an IDLE cpu, we must call the
		 * exit_idle() handler to wake it up on the policy
		 */
		cstate = ipanema_get_core_state(ipanema_task_policy(p),
						rq->cpu);
		if (cstate == IPANEMA_IDLE_CORE)
			ipanema_exit_idle(ipanema_task_policy(p),
					  rq->cpu);
		ipanema_new_place(&e);
		goto end;
	}

	/*
	 * To unblock a task, a thread calls wake_up(), which calls
	 * try_to_wake_up(), which sets the task's state to TASK_WAKING and
	 * then calls enqueue_task(). Therefore, we're only in the presence of
	 * an true unblock() if the state is TASK_WAKING.
	 *
	 * We also check for the OUSTED flag and TASK_ON_RQ_MIGRATING to
	 * simulate a block/unblock pair when a thread is kicked out from its
	 * cpu. It will be placed on a cpu handled by the policy and authorized
	 * for this thread.
	 */
	if (p->state == TASK_WAKING ||
	    (flags & OUSTED && task_on_rq_migrating(p))) {
		/*
		 * If unblock_prepare() chose an IDLE cpu, we must call the
		 * exit_idle() handler to wake it up on the policy
		 */
		cstate = ipanema_get_core_state(ipanema_task_policy(p),
						rq->cpu);
		if (cstate == IPANEMA_IDLE_CORE)
			ipanema_exit_idle(ipanema_task_policy(p),
					  rq->cpu);
		ipanema_unblock_place(&e);
		goto end;
	}

	/*
	 * If flags is ENQUEUE_RESTORE, it means we are in a quick
	 * dequeue/enqueue, just update nr_running/count_ready
	 */
	if (flags & ENQUEUE_RESTORE)
		goto end;

	pr_warn("[WARN] Uncaught enqueue, CONTEXT: p=[pid=%d, cpu=%d, state=%ld, on_cpu=%d, on_rq=%d, ipanema=[current_state=%s]]; rq[%d]=%p; flags=%d\n",
		       p->pid, p->cpu, p->state, p->on_cpu, p->on_rq,
		       ipanema_state_to_str(ipanema_task_state(p)),
		       rq->cpu, rq, flags);

end:
	add_nr_running(rq, 1);
	rq->nr_ipanema_running++;

	sched_monitor_ipanema_stop(ENQUEUE, start);
}

static void update_curr_ipanema(struct rq *rq)
{
	struct task_struct *curr = rq->curr;
	u64 delta_exec;

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [rq=%d]\n", __func__, rq->cpu);

	/*
	 * We now update statistics. Needed to get %CPU working for Ipanema
	 * processes in top, for instance.
	 */
	delta_exec = rq_clock_task(rq) - curr->se.exec_start;
	if (unlikely((s64)delta_exec <= 0))
		return;

	schedstat_set(curr->se.statistics.exec_max,
		      max(curr->se.statistics.exec_max, delta_exec));

	curr->se.sum_exec_runtime += delta_exec;
	account_group_exec_runtime(curr, delta_exec);

	curr->se.exec_start = rq_clock_task(rq);
	cpuacct_charge(curr, delta_exec);
}

static void dequeue_task_ipanema(struct rq *rq,
				 struct task_struct *p,
				 int flags)
{
	struct process_event e = { .target = p, .cpu = smp_processor_id() };
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [pid=%d, rq=%d]\n",
			__func__, p->pid, rq->cpu);

	update_curr_ipanema(rq);

	/* task has no ipanema policy, just decrement rq->nr_running */
	if (!ipanema_task_policy(p)) {
		pr_warn("[WARN] %s: called on a task with no ipanema policy set.\n",
			__func__);
		goto end;
	}

	/*
	 * We are changing attributes of a thread. We don't need to do anything,
	 * just update rq->nr_running/count_ready
	 */
	if (flags & ATTR_CHANGE)
		goto end;

	/*
	 * The task is being dequeued because it's switching to another
	 * scheduling class. In this case too, we should call terminate. We must
	 * also set the ipanema policy to NULL to avoid problems if the task
	 * switches back to SCHED_IPANEMA class.
	 */
	if (flags & SWITCHING_CLASS) {
		ipanema_terminate(&e);
		goto end;
	}

	/*
	 * We are in the middle of a migration. We don't need to do anything,
	 * just update rq->nr_running/count_ready
	 */
	if (task_on_rq_migrating(p) && !(flags & OUSTED))
		goto end;

	/*
	 * The thread doesn't even exist yet according to Ipanema. All we do
	 * is update nr_running/count_ready (at end)
	 */
	if (ipanema_task_state(p) == IPANEMA_NOT_QUEUED)
		goto end;

	/*
	 * In order to block, one sets the task to either TASK_INTERRUPTIBLE
	 * or TASK_UNINTERRUPTIBLE, and then calls schedule(), which calls
	 * deactivate_task(), which calls dequeue_task(). We are in this
	 * scenario: we're witnessing a true block().
	 *
	 * We also add TASK_STOPPED to make sure the task is removed from the
	 * runqueue when we receive a SIGSTOP signal.
	 *
	 * We add TASK_KILLABLE to make sure that all received signals are
	 * handled correctly.
	 *
	 * We also check for the OUSTED flag and TASK_ON_RQ_MIGRATING to
	 * simulate a block/unblock pair when a thread is kicked out from its
	 * cpu. It will be placed on a cpu handled by the policy and authorized
	 * for this thread.
	 */
	if (p->state & TASK_INTERRUPTIBLE ||
	    p->state & TASK_UNINTERRUPTIBLE ||
	    p->state & TASK_STOPPED ||
	    p->state & TASK_KILLABLE ||
	    (flags & OUSTED && task_on_rq_migrating(p))) {
		ipanema_block(&e);
		goto end;
	}

	/*
	 * The task is being dequeued because it's dead. This is where we should
	 * call terminate(), not in task_dead_ipanema(), because
	 * task_dead_ipanema() is called after the task is dequeued and
	 * schedule() is called. Consequently, if we don't remove the task from
	 * the rbtree now, it will be scheduled again while it is not queued,
	 * which will lead to a crash.
	 */
	if (p->flags & PF_EXITPIDONE) {
		ipanema_terminate(&e);
		goto end;
	}

	/*
	 * If flags is DEQUEUE_SAVE, it means we are in a quick
	 * dequeue/enqueue, just update nr_running/count_ready
	 */
	if (flags & DEQUEUE_SAVE)
		goto end;

	pr_warn("[WARN] Uncaught dequeue, CONTEXT: p=[pid=%d, cpu=%d, state=%ld, on_cpu=%d, on_rq=%d, ipanema=[current_state=%s]]; rq[%d]=%p; flags=%d\n",
		p->pid, p->cpu, p->state, p->on_cpu, p->on_rq,
		ipanema_state_to_str(ipanema_task_state(p)),
		rq->cpu, rq, flags);

end:
	sub_nr_running(rq, 1);
	rq->nr_ipanema_running--;

	sched_monitor_ipanema_stop(DEQUEUE, start);
}

static void yield_task_ipanema(struct rq *rq)
{
	struct process_event e = { .target = rq->curr,
				   .cpu = smp_processor_id() };
	struct task_struct *p = rq->curr;
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [rq=%d]\n",
			__func__, rq->cpu);

	/*
	 * The process called yield(). Switch its state to IPANEMA_READY,
	 * schedule() is going to be called very soon.
	 */
	ipanema_yield(&e);
	p->ipanema.just_yielded = 1;

	sched_monitor_ipanema_stop(YIELD, start);
}

static bool yield_to_task_ipanema(struct rq *rq,
				  struct task_struct *p,
				  bool preempt)
{
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [pid=%d, rq=%d]\n",
			__func__, p->pid, rq->cpu);

	sched_monitor_ipanema_stop(YIELD_TO, start);

	return 0;
}

static void check_preempt_wakeup(struct rq *rq,
				 struct task_struct *p,
				 int wake_flags)
{
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [pid=%d, rq=%d]\n",
			__func__, p->pid, rq->cpu);

	sched_monitor_ipanema_stop(CHECK_PREEMPT_CURR, start);
}

static struct task_struct *pick_next_task_ipanema(struct rq *rq,
						  struct task_struct *prev,
						  struct rq_flags *rf)
{
	struct task_struct *result = NULL;
	struct ipanema_policy *policy = NULL;
	enum ipanema_core_state cstate;
	unsigned long flags;
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
	u64 start_lb = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [pid=%d, rq=%d]\n",
			__func__, prev->pid, rq->cpu);

	/*
	 * If ipanema_current is not NULL, it means that pick_next_task() is
	 * called and neither yield(), block() or terminate() was called. This
	 * can happen in __schedule(), if the task is not RUNNABLE
	 * (prev->state != 0) and has a pending signal. The task is therefore
	 * not dequeued in order to handle the pending signals, and still in
	 * ipanema_current. For now, we keep the same task as ipanema_current,
	 * it will be removed when signals are handled (through a call to
	 * dequeue and the correct ipanema event handler).
	 * This might also happen if __schedule() is called with preempt set to
	 * true. This can happen with some syscalls. In this case, we want to
	 * force a preemption, so we're going to simulate a yield().
	 */
	if (per_cpu(ipanema_current, rq->cpu)) {
		if (prev->state != TASK_RUNNING) {
			/* current has signals pending, leave it running */
			result = per_cpu(ipanema_current, rq->cpu);
			goto end;
		} else {
			/* yield to force preemption */
			struct process_event e = { .target = current,
						   .cpu = smp_processor_id() };

			ipanema_yield(&e);
		}
	}
	read_lock_irqsave(&ipanema_rwlock, flags);
	list_for_each_entry(policy, &ipanema_policies, list) {
		ipanema_schedule(policy, rq->cpu);
		result = per_cpu(ipanema_current, rq->cpu);
		/* if a task is found, schedule it */
		if (result)
			break;
		/*
		 * Policy has no ready task on this cpu. If cpu is
		 * already idle, try next policy. Else, call the
		 * newly_idle() event and retry once.
		 */
		cstate = ipanema_get_core_state(policy, rq->cpu);
		if (cstate == IPANEMA_IDLE_CORE)
			continue;

		sched_monitor_ipanema_start(start_lb);

		ipanema_newly_idle(policy, rq->cpu, rf);

		sched_monitor_ipanema_stop(LB_IDLE, start_lb);

		ipanema_schedule(policy, rq->cpu);
		result = per_cpu(ipanema_current, rq->cpu);
		/* if a task is found, schedule it */
		if (result)
			break;
		/* else call enter_idle() handler for this policy/cpu */
		ipanema_enter_idle(policy, rq->cpu);
	}
	read_unlock_irqrestore(&ipanema_rwlock, flags);

	if (!result)
		goto end;

	if (result != prev) {
		put_prev_task(rq, prev);
		result->se.exec_start = rq_clock_task(rq);
	}

	if (ipanema_task_state(result) != IPANEMA_RUNNING) {
		pr_warn("[WARN] %s: picked task is not IPANEMA_RUNNING (%s instead). Switching to IPANEMA_RUNNING to prevent issues, but we shouldn't be in this situation!\n",
			__func__,
			ipanema_state_to_str(ipanema_task_state(current)));
		ipanema_task_state(result) = IPANEMA_RUNNING;
	}

end:
	sched_monitor_ipanema_stop(PICK_NEXT, start);

	return result;
}

static void put_prev_task_ipanema(struct rq *rq,
				  struct task_struct *prev)
{
	enum ipanema_state state;
	struct process_event e = { .target = prev, .cpu = smp_processor_id() };
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [pid=%d, rq=%d]\n",
			__func__, prev->pid, rq->cpu);

	/* Safety checks. Use BUG() to fail gracelessly. */
	if (!prev || prev->sched_class != &ipanema_sched_class) {
		pr_err("[ERR] %s: At least one precondition not verified [%d %d]\n",
			       __func__, !prev,
			       prev->sched_class != &ipanema_sched_class);
		BUG();
	}

	/*
	 * If no policy is set, we are moving out from an ipanema policy,
	 * dequeue_task_ipanema() already called terminate(). We just remove
	 * prev from ipanema_current if necessary. We don't call resched_curr()
	 * because the task will keep the cpu in its new sched_class.
	 */
	if (!prev->ipanema.policy) {
		if (per_cpu(ipanema_current, prev->cpu) == prev)
			per_cpu(ipanema_current, prev->cpu) = NULL;
		sched_monitor_ipanema_stop(PUT_PREV, start);
		return;
	}

	update_curr_ipanema(rq);

	state = ipanema_task_state(prev);
	switch (state) {
	case IPANEMA_RUNNING:
		/*
		 * Case 1: the thread is being preempted. If it's just one of
		 * these quick put_prev_task()/set_curr_task() things. Do
		 * nothing. Else, call a yield event (we should have a preempt
		 * event, but since we do not, we just call yield.
		 *
		 * Note: nopreempt is a flag we added.
		 */
		if (!prev->ipanema.nopreempt)
			ipanema_yield(&e);
		break;
	case IPANEMA_READY_TICK:
		/*
		 * Case 2: preemption caused by a transition to READY in tick().
		 * We're just before the preemption of a thread that has just
		 * been moved to the READY queue from tick(). The thread is
		 * still running from the runtime's point of view, but we
		 * already updated its Ipanema metadata, which is why it is
		 * not in the IPANEMA_RUNNING state. We can simply change its
		 * state to IPANEMA_READY, a context switch that puts the
		 * thread in the runqueue will soon happen.
		 */
		ipanema_task_state(prev) = IPANEMA_READY;
		break;
	case IPANEMA_READY:
		/*
		 * Case 3: if we're already in the READY state, a yield()
		 * event from a call to sched_yield() set us in this state.
		 */
		prev->ipanema.just_yielded = 0;
		break;
	case IPANEMA_BLOCKED:
	case IPANEMA_TERMINATED:
	case IPANEMA_MIGRATING:
		/*
		 * Cases 4, 5, 6: Nothing to do.
		 */
		break;
	default:
		/*
		 * Case 7: we're in another state: shouldn't happen.
		 */
		pr_warn("[WARN] %s[pid=%d]: Invalid state %d.\n",
			__func__, prev->pid, state);
	}

	sched_monitor_ipanema_stop(PUT_PREV, start);
}

#ifdef CONFIG_SMP
static int select_task_rq_ipanema(struct task_struct *p,
				  int prev_cpu,
				  int sd_flag,
				  int wake_flags)
{
	struct process_event e = { .target = p, .cpu = smp_processor_id() };
	int ret = p->cpu;
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [pid=%d]\n",
			__func__, p->pid);

	/* Safety checks. */
	if (!p || p->sched_class != &ipanema_sched_class) {
		pr_warn("[WARN] %s: Preconditions not fulfilled [%d %d]\n",
			__func__, !p,
			p->sched_class != &ipanema_sched_class);
		sched_monitor_ipanema_stop(SELECT_RQ, start);
		return task_cpu(p);
	}

	/*
	 * If state == IPANEMA_NOT_QUEUED, p is a forked process that
	 * will soon be enqueued. We must call new_prepare() event.
	 */
	if (ipanema_task_state(p) == IPANEMA_NOT_QUEUED) {
		if (!ipanema_task_policy(p))
			pr_err("[ERR] %s: p is IPANEMA_NOT_QUEUED and policy is NULL. Shouldn't happen\n",
			       __func__);
		ipanema_task_rq(p) = NULL;
		ret = ipanema_new_prepare(&e);
		if (ret < 0) {
			pr_warn("[WARN] %s: new_prepare failed (pid=%d, policy=%llu), reverting to p->cpu\n",
				__func__, p->pid,
				ipanema_task_policy(p)->id);
			ret = p->cpu;
		}
	} else if (p->state == TASK_WAKING) {
		ret = ipanema_unblock_prepare(&e);
		/* if migrating on wakeup, remove from previous cpu */
		if (ret >= 0 && ret != task_cpu(p)) {
			struct rq_flags rf;

			rq_lock(task_rq(p), &rf);
			change_rq(p, IPANEMA_BLOCKED, NULL);
			rq_unlock(task_rq(p), &rf);
		}
	}

	sched_monitor_ipanema_stop(SELECT_RQ, start);

	return ret;
}

static void migrate_task_rq_ipanema(struct task_struct *p, int new_cpu)
{
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s, [pid=%d, new_cpu=%d]\n",
			__func__, p->pid, new_cpu);

	sched_monitor_ipanema_stop(MIGRATE, start);
}

static void rq_online_ipanema(struct rq *rq)
{
	struct ipanema_policy *policy = NULL;
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [rq=%d]\n",
			__func__, rq->cpu);

	list_for_each_entry(policy, &ipanema_policies, list)
		ipanema_core_entry(policy, rq->cpu);

	sched_monitor_ipanema_stop(RQ_ONLINE, start);
}

static void rq_offline_ipanema(struct rq *rq)
{
	struct ipanema_policy *policy = NULL;
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [rq=%d]\n",
			__func__, rq->cpu);

	list_for_each_entry(policy, &ipanema_policies, list)
		ipanema_core_exit(policy, rq->cpu);

	sched_monitor_ipanema_stop(RQ_OFFLINE, start);
}

static void task_woken_ipanema(struct rq *this_rq, struct task_struct *p)
{
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("in %s [pid=%d, rq=%d]\n",
			__func__, p->pid, this_rq->cpu);

	sched_monitor_ipanema_stop(WOKEN, start);
}

static void task_dead_ipanema(struct task_struct *p)
{
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [pid=%d]\n",
			__func__, p->pid);

	if (!p || p->sched_class != &ipanema_sched_class)
		pr_err("[ERR] %s: exiting because it was called on an invalid process, a non-ipanema process, or a process whose metadata was not initialized. [%p %d]",
		       __func__, p,
		       p->sched_class != &ipanema_sched_class);

	ipanema_task_policy(p) = NULL;
	ipanema_task_state(p) = IPANEMA_NOT_QUEUED;

	sched_monitor_ipanema_stop(DEAD, start);
}
#endif

static void set_curr_task_ipanema(struct rq *rq)
{
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [rq=%d]\n",
			__func__, rq->cpu);

	/* Check that rq->curr is also ipanema_current and fix it.
	 * Happens when switching to SCHED_IPANEMA: the task is dequeued
	 * from the previous scheduling class queue, then the previous class'
	 * put_prev_task() is called, then the task is enqueued with
	 * enqueue_task_ipanema() which removes it from ipanema_current and
	 * puts it in READY state.
	 */
	if (per_cpu(ipanema_current, rq->cpu) != rq->curr)
		change_state(rq->curr, IPANEMA_RUNNING, rq->cpu, NULL);

	/* Update statistics. */
	rq->curr->se.exec_start = rq_clock_task(rq);

	sched_monitor_ipanema_stop(SET_CURR, start);
}

static void task_tick_ipanema(struct rq *rq,
			      struct task_struct *curr,
			      int queued)
{
	struct process_event e = { .target = curr, .cpu = smp_processor_id() };
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [pid=%d, rq=%d]\n",
			__func__, curr->pid, rq->cpu);

	update_curr_ipanema(rq);

	/*
	 * In task_tick_ipanema, it sometimes happens that rq and curr are on a
	 * different CPU, i.e., rq->cpu and task_cpu(curr) are different. Only
	 * rq's lock is held. This is a bit strange because all calls to
	 * task_tick() in core.c call it with rq and rq->curr. I suspect we are
	 * seeing this because no locks are taken when rq->curr is read, so
	 * it's possible the process was moved before the rq is read.
	 *
	 * What this means is that we may not hold the lock for curr's rq in
	 * tick().  IT DOESN'T MATTER HOWEVER, since we don't allow state
	 * changes in tick() (it seems reasonable).
	 *
	 * FIXME: not the case anymore. State transitions happen in tick().
	 */
	if (rq->cpu != task_cpu(curr))
		pr_warn("%s: rq->cpu=%d task_cpu(curr)=%d\n",
			__func__, rq->cpu, task_cpu(curr));
	ipanema_tick(&e);

	sched_monitor_ipanema_stop(TICK, start);
}

static void task_fork_ipanema(struct task_struct *p)
{
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [pid=%d]\n",
			__func__, p->pid);

	ipanema_task_state(p) = IPANEMA_NOT_QUEUED;
	ipanema_task_rq(p) = NULL;
	p->ipanema.node_runqueue.__rb_parent_color = 0;
	p->ipanema.node_runqueue.rb_right = NULL;
	p->ipanema.node_runqueue.rb_left = NULL;
	policy_metadata(p) = NULL;

	sched_monitor_ipanema_stop(FORK, start);
}

static void prio_changed_ipanema(struct rq *rq,
				 struct task_struct *p,
				 int oldprio)
{
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [pid=%d, rq=%d]\n",
			__func__, p->pid, rq->cpu);

	sched_monitor_ipanema_stop(PRIO_CHANGED, start);
}

static void switched_from_ipanema(struct rq *rq, struct task_struct *p)
{
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [pid=%d, rq=%d]\n",
			__func__, p->pid, rq->cpu);

	/* Task is leaving ipanema, let's cleanup everything */
	ipanema_task_state(p) = IPANEMA_NOT_QUEUED;
	ipanema_task_rq(p) = NULL;
	p->ipanema.node_runqueue.__rb_parent_color = 0;
	p->ipanema.node_runqueue.rb_right = NULL;
	p->ipanema.node_runqueue.rb_left = NULL;
	policy_metadata(p) = NULL;

	sched_monitor_ipanema_stop(SWITCHED_FROM, start);
}

static void switched_to_ipanema(struct rq *rq, struct task_struct *p)
{
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [pid=%d, rq=%d]\n",
			__func__, p->pid, rq->cpu);

	if (rq->curr != p) {
		/*
		 * We can safely call resched_curr() here, because the rq lock
		 * is held.
		 */
		lockdep_assert_held(&rq->lock);
		resched_curr(rq);
	}

	sched_monitor_ipanema_stop(SWITCHED_TO, start);
}

static unsigned int get_rr_interval_ipanema(struct rq *rq,
					    struct task_struct *task)
{
	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [pid=%d, rq=%d]\n",
			__func__, task->pid, rq->cpu);

	return (100 * HZ / 1000);
}

#ifdef CONFIG_FAIR_GROUP_SCHED
static void task_change_group_ipanema(struct task_struct *p, int type)
{
	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [pid=%d]\n",
			__func__, p->pid);
}
#endif

void run_rebalance_domains(struct softirq_action *h)
{
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);
	sched_monitor_start(&run_rebalance_domains);

	ipanema_balancing_select();

	sched_monitor_ipanema_stop(LB_PERIOD, start);
	sched_monitor_stop(&run_rebalance_domains);
}

const struct sched_class ipanema_sched_class = {
	.next			= &idle_sched_class,
	.enqueue_task		= enqueue_task_ipanema,
	.dequeue_task		= dequeue_task_ipanema,
	.yield_task		= yield_task_ipanema,
	.yield_to_task		= yield_to_task_ipanema,

	.check_preempt_curr	= check_preempt_wakeup,

	.pick_next_task		= pick_next_task_ipanema,
	.put_prev_task		= put_prev_task_ipanema,

#ifdef CONFIG_SMP
	.select_task_rq		= select_task_rq_ipanema,
	.migrate_task_rq	= migrate_task_rq_ipanema,

	.rq_online		= rq_online_ipanema,
	.rq_offline		= rq_offline_ipanema,

	.task_woken		= task_woken_ipanema,
	.task_dead		= task_dead_ipanema,
	.set_cpus_allowed	= set_cpus_allowed_common,
#endif

	.set_curr_task	  = set_curr_task_ipanema,
	.task_tick		  = task_tick_ipanema,
	.task_fork		  = task_fork_ipanema,

	.prio_changed	   = prio_changed_ipanema,
	.switched_from	  = switched_from_ipanema,
	.switched_to		= switched_to_ipanema,

	.get_rr_interval	= get_rr_interval_ipanema,

	.update_curr		= update_curr_ipanema,

#ifdef CONFIG_FAIR_GROUP_SCHED
	.task_change_group	= task_change_group_ipanema,
#endif
};

void trigger_load_balance_ipanema(struct rq *rq)
{
	raise_softirq(SCHED_SOFTIRQ_IPANEMA);
}

DEFINE_PER_CPU(struct topology_level *, topology_levels);
EXPORT_SYMBOL(topology_levels);

static int create_topology(void)
{
	int cpu;
	struct sched_domain *sd;
	struct topology_level *l, *cur;

	/*
	 * for each CPU, we export the topology to the ipanema policies through
	 * the topology_levels per-cpu variable.
	 * To build this, we use the already built sched_domains.
	 */
	for_each_possible_cpu(cpu) {
		per_cpu(topology_levels, cpu) = NULL;
		cur = NULL;
		for_each_domain(cpu, sd) {
			l = kzalloc(sizeof(struct topology_level), GFP_KERNEL);
			if (!l)
				return -ENOMEM;
			if (sd->flags & SD_SHARE_CPUCAPACITY)
				l->flags |= DOMAIN_SMT;
			if (sd->flags & SD_SHARE_PKG_RESOURCES)
				l->flags |= DOMAIN_CACHE;
			if (sd->flags & SD_NUMA)
				l->flags |= DOMAIN_NUMA;
			cpumask_copy(&l->cores, sched_domain_span(sd));

			/* insert level in per_cpu list (at tail) */
			l->next = NULL;
			if (!per_cpu(topology_levels, cpu))
				per_cpu(topology_levels, cpu) = l;
			else
				cur->next = l;
			cur = l;
		}
	}

	return 0;
}

#ifdef CONFIG_IPANEMA_DEBUG_TOPOLOGY
static void print_topology(void)
{
	int cpu;
	struct topology_level *l;

	pr_info("+-----------------------+\n");
	pr_info("|    ipanema topology   |\n");
	pr_info("+-----------------------+\n");
	pr_info("  cpu  | SMT | CACHE | NUMA |   cpulist\n");
	for_each_possible_cpu(cpu) {
		pr_info("-------+-----+-------+------+--------------\n");
		pr_info(" %5d |\n", cpu);
		l = per_cpu(topology_levels, cpu);
		while (l) {
			pr_info("       |  %d  |   %d   |   %d  | %*pbl\n",
				l->flags & DOMAIN_SMT ? 1 : 0,
				l->flags & DOMAIN_CACHE ? 1 : 0,
				l->flags & DOMAIN_NUMA ? 1 : 0,
				cpumask_pr_args(&l->cores));
			l = l->next;
		}
	}
}
#endif	/* CONFIG_IPANEMA_DEBUG_TOPOLOGY */

#ifdef CONFIG_CGROUP_IPANEMA
static struct cgroup_subsys_state *
ipanema_cgroup_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct ipanema_group *ipa_grp;

	ipa_grp = kzalloc(sizeof(struct ipanema_group), GFP_KERNEL);
	if (!ipa_grp)
		return ERR_PTR(-ENOMEM);

	return &ipa_grp->css;
}

static void ipanema_cgrp_attach(struct cgroup_taskset *tset)
{
	struct task_struct *t = NULL;
	struct cgroup_subsys_state *css = NULL;
	struct sched_attr attr = { .size = sizeof(struct sched_attr),
				   .sched_flags = 0,
				   .sched_nice = 0,
				   .sched_priority = 0
	};

	/* Move each task to the ipanema policy */
	cgroup_taskset_for_each(t, css, tset) {
		struct ipanema_group *ipa_grp = ipanema_group_of(css);

		if (ipa_grp->policy) {
			/* move thread to new ipanema policy */
			attr.sched_policy = SCHED_IPANEMA;
			attr.sched_ipa_policy = ipa_grp->policy->id;
			attr.sched_ipa_attr_size = 0;
			attr.sched_ipa_attr = NULL;
		} else {
			/* move thread to fair */
			attr.sched_policy = SCHED_NORMAL;
		}
		if (sched_setattr_nocheck(t, &attr)) {
			if (ipa_grp->policy)
				pr_err("task %d could not be moved to ipanema policy %llu!\n",
				       t->pid, ipa_grp->policy->id);
			else
				pr_err("task %d could not be moved to fair!\n",
				       t->pid);
		}
	}
}

static void ipanema_cgroup_css_free(struct cgroup_subsys_state *css)
{
	struct ipanema_group *ipa_grp;

	ipa_grp = ipanema_group_of(css);
	kfree(ipa_grp);
}

static s64 ipanema_policy_id_read_s64(struct cgroup_subsys_state *css,
				      struct cftype *cft)
{
	struct ipanema_group *ipa_grp = ipanema_group_of(css);

	if (!ipa_grp->policy)
		return -1;
	return ipa_grp->policy->id;
}

static int ipanema_policy_id_write_s64(struct cgroup_subsys_state *css,
				       struct cftype *cft, s64 val)
{
	struct ipanema_group *ipa_grp = ipanema_group_of(css);
	struct css_task_iter it;
	struct task_struct *t;
	struct ipanema_policy *policy, *old_policy = ipa_grp->policy;
	bool found = false;
	unsigned long flags;
	int ret = 0;
	struct sched_attr attr = { .size = sizeof(struct sched_attr),
				   .sched_flags = 0,
				   .sched_nice = 0,
				   .sched_priority = 0
	};

	if (!css->parent)
		return -EPERM;

	/* check boundaries (i.e. policy id is a s64, and -1 is ok here */
	if (val < -1 || val > S64_MAX)
		return -EINVAL;
	if (val != -1) {
		/* if no change, nothing to do */
		if (ipa_grp->policy && val == ipa_grp->policy->id)
			return 0;

		read_lock_irqsave(&ipanema_rwlock, flags);
		list_for_each_entry(policy, &ipanema_policies, list) {
			if (policy->id == val) {
				found = true;
				break;
			}
		}
		if (found) {
			if (!try_module_get(policy->kmodule))
				ret = -EINVAL;
		} else
			ret = -EINVAL;
		read_unlock_irqrestore(&ipanema_rwlock, flags);
		if (ret)
			return ret;

		ipa_grp->policy = policy;
		attr.sched_policy = SCHED_IPANEMA;
		attr.sched_ipa_policy = val;
		attr.sched_ipa_attr_size = 0;
		attr.sched_ipa_attr = NULL;
	} else {
		ipa_grp->policy = NULL;
		attr.sched_policy = SCHED_NORMAL;
	}

	if (old_policy) {
		module_put(old_policy->kmodule);
	}

	/* Move all tasks in css to their new policy */
	css_task_iter_start(css, 0, &it);
	while ((t = css_task_iter_next(&it))) {
		if (sched_setattr_nocheck(t, &attr)) {
			if (val == -1)
				pr_err("task %d could not be moved to fair!\n",
				       t->pid);
			else
				pr_err("task %d could not be moved to ipanema policy %lld!\n",
				       t->pid, val);
		}
	}
	css_task_iter_end(&it);

	return 0;
}

static struct cftype ipanema_cgrp_files[] = {
	{
		.name      = "policy_id",
		.read_s64  = ipanema_policy_id_read_s64,
		.write_s64 = ipanema_policy_id_write_s64,
	},
	{ }    /* terminate */
};

struct cgroup_subsys ipanema_cgrp_subsys = {
	.css_alloc      = ipanema_cgroup_css_alloc,
	.css_free       = ipanema_cgroup_css_free,
	.attach         = ipanema_cgrp_attach,
	.legacy_cftypes	= ipanema_cgrp_files,
	.dfl_cftypes	= ipanema_cgrp_files,
};
#endif	/* CONFIG_CGROUP_IPANEMA */

/*
 * Rbtree manipulation
 */
static inline int ipanema_add_task_rbtree(struct rb_root *root,
					  struct task_struct *data,
					  int (*cmp_fn)(struct task_struct *,
							struct task_struct *))
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	while (*new) {
		struct task_struct *t = container_of(*new, struct task_struct,
						     ipanema.node_runqueue);
		int res = cmp_fn(data, t);

		parent = *new;

		/*
		 * We compare with the provided function, but if both threads
		 * are equal, we use the task_struct's address to differenciate.
		 * If the node is already in the rbtree, we stop here.
		 */
		if (res < 0)
			new = &((*new)->rb_left);
		else if (res > 0)
			new = &((*new)->rb_right);
		else if (data < t)
			new = &((*new)->rb_left);
		else if (data > t)
			new = &((*new)->rb_right);
		else
			return -EINVAL;
	}

	rb_link_node(&data->ipanema.node_runqueue, parent, new);
	rb_insert_color(&data->ipanema.node_runqueue, root);

	return 0;
}

static inline struct task_struct *
ipanema_remove_task_rbtree(struct rb_root *root, struct task_struct *data)
{
	rb_erase(&data->ipanema.node_runqueue, root);
	memset(&data->ipanema.node_runqueue, 0,
	       sizeof(data->ipanema.node_runqueue));
	return data;
}

static inline struct task_struct *
ipanema_first_task_rbtree(struct rb_root *root)
{
	struct rb_node *first;

	first = rb_first(root);
	if (!first)
		return NULL;

	return container_of(first, struct task_struct, ipanema.node_runqueue);
}

/*
 * LIST manipulation
 */
static inline int ipanema_add_task_list(struct list_head *head,
					struct task_struct *data,
					int (*cmp_fn)(struct task_struct *,
						      struct task_struct *))
{
	struct task_struct *ts;

	list_for_each_entry(ts, head, ipanema.node_list) {
		if (cmp_fn(data, ts) < 0) {
			list_add_tail(&data->ipanema.node_list,
				      &ts->ipanema.node_list);
			return 0;
		}
	}
	list_add_tail(&data->ipanema.node_list, head);
	return 0;
}

static inline struct task_struct *
ipanema_remove_task_list(struct list_head *head, struct task_struct *data)
{
	list_del_init(&data->ipanema.node_list);

	return data;
}

static inline struct task_struct *
ipanema_first_task_list(struct list_head *head)
{
	return list_first_entry_or_null(head, struct task_struct,
					ipanema.node_list);
}

/*
 * FIFO manipulation
 */
static inline int ipanema_add_task_fifo(struct list_head *head,
					struct task_struct *data,
					int (*cmp_fn)(struct task_struct *,
						      struct task_struct *))
{
	list_add_tail(&data->ipanema.node_list, head);
	return 0;
}

/*
 * Generic ipanema_rq API
 */
int ipanema_add_task(struct ipanema_rq *rq, struct task_struct *data)
{
	switch (rq->type) {
	case RBTREE:
		return ipanema_add_task_rbtree(&rq->root, data, rq->order_fn);
	case LIST:
		return ipanema_add_task_list(&rq->head, data, rq->order_fn);
	case FIFO:
		return ipanema_add_task_fifo(&rq->head, data, rq->order_fn);
	default:
		return -EINVAL;
	}
}

struct task_struct *ipanema_remove_task(struct ipanema_rq *rq,
					struct task_struct *data)
{
	switch (rq->type) {
	case RBTREE:
		return ipanema_remove_task_rbtree(&rq->root, data);
	case LIST:
	case FIFO:
		return ipanema_remove_task_list(&rq->head, data);
	default:
		return NULL;
	}
}

struct task_struct *ipanema_first_task(struct ipanema_rq *rq)
{
	switch (rq->type) {
	case RBTREE:
		return ipanema_first_task_rbtree(&rq->root);
	case LIST:
	case FIFO:
		return ipanema_first_task_list(&rq->head);
	default:
		return NULL;
	}
}
EXPORT_SYMBOL(ipanema_first_task);

void init_ipanema_rq(struct ipanema_rq *rq, enum ipanema_rq_type type,
		     unsigned int cpu, enum ipanema_state state,
		     int (*order_fn)(struct task_struct *a,
				     struct task_struct *b))
{
	rq->type = type;
	switch (type) {
	case RBTREE:
		rq->root.rb_node = NULL;
		break;
	case LIST:
	case FIFO:
		INIT_LIST_HEAD(&rq->head);
		break;
	}
	rq->cpu = cpu;
	rq->state = state;
	rq->nr_tasks = 0;
	rq->order_fn = order_fn;
}
EXPORT_SYMBOL(init_ipanema_rq);

/*
 * procfs interface: located in /proc/ipanema
 */
static void *ipanema_policies_start(struct seq_file *f, loff_t *pos)
{
	read_lock(&ipanema_rwlock);
	return seq_list_start(&ipanema_policies, *pos);
}

static void *ipanema_policies_next(struct seq_file *f, void *v, loff_t *pos)
{
	return seq_list_next(v, &ipanema_policies, pos);
}

static void ipanema_policies_stop(struct seq_file *f, void *v)
{
	read_unlock(&ipanema_rwlock);
}

static int ipanema_policies_show(struct seq_file *f, void *v)
{
	struct ipanema_policy *policy = list_entry(v, struct ipanema_policy,
						   list);
	seq_printf(f, "%llu %s %d\n",
		   policy->id, policy->name, module_refcount(policy->kmodule));
	return 0;
}

static const struct seq_operations ipanema_policies_ops = {
	.start = ipanema_policies_start,
	.next  = ipanema_policies_next,
	.show  = ipanema_policies_show,
	.stop  = ipanema_policies_stop
};

static int ipanema_policies_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ipanema_policies_ops);
}

static const struct file_operations ipanema_policies_fops = {
	.open    = ipanema_policies_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

struct proc_dir_entry *ipa_procdir;
EXPORT_SYMBOL(ipa_procdir);

/*
 * sysfs interface: located at /sys/kernel/ipanema/
 */

#define IPANEMA_ATTR_RO(_name) \
static struct kobj_attribute _name##_attr = __ATTR_RO(_name)

#define IPANEMA_ATTR_RW(_name) \
static struct kobj_attribute _name##_attr = \
	__ATTR(_name, 0644, _name##_show, _name##_store)


/*
 * Check that transitions do not violate the Ipanema finite state machine
 * Prints errors in dmesg if it does
 */
int ipanema_fsm_check;
static ssize_t ipanema_fsm_check_show(struct kobject *kobj,
				      struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", READ_ONCE(ipanema_fsm_check));
}
static ssize_t ipanema_fsm_check_store(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	if (kstrtoint(buf, 0, &ipanema_fsm_check))
		return -EINVAL;

	return count;
}
IPANEMA_ATTR_RW(ipanema_fsm_check);

/*
 * Log all transitions in the Ipanema finite state machine
 */
int ipanema_fsm_log;
static ssize_t ipanema_fsm_log_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", READ_ONCE(ipanema_fsm_log));
}
static ssize_t ipanema_fsm_log_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	if (kstrtoint(buf, 0, &ipanema_fsm_log))
		return -EINVAL;

	return count;
}
IPANEMA_ATTR_RW(ipanema_fsm_log);

/*
 * Log calls to the ipanema scheduling class functions
 */
int ipanema_sched_class_log;
static ssize_t ipanema_sched_class_log_show(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    char *buf)
{
	return sprintf(buf, "%d\n", READ_ONCE(ipanema_sched_class_log));
}
static ssize_t ipanema_sched_class_log_store(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     const char *buf, size_t count)
{
	if (kstrtoint(buf, 0, &ipanema_sched_class_log))
		return -EINVAL;

	return count;
}
IPANEMA_ATTR_RW(ipanema_sched_class_log);

struct kobject *ipanema_kobj;

static struct attribute *ipanema_attrs[] = {
	&ipanema_fsm_check_attr.attr,
	&ipanema_fsm_log_attr.attr,
	&ipanema_sched_class_log_attr.attr,
	NULL
};

static struct attribute_group ipanema_attr_group = {
	.attrs = ipanema_attrs,
};

__init void init_sched_ipanema_class(void)
{
	rwlock_init(&ipanema_rwlock);
	open_softirq(SCHED_SOFTIRQ_IPANEMA, run_rebalance_domains);

	pr_info("sched_class initialized\n");
}

__init int init_sched_ipanema_late(void)
{
	int ret;

	ret = create_topology();
	if (ret) {
		pr_err("create_topology() failed\n");
		goto exit;
	}

#ifdef CONFIG_IPANEMA_DEBUG_TOPOLOGY
	print_topology();
#endif

	ipa_procdir = proc_mkdir("ipanema", NULL);
	if (!ipa_procdir) {
		pr_err("procfs creation failed\n");
		ret = -ENOMEM;
		goto exit;
	}
	if (!proc_create("policies", 0444, ipa_procdir,
			 &ipanema_policies_fops)) {
		pr_err("procfs creation failed\n");
		ret = -ENOMEM;
		goto exit;
	}
	pr_info("/proc/ipanema/ directory created\n");

	/* Create /sys/kernel/ipanema */
	ipanema_kobj = kobject_create_and_add("ipanema", kernel_kobj);
	if (!ipanema_kobj) {
		ret = -ENOMEM;
		goto exit;
	}
	ret = sysfs_create_group(ipanema_kobj, &ipanema_attr_group);
	if (ret)
		goto exit;
	pr_info("/sys/kernel/ipanema/ directory created\n");

	return 0;

exit:
	return ret;
}
late_initcall(init_sched_ipanema_late);
