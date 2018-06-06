#include "sched.h"
#include "ipanema_common.h"
#include "monitor.h"

#ifndef CONFIG_LOCKDEP
#error CONFIG_LOCKDEP must be enabled
#endif

#include <linux/lockdep.h>
#include <linux/cpufreq.h>
#include <linux/kgdb.h>

int ipanema_debug;
EXPORT_SYMBOL(ipanema_debug);

/* Current running task per type */
DEFINE_PER_CPU(struct task_struct *, ipanema_current);
EXPORT_SYMBOL(ipanema_current);

static void update_curr_ipanema(struct rq *rq);

/*
 * Check the validity of an ipanema transition
 */
static void check_ipanema_transition(struct task_struct *p,
				     enum ipanema_state next_state,
				     unsigned int next_cpu)
{
	enum ipanema_state prev_state = p->ipanema_metadata.state;
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
	pr_err("%s:%d: WARNING! [pid=%d] Incorrect transition %s[%d] -> %s[%d]\n",
	       __FUNCTION__, __LINE__, p->pid,
	       ipanema_state_to_str(prev_state), prev_cpu,
	       ipanema_state_to_str(next_state), next_cpu);
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
		p = ipanema_remove_task(prev_rq, p,
					ipanema_order_process);
		prev_rq->nr_tasks--;
	}

	ipanema_task_rq(p) = next_rq;
	ipanema_task_state(p) = next_state;

	if (next_rq) {
		next_cpu = next_rq->cpu;
		next_state = next_rq->state;
		lockdep_assert_held(&cpu_rq(next_cpu)->lock);
		ipanema_add_task(next_rq, p,
				 ipanema_order_process);
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
		IPA_EMERG_SAFE("WARNING! Called %s with a null process! Exiting...\n",
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
			IPA_EMERG_SAFE("%s: Discrepancy in parameters: next_state = %s; next_cpu = %d, next_rq = [cpu=%d, state=%s]. Using next_rq values\n",
				       __func__,
				       ipanema_state_to_str(next_state),
				       next_cpu, next_rq->cpu,
				       ipanema_state_to_str(next_rq->state));
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
		pr_info("ipanema: [pid=%d] %s[%d] -> %s[%d]\n",
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
			IPA_EMERG_SAFE("putting a task in RUNNING but there is already another task! We preempt it to avoid potential bugs. Should not happen !!!\n");

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
	if (!per_cpu(ipanema_current, prev_cpu)
	    && cpu_rq(prev_cpu)->nr_running
	    && prev_cpu == next_cpu)
		resched_curr(cpu_rq(prev_cpu));
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
	struct process_event e = { .target = p , .cpu = smp_processor_id() };
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
		IPA_EMERG_SAFE("%s: WARNING: called on a task with no ipanema policy set.\n",
			       __func__);
		goto end;
	}

	/*
	 * We are in the middle of a migration. We don't need to do anything,
	 * just update rq->nr_running/count_ready
	 */
	if (task_on_rq_migrating(p))
		goto end;

	/* The thread is switching to SCHED_IPANEMA class,
	 * we must:
	 * - initialize its ipanema_metadata
	 * - call its policy's new_prepare() routine to
	 *   initialize the per-policy metadata, but we ignore
	 *   the return value to avoid inconsistency, since it's
	 *   too late to choose a runqueue.
	 */
	if (p->switching_classes) {
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
		 */
		if (!p->ipanema_metadata.policy_metadata)
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
	 */
	if (p->state == TASK_WAKING) {
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

	IPA_EMERG_SAFE("WARNING! Uncaught enqueue, CONTEXT: p=[pid=%d, cpu=%d, state=%ld, on_cpu=%d, on_rq=%d, ipanema=[current_state=%s]]; rq[%d]=%p; flags=%d\n",
		       p->pid, p->cpu, p->state, p->on_cpu, p->on_rq,
		       ipanema_state_to_str(ipanema_task_state(p)),
		       rq->cpu, rq, flags);

end:
	add_nr_running(rq, 1);
	rq->nr_ipanema_running++;
	IPA_DBG_SAFE("Enqueueing %p, nr_running=%d.\n", p, rq->nr_running);

	sched_monitor_ipanema_stop(ENQUEUE, start);
}

static void dequeue_task_ipanema(struct rq *rq,
				 struct task_struct *p,
				 int flags)
{
	struct process_event e = { .target = p , .cpu = smp_processor_id() };
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
		IPA_EMERG_SAFE("%s: WARNING: called on a task with no ipanema policy set.\n",
			       __func__);
		goto end;
	}

	/*
	 * We are in the middle of a migration. We don't need to do anything,
	 * just update rq->nr_running/count_ready
	 */
	if (task_on_rq_migrating(p))
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
	 */
	if (p->state & TASK_INTERRUPTIBLE ||
	    p->state & TASK_UNINTERRUPTIBLE ||
	    p->state & TASK_STOPPED ||
	    p->state & TASK_KILLABLE) {
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
	 * The task is being dequeued because it's switching to another
	 * scheduling class. In this case too, we should call terminate. We must
	 * also set the ipanema policy to NULL to avoid problems if the task
	 * switches back to SCHED_IPANEMA class.
	 */
	if (p->switching_classes) {
		ipanema_terminate(&e);
		ipanema_task_policy(p) = NULL;
		goto end;
	}

	/*
	 * If flags is DEQUEUE_SAVE, it means we are in a quick
	 * dequeue/enqueue, just update nr_running/count_ready
	 */
	if (flags & DEQUEUE_SAVE)
		goto end;

	IPA_EMERG_SAFE("WARNING! Uncaught dequeue, CONTEXT: p=[pid=%d, cpu=%d, state=%ld, on_cpu=%d, on_rq=%d, ipanema=[current_state=%s]]; rq[%d]=%p; flags=%d\n",
		       p->pid, p->cpu, p->state, p->on_cpu, p->on_rq,
		       ipanema_state_to_str(ipanema_task_state(p)),
		       rq->cpu, rq, flags);

end:
	sub_nr_running(rq, 1);
	rq->nr_ipanema_running--;
	IPA_DBG_SAFE("Dequeueing %p, nr_running=%d, p->state=%16lx, p->flags=%8x.\n",
		     p, rq->nr_running, p->state, p->flags);

	sched_monitor_ipanema_stop(DEQUEUE, start);
}

static void yield_task_ipanema(struct rq *rq)
{
	struct process_event e = { .target = rq->curr , .cpu = smp_processor_id() };
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
	p->ipanema_metadata.just_yielded = 1;

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
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
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
	 * dequeue and the correct ipanema event handler)
	 */
	if (per_cpu(ipanema_current, rq->cpu)) {
		result = per_cpu(ipanema_current, rq->cpu);
		if (prev->state != TASK_RUNNING)
			pr_info("%s: ipanema_current was not NULL and task is not TASK_RUNNING. Should not happen\n",
				__FUNCTION__);
	} else {
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
			cstate = ipanema_get_core_state(policy,
							rq->cpu);
			if (cstate == IPANEMA_IDLE_CORE)
				continue;
			sched_monitor_ipanema_idle_balance();
			ipanema_newly_idle(policy, rq->cpu, rf);
			ipanema_schedule(policy, rq->cpu);
			result = per_cpu(ipanema_current, rq->cpu);
			/* if a task is found, schedule it */
			if (result)
				break;
			/* else call enter_idle() handler for this policy/cpu */
			ipanema_enter_idle(policy, rq->cpu);
		}
	}

	if (!result)
		goto end;

	/*
	 * Case 1: the next task we pick is the same as the previous one. I
	 * believe this can happen in two cases: the thread's quantum is over
	 * or the thread called yield(). In both cases, there won't be an
	 * actual preemption. We don't want to call put_prev_task() here because
	 * it may make prev IPANEMA_READY, even though it will be running.
	 */
	if (result == prev)
		IPA_DBG_SAFE("We picked the same task as before! Don't call put_prev_task!\n");

	if (result != prev) {
		put_prev_task(rq, prev);
		IPA_DBG_SAFE("put_prev_task() over.\n");

		result->se.exec_start = rq_clock_task(rq);
	}

	if (ipanema_task_state(result) != IPANEMA_RUNNING) {
		IPA_EMERG_SAFE("The result of pick_next_task_ipanema() is not in the IPANEMA_RUNNING state ! It's in state %s instead. Switching to IPANEMA_RUNNING to prevent issues, but we shouldn't be in this situation!\n",
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
	struct process_event e = { .target = prev , .cpu = smp_processor_id() };
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s [pid=%d, rq=%d]\n",
			__func__, prev->pid, rq->cpu);

	/* Safety checks. Avoid using BUG_ON() to fail gracefully. */
	if (!prev || prev->sched_class != &ipanema_sched_class) {
		IPA_EMERG_SAFE("WARNING! At least one precondition not verified in %s [%d %d]\n",
			       __func__, !prev,
			       prev->sched_class != &ipanema_sched_class);
		BUG();
	}

	/* If we are switching class, ie. moving out from ipanema,
	 * dequeue_task_ipanema() already called terminate(). We just remove
	 * prev from ipanema_current if necessary. We don't call resched_curr()
	 * because the task will keep the cpu in its new sched_class.
	 */
	if (prev->switching_classes) {
		if (per_cpu(ipanema_current, prev->cpu) == prev)
			per_cpu(ipanema_current, prev->cpu) = NULL;
		sched_monitor_ipanema_stop(PUT_PREV, start);
		return;
	}

	update_curr_ipanema(rq);

	state = ipanema_task_state(prev);

	IPA_DBG_SAFE("In %s [%p on rq %d, state=%d].\n",
		     __func__, prev, rq->cpu, state);

	/*
	 * Case 1: this is either one of these times when we have a quick
	 * put_prev_task()/set_curr_task() with the rq lock held, or we've been
	 * preempted by a non-ipanema thread.
	 *
	 * FIXME: add a preempt() event.
	 */
	if (state == IPANEMA_RUNNING) {
		/*
		 * Case 1a: this isn't a preemption, just one of these quick
		 * put_prev_task()/set_curr_task() things. Do nothing.
		 *
		 * Note: nopreempt is a flag we added.
		 */
		if (prev->nopreempt) {
			IPA_DBG_SAFE("Non-preempting %s\n", __func__);
			sched_monitor_ipanema_stop(PUT_PREV, start);
			return;
		}

		/*
		 * Case 1b: preemption! We should call preempt() but we don't
		 * have a preempt() event. So we just call yield().
		 */
		ipanema_yield(&e);
		/*
		 * Case 2: preemption caused by a transition to ready in tick().
		 */
	} else if (state == IPANEMA_READY_TICK) {
		/*
		 * We're just before the preemption of a thread that has just
		 * been moved to the ready queue from tick(). The thread is
		 * still running from the runtime's point of view, but we
		 * already updated its Ipanema metadata, which is why it is
		 * not in the IPANEMA_RUNNING state. We can simply change its
		 * state to IPANEMA_READY, a context switch that puts the
		 * thread in the runqueue will soon happen.
		 */
		IPA_DBG_SAFE("In %s [prev=%p, rq=%d], following a context switch from a transition to the ready state in tick(). Going from READY_TICK to READY.\n",
			     __func__, prev, rq->cpu);
		ipanema_task_state(prev) = IPANEMA_READY;
		/*
		 * Case 3: if we're already in the READY state, either a yield() event
		 * from a call to sched_yield() set us in this state, or we switched to
		 * ipanema sched_class.
		 */
	} else if (state == IPANEMA_READY) {
		/* Safety check. */
		if (!prev->ipanema_metadata.just_yielded) {
			IPA_EMERG_SAFE("WARNING! IPANEMA_READY in %s not following a yield().\n",
				       __func__);
			sched_monitor_ipanema_stop(PUT_PREV, start);
			return;
		}

		IPA_DBG_SAFE("In %s following a yield().\n",
			     __func__);
		prev->ipanema_metadata.just_yielded = 0;
		/*
		 * Case 4: if we're in the BLOCKED state, a block() event (from
		 * try_to_wake_up() -> enqueue_task_ipanema()) must have set us
		 * in this state.
		 */
	} else if (state == IPANEMA_BLOCKED) {
		IPA_DBG_SAFE("Blocked in %s, should follow a block() event.\n",
			     __func__);
		/*
		 * Case 5: the thread was terminated during its last dequeue. Don't
		 * do anything.
		 */
	} else if (state == IPANEMA_TERMINATED) {
		IPA_DBG_SAFE("Terminated in %s, should follow a terminate() event.\n",
			     __func__);
		/*
		 * Case 6: the thread is migrating.
		 */
	} else if (state == IPANEMA_MIGRATING) {

		/*
		 * Case 7: we're in another state: shouldn't happen.
		 */
	} else {
		IPA_EMERG_SAFE("WARNING! Invalid state (%d) in %s.\n",
			       state, __func__);
	}
	sched_monitor_ipanema_stop(PUT_PREV, start);
}

#ifdef CONFIG_SMP
static int select_task_rq_ipanema(struct task_struct *p,
				  int prev_cpu,
				  int sd_flag,
				  int wake_flags)
{
	struct process_event e = { .target = p , .cpu = smp_processor_id() };
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
		IPA_EMERG_SAFE("WARNING! Preconditions not fulfilled in %s [%d %d]\n",
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
			IPA_EMERG_SAFE("%s: p is IPANEMA_NOT_QUEUED and policy is NULL. Shouldn't happen\n",
				       __func__);
		ipanema_task_rq(p) = NULL;
		ret = ipanema_new_prepare(&e);
		if (ret < 0) {
			IPA_EMERG_SAFE("%s: new_prepare failed (pid=%d, policy=%d), reverting to p->cpu\n",
				       __func__, p->pid,
				       ipanema_task_policy(p)->id);
			ret = p->cpu;
		}
	} else if (p->state == TASK_WAKING) {
		ret = ipanema_unblock_prepare(&e);
	}

	sched_monitor_ipanema_stop(SELECT_RQ, start);

	return ret;
}

static void migrate_task_rq_ipanema(struct task_struct *p)
{
#ifdef CONFIG_SCHED_MONITOR_IPANEMA
	u64 start = 0;
#endif

	sched_monitor_ipanema_start(start);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In %s, [pid=%d]\n",
			__func__, p->pid);

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

	list_for_each_entry(policy, &ipanema_policies, list) {
		if (cpumask_test_cpu(rq->cpu, &policy->allowed_cores))
			ipanema_core_entry(policy, rq->cpu);
	}

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

	list_for_each_entry(policy, &ipanema_policies, list) {
		if (cpumask_test_cpu(rq->cpu, &policy->allowed_cores))
			ipanema_core_exit(policy, rq->cpu);
	}

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
		IPA_DBG_SAFE("WARNING! Exiting %s, because it was called on an invalid process, a non-ipanema process, or a process whose metadata was not initialized. [%p %d]",
			     __func__, p,
			     p->sched_class != &ipanema_sched_class);

	/*
	 * We should decrease the reference counter on p, because we increased
	 * it in the IOCTL. This is assuming the IOCTL has indeed been called.
	 * Disabled for now, might cause issues.
	 */
//	put_task_struct(p);

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
	struct process_event e = { .target = curr , .cpu = smp_processor_id() };
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
	 *
	 */
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
	p->ipanema_metadata.node_runqueue.__rb_parent_color = 0;
	p->ipanema_metadata.node_runqueue.rb_right = NULL;
	p->ipanema_metadata.node_runqueue.rb_left = NULL;
	p->ipanema_metadata.policy_metadata = NULL;

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
		IPA_DBG_SAFE("Calling resched_curr().\n");
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

#ifdef CONFIG_FAIR_GROUP_SCHED
static void task_change_group_ipanema(struct task_struct *p, int type)
{
	if (unlikely(ipanema_sched_class_log))
		pr_info("In task_change_group_ipanema() [pid=%d]\n",
			p->pid);

	switch (type) {
	case TASK_SET_GROUP:
		IPA_DBG_SAFE("In %s setting group.\n", __func__);
		break;

	case TASK_MOVE_GROUP:
		IPA_DBG_SAFE("In %s moving group.\n", __func__);
		break;
	}
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
			if (!l) {
				pr_err("ipanema: failed to allocate memory for topology_levels (cpu%d)\n",
				       cpu);
				return -ENOMEM;
			}
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

static void print_topology(void)
{
	int cpu;
	struct topology_level *l;

	pr_info("+-----------------------+*\n");
	pr_info("|    ipanema topology   |\n");
	pr_info("+-----------------------+\n");
	pr_info("  cpu  | SMT | CACHE | NUMA |   cpulist    \n");
	for_each_possible_cpu(cpu) {
		pr_info("-------+-----+-------+------+--------------\n");
		pr_info(" %5d |\n", cpu);
		l = per_cpu(topology_levels, cpu);
		while (l) {
			pr_info("       |  %d  |   %d   |   %d  | %*pbl \n",
				l->flags & DOMAIN_SMT ? 1 : 0,
				l->flags & DOMAIN_CACHE ? 1 : 0,
				l->flags & DOMAIN_NUMA ? 1 : 0,
				cpumask_pr_args(&l->cores));
			l = l->next;
		}
	}
}

void __init init_sched_ipanema_class(void)
{
	rwlock_init(&ipanema_rwlock);
	open_softirq(SCHED_SOFTIRQ_IPANEMA, run_rebalance_domains);

	pr_info("ipanema: sched_class initialized\n");
}

int __init init_sched_ipanema_late(void)
{
	int ret;

	ret = create_topology();
	if (ret)
		pr_err("ipanema: create_topology() failed\n");
	print_topology();

	return 0;
}
late_initcall(init_sched_ipanema_late);
