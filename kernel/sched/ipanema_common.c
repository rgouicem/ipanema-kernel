#include "ipanema_common.h"
#include "sched.h"

#ifndef CONFIG_LOCKDEP
#error CONFIG_LOCKDEP must be enabled
#endif

#include <linux/lockdep.h>
#include <linux/cpufreq.h>
#include <linux/kgdb.h>

int ipanema_debug = 0;
EXPORT_SYMBOL(ipanema_debug);

/* DEFINE_SPINLOCK(rq_lock); */

/* Runqueues per type */
DEFINE_PER_CPU(struct task_struct *, ipanema_current);
EXPORT_SYMBOL(ipanema_current);
DEFINE_PER_CPU(ipanema_rq, ipanema_ready);
EXPORT_SYMBOL(ipanema_ready);
DEFINE_PER_CPU(int, count_ready);

static void update_curr_ipanema(struct rq *rq);

static inline struct ipanema_runtime_metadata *
runtime_metadata(struct task_struct *p)
{
	return p->ipanema_metadata.runtime_metadata;
}

inline void check_identical_rqs(struct rq *rq, struct task_struct *p)
{
	if (p && p->sched_class == &ipanema_sched_class &&
	    runtime_metadata(p) &&
	    (cpu_rq(p->cpu) != rq ||
	     rq != task_rq(p))) {
		IPA_EMERG_SAFE("WARNING! Different rq cpu/locks: %d/%d %d/%d\n",
			task_cpu(p),
			lockdep_is_held(&task_rq(p)->lock),
			(rq)->cpu,
			lockdep_is_held(&(rq)->lock));
	}
}
EXPORT_SYMBOL(check_identical_rqs);

/* Needed to acquire the rq lock in modules. */
raw_spinlock_t *ipanema_task_lock(struct task_struct *p)
{
	return &task_rq(p)->lock;
}
EXPORT_SYMBOL(ipanema_task_lock);

int ipanema_get_current_cpu(struct task_struct *p)
{
	struct ipanema_runtime_metadata *metadata = runtime_metadata(p);

	BUG_ON(!metadata);

	return p->cpu;
}
EXPORT_SYMBOL(ipanema_get_current_cpu);

enum ipanema_state ipanema_get_current_state(struct task_struct *p)
{
	struct ipanema_runtime_metadata *metadata = runtime_metadata(p);

	BUG_ON(!metadata);

	return metadata->current_state;
}
EXPORT_SYMBOL(ipanema_get_current_state);

/* 
 * Get the runqueue attached to an ipanema state for a given cpu
 */
ipanema_rq *get_rq(enum ipanema_state state, int cpu)
{
	switch(state) {
	case IPANEMA_READY:
	case IPANEMA_READY_TICK:
		return &per_cpu(ipanema_ready, cpu);
	default:
		return NULL;
	}
}

/* 
 * Check the validity of an ipanema transition
 */
static void check_ipanema_transition(struct task_struct *p,
				     enum ipanema_state next_state,
				     int next_cpu)
{
	enum ipanema_state prev_state = runtime_metadata(p)->current_state;
	int prev_cpu = p->cpu;

	switch(prev_state) {
	case IPANEMA_NOT_QUEUED:
		if (next_state != IPANEMA_READY)
			goto wrong_transition;
		break;
	case IPANEMA_READY:
		if (next_state == IPANEMA_NOT_QUEUED ||
		    next_state == IPANEMA_READY_TICK)
			goto wrong_transition;
		if (next_state == IPANEMA_MIGRATING)
			goto no_cpu_check;
		break;
	case IPANEMA_RUNNING:
		if (next_state == IPANEMA_NOT_QUEUED ||
		    next_state == IPANEMA_MIGRATING)
			goto wrong_transition;
		break;
	case IPANEMA_READY_TICK:
		if (next_state == IPANEMA_NOT_QUEUED ||
		    next_state == IPANEMA_MIGRATING ||
		    next_state == IPANEMA_READY)
			goto wrong_transition;
		break;
	case IPANEMA_BLOCKED:
	case IPANEMA_MIGRATING:
		if (next_state != IPANEMA_READY &&
		    next_state != IPANEMA_TERMINATED)
			goto wrong_transition;
		break;
	case IPANEMA_TERMINATED:
		goto wrong_transition;
	}

	if (prev_cpu != next_cpu)
		goto wrong_transition;

no_cpu_check:
	return;

wrong_transition:
	IPA_EMERG_SAFE("WARNING! Incorrect transition %s[%d] -> %s[%d]\n",
		       ipanema_state_to_str(prev_state), prev_cpu,
		       ipanema_state_to_str(next_state), next_cpu);
}

/* 
 * Move task p from its current runqueue to the runqueue attached to next_state
 * on next_cpu
 */
static void change_rq(struct task_struct *p, enum ipanema_state next_state,
		      int next_cpu)
{
	ipanema_rq *prev_rq = NULL, *next_rq = NULL;
	int prev_cpu;
	enum ipanema_state prev_state;

	prev_rq = runtime_metadata(p)->current_rq;
	prev_cpu = p->cpu;
	prev_state = runtime_metadata(p)->current_state;

	next_rq = get_rq(next_state, next_cpu);

	runtime_metadata(p)->current_rq = next_rq;
	runtime_metadata(p)->current_state = next_state;
		
	if (prev_rq) {
		lockdep_assert_held(&task_rq(p)->lock);
		p = ipanema_remove_task(prev_rq, p,
					ipanema_routines.order_process);
	}
	if (next_rq) {
		lockdep_assert_held(&cpu_rq(next_cpu)->lock);
		ipanema_add_task(next_rq, p,
				 ipanema_routines.order_process);
	}
}

/* 
 * Main function handling state change of an ipanema task
 */
void change_state(struct task_struct *p, enum ipanema_state next_state,
		  int next_cpu)
{
	int prev_cpu;
	enum ipanema_state prev_state;

	/* Safety checks */
	if (!p) {
		IPA_EMERG_SAFE("WARNING! Called change_state() with a null process! Exiting...\n");
		return;
	}

	if (!runtime_metadata(p)) {
		IPA_EMERG_SAFE("WARNING! Called change_state() with a process without ipanema_metadata! Exiting...\n");
		return;
	}

	/* Get current task fields */
	prev_cpu = p->cpu;
	prev_state = runtime_metadata(p)->current_state;
	
	/* Safety checks on parameters,
	 * if badly set, use the process' current values */
	if (next_cpu < 0)
		next_cpu = prev_cpu;
	if (next_state < 0)
		next_state = prev_state;

	/* If no change, return */
	if (prev_cpu == next_cpu && prev_state == next_state)
		return;

	if (unlikely(ipanema_fsm_log))
		pr_info("ipanema: [pid=%d] %s[%d] -> %s[%d]\n",
			p->pid, ipanema_state_to_str(prev_state), prev_cpu,
			ipanema_state_to_str(next_state), next_cpu);
	/* Check transition validity if necessary */
	if (unlikely(ipanema_fsm_check))
		check_ipanema_transition(p, next_state, next_cpu);

	/* Do the actual rq change */
	change_rq(p, next_state, next_cpu);


	/* Now, let's do transition specific handling */

	/* RUNNING -> x */
	if (prev_state == IPANEMA_RUNNING)
		per_cpu(ipanema_current, prev_cpu) = NULL;

	/* x -> RUNNING */
	if (next_state == IPANEMA_RUNNING) {
		if (per_cpu(ipanema_current, next_cpu)) {
			IPA_EMERG_SAFE("putting a task in RUNNING but there is already another task! We preempt it to avoid potential bugs.\n");
			change_state(per_cpu(ipanema_current, next_cpu),
				     IPANEMA_READY, next_cpu);
		}

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

	/* Let's check that we have someone RUNNING
	 * if not, trigger a resched */
	if (!per_cpu(ipanema_current, prev_cpu)
	    && cpu_rq(prev_cpu)->nr_running
	    && prev_cpu == next_cpu)
		resched_curr(cpu_rq(prev_cpu));
}
EXPORT_SYMBOL(change_state);

/* 
 * Return the number of tasks on the cpu (not only in SCHED_IPANEMA !!!!)
 */
int count(enum ipanema_state state, int cpu)
{
	if(state == IPANEMA_READY || state == IPANEMA_READY_TICK)
		return cpu_rq(cpu)->nr_running;
	return -1;
}
EXPORT_SYMBOL(count);

/* 
 * Return the first task in the runqueue attached to state on cpu
 */
struct task_struct *ipanema_first_of_state(enum ipanema_state state, int cpu)
{
	struct task_struct *result;
	ipanema_rq *rq = get_rq(state, cpu);

	if (rq) {
		result = ipanema_first_task(rq);
		return result;
	} else {
		return NULL;
	}
}

static void enqueue_task_ipanema(struct rq *rq,
				 struct task_struct *p,
				 int flags)
{
	struct process_event e = { .target = p };

	if (unlikely(ipanema_sched_class_log))
		pr_info("In enqueue_task_ipanema() [pid=%d, rq=%d]\n",
			p->pid, rq->cpu);

	/*
	 * We are in the middle of a migration. We don't need to do anything,
	 * just update rq->nr_running/count_ready
	 */
	if (task_on_rq_migrating(p))
		goto end;

	/*
	 * The thread doesn't even exist yet according to Ipanema. If it is
	 * switching to SCHED_IPANEMA, we handle it; elsewise, all we do
	 * is update nr_running/count_ready (at end)
	 */
	if (!runtime_metadata(p)) {
		if (!p->switching_classes)
			goto end;

		/* The thread is switching to SCHED_IPANEMA class,
		 * we must:
		 * - allocate its runtime metadata,
		 * - call its policy's new_prepare() routine to
		 *   initialize the per-policy metadata, but we ignore
		 *   the return value to avoid inconsistency, since it's
		 *   to late to choose a runqueue.
		 */
		p->ipanema_metadata.runtime_metadata =
			kcalloc(1, sizeof(*runtime_metadata(p)),
				GFP_ATOMIC);
		memset(runtime_metadata(p), 0,
		       sizeof(*runtime_metadata(p)));
		runtime_metadata(p)->current_state = IPANEMA_NOT_QUEUED;
		runtime_metadata(p)->current_rq = NULL;

		ipanema_routines.new_prepare(&e);
	}

	/*
	 * p->cpu has been set up by ipanema_new_prepare(), we now need to do
	 * the actual enqueueing by calling ipanema_new_place(), thus going
	 * from IPANEMA_NOT_QUEUED to IPANEMA_READY.
	 */
	if (runtime_metadata(p)->current_state == IPANEMA_NOT_QUEUED) {
		ipanema_routines.new_place(&e);
		goto end;
	}
	/*
	 * To unblock a task, a thread calls wake_up(), which calls
	 * try_to_wake_up(), which sets the task's state to TASK_WAKING and
	 * then calls enqueue_task(). Therefore, we're only in the presence of
	 * an true unblock() if the state is TASK_WAKING.
	 */
	if (p->state == TASK_WAKING) {
		ipanema_routines.unblock_place(&e);
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
		       ipanema_state_to_str(runtime_metadata(p)->current_state),
		       rq->cpu, rq, flags);

end:
	add_nr_running(rq, 1);
	per_cpu(count_ready, rq->cpu)++;
	IPA_DBG_SAFE("Enqueueing %p, nr_running=%d.\n", p, rq->nr_running);
}

static void dequeue_task_ipanema(struct rq *rq,
				 struct task_struct *p,
				 int flags)
{
	struct process_event e = { .target = p };

	if (unlikely(ipanema_sched_class_log))
		pr_info("In dequeue_task_ipanema() [pid=%d, rq=%d]\n",
			p->pid, rq->cpu);

	update_curr_ipanema(rq);

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
	if (!runtime_metadata(p)
	    || runtime_metadata(p)->current_state == IPANEMA_NOT_QUEUED) {
		goto end;
	}

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
		ipanema_routines.block(&e);
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
		ipanema_routines.terminate(&e);
		goto end;
	}

	/*
	 * The task is being dequeued because it's switching
	 * to another scheduling class. In this case too, we should
	 * call terminate. We must also free the runtime metadata,
	 * since it is useless now, and to avoid problems if the task switches
	 * bach to SCHED_IPANEMA class.
	 */
	if (p->switching_classes) {
		ipanema_routines.terminate(&e);
		kfree(runtime_metadata(p));
		p->ipanema_metadata.runtime_metadata = NULL;
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
		       ipanema_state_to_str(runtime_metadata(p)->current_state),
		       rq->cpu, rq, flags);

end:
	sub_nr_running(rq, 1);
	per_cpu(count_ready, rq->cpu)--;
	IPA_DBG_SAFE("Dequeueing %p, nr_running=%d, p->state=%16lx, "
		     "p->flags=%8x.\n",
		     p, rq->nr_running, p->state, p->flags);
}

static void yield_task_ipanema(struct rq *rq)
{
	struct process_event e = { .target = rq->curr };

	if (unlikely(ipanema_sched_class_log))
		pr_info("In yield_task_ipanema() [rq=%d]\n",
			rq->cpu);

	/*
	 * The process called yield(). Switch its state to IPANEMA_READY,
	 * schedule() is going to be called very soon.
	 */
	ipanema_routines.yield(&e);
	runtime_metadata(e.target)->just_yielded = 1;
}

static bool yield_to_task_ipanema(struct rq *rq,
				  struct task_struct *p,
				  bool preempt)
{
	if (unlikely(ipanema_sched_class_log))
		pr_info("In yield_to_task_ipanema() [pid=%d, rq=%d]\n",
			p->pid, rq->cpu);
	return 0;
}

static void check_preempt_wakeup(struct rq *rq,
				 struct task_struct *p,
				 int wake_flags)
{
	if (unlikely(ipanema_sched_class_log))
		pr_info("In check_preempt_wakeup() [pid=%d, rq=%d]\n",
			p->pid, rq->cpu);
}

static struct task_struct *pick_next_task_ipanema(struct rq *rq,
						  struct task_struct *prev,
						  struct rq_flags *rf)
{
	struct task_struct *result = NULL;

	if (unlikely(ipanema_sched_class_log))
		pr_info("In pick_next_task_ipanema() [pid=%d, rq=%d]\n",
			prev->pid, rq->cpu);

	if (per_cpu(ipanema_current, rq->cpu)) {
		result = per_cpu(ipanema_current, rq->cpu);
	} else if (ipanema_first_of_state(IPANEMA_READY, rq->cpu)) {
		/* TODO: add check with first. */
		ipanema_routines.schedule(rq->cpu);
		result = per_cpu(ipanema_current, rq->cpu);
	}

	if (!result)
		return NULL;

	/*
	 * Case 1: the next task we pick is the same as the previous one. I
	 * believe this can happen in two cases: the thread's quantum is over
	 * or the thread called yield(). In both cases, there won't be an
	 * actual preemption. We don't want to call put_prev_task() here because
	 * it may make prev IPANEMA_READY, even though it will be running.
	 */
	if (result == prev) {
		IPA_DBG_SAFE("We picked the same task as before! Don't "
			     "call put_prev_task!\n");
	}
	if (result != prev) {
		IPA_DBG_SAFE("Pick next -> %p %d.\n", result,
			     result ?
			     ipanema_routines.get_metric(result) : 0);

		put_prev_task(rq, prev);
		IPA_DBG_SAFE("put_prev_task() over.\n");

		result->se.exec_start = rq_clock_task(rq);
	}

	if (runtime_metadata(result)->current_state != IPANEMA_RUNNING) {
		IPA_EMERG_SAFE("The result of pick_next_task_ipanema() is not "
			       "in the IPANEMA_RUNNING state ! It's in state "
			       "%s instead. Switching to IPANEMA_RUNNING to "
			       "prevent issues, but we shouldn't be in this "
			       "situation!\n",
			       ipanema_state_to_str(runtime_metadata(result)->current_state));

		runtime_metadata(result)->current_state = IPANEMA_RUNNING;
	}

	return result;
}

static void put_prev_task_ipanema(struct rq *rq,
				  struct task_struct *prev)
{
	int state;
	struct process_event e = { .target = prev };

	if (unlikely(ipanema_sched_class_log))
		pr_info("In put_prev_task_ipanema() [pid=%d, rq=%d]\n",
			prev->pid, rq->cpu);

	/* Safety checks. Avoid using BUG_ON() to fail gracefully. */
	if (!prev || prev->sched_class != &ipanema_sched_class) {
		IPA_EMERG_SAFE("WARNING! At least one precondition not "
			       "verified in put_prev_task_ipanema() "
			       "[%d %d]\n",
			       !prev,
			       prev->sched_class != &ipanema_sched_class);

		return;
	}

	/* If we are switching class, ie. moving out from ipanema,
	 * dequeue_task_ipanema() already called terminate() and freed
	 * the task's runtime metadata, so we cannot access them.
	 * We just remove prev from ipanema_current if necessary.
	 * We don't call resched_curr() because the task will keep the cpu in
	 * its new sched_class.
	 */
	if (prev->switching_classes) {
		if (per_cpu(ipanema_current, prev->cpu) == prev)
			per_cpu(ipanema_current, prev->cpu) = NULL;
		return;
	}

	check_identical_rqs(rq, prev);
	update_curr_ipanema(rq);

	state = ipanema_get_current_state(prev);

	IPA_DBG_SAFE("In put_prev_task_ipanema() [%p on rq %d, state=%d].\n",
		     prev, rq->cpu, state);

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
			IPA_DBG_SAFE("Non-preempting put_prev_task()");
			return;
		}

		/*
	 	 * Case 1b: preemption! We should call preempt() but we don't
		 * have a preempt() event. So we just call yield().
		 */
		ipanema_routines.yield(&e);
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
		IPA_DBG_SAFE("In put_prev_task_ipanema() [prev=%p, rq=%d], "
			     "following a context switch from a transition to "
			     "the ready state in tick(). Going from READY_TICK "
			     "to READY.\n", prev, rq->cpu);
		runtime_metadata(prev)->current_state = IPANEMA_READY;
	/*
	 * Case 3: if we're already in the READY state, either a yield() event
	 * from a call to sched_yield() set us in this state, or we switched to
	 * ipanema sched_class.
	 */
	} else if (state == IPANEMA_READY) {
		/* Safety check. */
		if (!runtime_metadata(prev)->just_yielded) {
			IPA_EMERG_SAFE("WARNING! IPANEMA_READY in "
				       "put_prev_task_ipanema() not following "
				       "a yield().\n");
			return;
		}

		IPA_DBG_SAFE("In put_prev_task() following a "
			     "yield().\n");
		runtime_metadata(prev)->just_yielded = 0;
	/*
	 * Case 4: if we're in the BLOCKED state, a block() event (from
	 * try_to_wake_up() -> enqueue_task_ipanema()) must have set us
	 * in this state.
	 */
	} else if (state == IPANEMA_BLOCKED) {
		IPA_DBG_SAFE("Blocked in put_prev_task(), should follow a "
			     "block() event.\n");
	/*
	 * Case 5: the thread was terminated during its last dequeue. Don't
	 * do anything.
	 */
	} else if (state == IPANEMA_TERMINATED) {
		IPA_DBG_SAFE("Terminated in put_prev_task(), should follow a "
			     "terminate() event.\n");
	/*
	 * Case 6: the thread is migrating.
	 */
	} else if (state == IPANEMA_MIGRATING) {

	/*
	 * Case 7: we're in another state: shouldn't happen.
	 */
	} else {
		IPA_EMERG_SAFE("WARNING! Invalid state (%d) in "
			       "put_prev_task_ipanema().\n", state);
	}
}

#ifdef CONFIG_SMP
static int select_task_rq_ipanema(struct task_struct *p,
				  int prev_cpu,
				  int sd_flag,
				  int wake_flags)
{
	struct process_event e = { .target = p };

	if (unlikely(ipanema_sched_class_log))
		pr_info("In select_task_rq_ipanema() [pid=%d]\n",
			p->pid);

	/* Safety checks. */
	if (!p || p->sched_class != &ipanema_sched_class) {
		IPA_EMERG_SAFE("WARNING! Preconditions not fulfilled in "
			       "select_task_rq_ipanema() [%d %d]\n",
			       !p, p->sched_class != &ipanema_sched_class);
		return task_cpu(p);
	}

	/*
	 * FIXME: move this to enqueue_task_ipanema() (which is called just
	 * after select_task_ipanema()). It would avoid having to use the
	 * just_queued flag.
	 */
	if(!runtime_metadata(p)) {
		IPA_DBG_SAFE("GOOD! Creating runtime_metadata(p) in "
			     "select_task_rq_ipanema().\n");

		/*
		 * We have to use GFP_ATOMIC here, because we call
		 * sched_getscheduler() from inside a critical section, which
		 * makes us end up here.
		 */
		p->ipanema_metadata.runtime_metadata =
			kcalloc(1, sizeof(*runtime_metadata(p)), GFP_ATOMIC);
		memset(runtime_metadata(p), 0, sizeof(*runtime_metadata(p)));
		runtime_metadata(p)->current_state = IPANEMA_NOT_QUEUED;
		runtime_metadata(p)->current_rq = NULL;

		/*
		 * This is actually the correct place for calling new():
		 * select_task_rq_ipanema() is called just before
		 * enqueue_task_ipanema().
		 */
		return ipanema_routines.new_prepare(&e);

		/* return runtime_metadata(p)->current_cpu; */
	} else if (p->state == TASK_WAKING)
		return ipanema_routines.unblock_prepare(&e);

	return p->cpu;
}

static void migrate_task_rq_ipanema(struct task_struct *p)
{
	if (unlikely(ipanema_sched_class_log))
		pr_info("In migrate_task_rq_ipanema(), [pid=%d]\n",
			p->pid);
}

static void rq_online_ipanema(struct rq *rq)
{
	if (unlikely(ipanema_sched_class_log))
		pr_info("In rq_online_ipanema() [rq=%d]\n",
			rq->cpu);
}

static void rq_offline_ipanema(struct rq *rq)
{
	if (unlikely(ipanema_sched_class_log))
		pr_info("In rq_offline_ipanema() [rq=%d]\n",
			rq->cpu);
}

static void task_woken_ipanema(struct rq *this_rq, struct task_struct *p)
{
	if (unlikely(ipanema_sched_class_log))
		pr_info("in task_woken_ipanema() [pid=%d, rq=%d]\n",
			p->pid, this_rq->cpu);
}

static void task_dead_ipanema(struct task_struct *p)
{
	if (unlikely(ipanema_sched_class_log))
		pr_info("In task_dead_ipanema() [pid=%d]\n",
			p->pid);

	if (!p || p->sched_class != &ipanema_sched_class
	    || !runtime_metadata(p)) {
		IPA_DBG_SAFE("WARNING! Exiting task_dead_ipanema(), because it "
			     "was called on an invalid process, a non-ipanema "
			     "process, or a process whose metadata was not "
			     "initialized. [%p %d %p]", p,
			     p->sched_class != &ipanema_sched_class,
			     runtime_metadata(p));
	}

	/*
	 * We should decrease the reference counter on p, because we increased
	 * it in the IOCTL. This is assuming the IOCTL has indeed been called.
	 * Disabled for now, might cause issues.
	 */
//	put_task_struct(p);

	/* We should also free the thread's metadata here. */
//	kfree(metadata(p));

	kfree(runtime_metadata(p));
	p->ipanema_metadata.runtime_metadata = NULL;
}
#endif

static void set_curr_task_ipanema(struct rq *rq)
{
	if (unlikely(ipanema_sched_class_log))
		pr_info("In set_curr_task_ipanema() [rq=%d]\n",
			rq->cpu);

	/* Check that rq->curr is also ipanema_current and fix it.
	 * Happens when switching to SCHED_IPANEMA: the task is dequeued
	 * from the previous scheduling class queue, then the previous class'
	 * put_prev_task() is called, then the task is enqueued with
	 * enqueue_task_ipanema() which removes it from ipanema_current and
	 * puts it in READY state.
	 */
	if (per_cpu(ipanema_current, rq->cpu) != rq->curr)
		change_state(rq->curr, IPANEMA_RUNNING, rq->cpu);

	/* Update statistics. */
	rq->curr->se.exec_start = rq_clock_task(rq);
}

static void task_tick_ipanema(struct rq *rq,
			      struct task_struct *curr,
			      int queued)
{
	struct process_event e = { .target = curr };

	if (unlikely(ipanema_sched_class_log))
		pr_info("In task_tick_ipanema() [pid=%d, rq=%d]\n",
			curr->pid, rq->cpu);

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
//	check_identical_rqs(rq, curr);
	ipanema_routines.tick(&e);
}

static void task_fork_ipanema(struct task_struct *p)
{
	struct ipanema_metadata *md = &(p->ipanema_metadata);

	if (unlikely(ipanema_sched_class_log))
		pr_info("In task_fork_ipanema() [pid=%d]\n",
			p->pid);

	md->seen = 0;
	md->node_runqueue.__rb_parent_color = 0;
	md->node_runqueue.rb_right = NULL;
	md->node_runqueue.rb_left = NULL;
	md->runtime_metadata = NULL;
	md->policy_metadata = NULL;
}

static void prio_changed_ipanema(struct rq *rq,
				 struct task_struct *p,
				 int oldprio)
{
	if (unlikely(ipanema_sched_class_log))
		pr_info("In prio_changed_ipanema() [pid=%d, rq=%d]\n",
			p->pid, rq->cpu);
}

static void switched_from_ipanema(struct rq *rq, struct task_struct *p)
{
	if (unlikely(ipanema_sched_class_log))
		pr_info("In switched_from_ipanema() [pid=%d, rq=%d]\n",
			p->pid, rq->cpu);
}

static void switched_to_ipanema(struct rq *rq, struct task_struct *p)
{
	if (unlikely(ipanema_sched_class_log))
		pr_info("In switched_to_ipanema() [pid=%d, rq=%d]\n",
			p->pid, rq->cpu);

	if (rq->curr != p) {
		/*
		 * We can safely call resched_curr() here, because the rq lock
		 * is held.
		 */
		IPA_DBG_SAFE("Calling resched_curr().\n");
		lockdep_assert_held(&rq->lock);
		resched_curr(rq);
	}
}

static unsigned int get_rr_interval_ipanema(struct rq *rq,
					    struct task_struct *task)
{
	if (unlikely(ipanema_sched_class_log))
		pr_info("In get_rr_interval_ipanema() [pid=%d, rq=%d]\n",
			task->pid, rq->cpu);

	return (100 * HZ / 1000);
}

static void update_curr_ipanema(struct rq *rq)
{
	struct task_struct *curr = rq->curr;
	u64 delta_exec;

	if (unlikely(ipanema_sched_class_log))
		pr_info("In update_curr_ipanema() [rq=%d]\n",
			rq->cpu);

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
		IPA_DBG_SAFE("In task_change_group_ipanema() setting group.\n");
		break;

	case TASK_MOVE_GROUP:
		IPA_DBG_SAFE("In task_change_group_ipanema() moving group.\n");
		break;
	}
}
#endif

void run_rebalance_domains(struct softirq_action *h)
{
	if(ipanema_routines.balancing_select)
		ipanema_routines.balancing_select();
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

void init_sched_ipanema_late(void)
{
	ipanema_create_dev();
	ipanema_create_procs();
}

static int init_done = 0;
int nb_topology_levels = 0;

EXPORT_SYMBOL(nb_topology_levels);
DEFINE_PER_CPU(struct topology_level *, topology_levels);
EXPORT_SYMBOL(topology_levels);

static const struct cpumask *machine_mask(int cpu)
{
	return cpu_possible_mask;
}

sched_domain_mask_f topology_masks[] = { cpu_smt_mask,
					 cpu_coregroup_mask,
					 cpu_cpu_mask,
					 machine_mask };

#define NB_TOPOLOGY_LEVELS (sizeof(topology_masks) / sizeof(*topology_masks))

__init void init_sched_ipanema_class(void)
{
	int cpu, level;

	if(init_done)
		return;

	init_done = 1;

	for_each_possible_cpu(cpu) {
		per_cpu(ipanema_ready, cpu) = RB_ROOT;
	}

	open_softirq(SCHED_SOFTIRQ_IPANEMA, run_rebalance_domains);

	nb_topology_levels = NB_TOPOLOGY_LEVELS;
	for_each_possible_cpu(cpu) {
		per_cpu(topology_levels, cpu) =
			kcalloc(NB_TOPOLOGY_LEVELS,
				sizeof(*per_cpu(topology_levels, cpu)),
				GFP_ATOMIC);

		for(level = 0; level < NB_TOPOLOGY_LEVELS; level++) {
			struct topology_level *l =
				&(per_cpu(topology_levels, cpu)[level]);
			l->cores = topology_masks[level](cpu);
		}
	}

	if(ipanema_routines.init)
		ipanema_routines.init();
}
