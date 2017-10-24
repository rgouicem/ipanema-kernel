#define LINUX

#include <linux/delay.h>
#include <linux/ipanema.h>
#include <linux/module.h>
#include <linux/slab.h>

/****
 * Ipanema: "dummy" scheduler.
 *
 * A scheduling policy that does literally nothing.
 */

static char *name = "dummy";
static struct ipanema_module *module;

static int ipanema_dum_order_process(struct ipanema_policy *policy,
				     struct task_struct *a,
				     struct task_struct *b)
{
	/*
	 * FIXME: some processes may never be scheduled, and therefore they
	 * won't be visible in e.g., ps. What we need to do here is to implement
	 * something similar to what is done in ipanema_{seq,ran,fil}.c.
	 */
	return 0;
}

static int ipanema_dum_get_metric(struct ipanema_policy *policy,
				  struct task_struct *a)
{
	return 0;
}

static bool ipanema_dum_attach(struct ipanema_policy *policy,
			       struct task_struct *task,
			       char *command)
{
	return true;
}

static int ipanema_dum_new_prepare(struct ipanema_policy *policy,
				   struct process_event *e)
{
	return e->target->cpu;
}

static void ipanema_dum_new_place(struct ipanema_policy *policy,
				  struct process_event *e)
{
	change_state(e->target, IPANEMA_READY, e->target->cpu);
}

static void ipanema_dum_new_end(struct ipanema_policy *policy,
				  struct process_event *e)
{
}

static void ipanema_dum_tick(struct ipanema_policy *policy,
			     struct process_event *e)
{
}

static void ipanema_dum_yield(struct ipanema_policy *policy,
			      struct process_event *e)
{
	change_state(e->target, IPANEMA_READY, e->target->cpu);
}

static void ipanema_dum_block(struct ipanema_policy *policy,
			      struct process_event *e)
{
	change_state(e->target, IPANEMA_BLOCKED, e->target->cpu);
}

static int ipanema_dum_unblock_prepare(struct ipanema_policy *policy,
					struct process_event *e)
{
	return e->target->cpu;
}

static void ipanema_dum_unblock_place(struct ipanema_policy *policy,
				      struct process_event *e)
{
	change_state(e->target, IPANEMA_READY, e->target->cpu);
}

static void ipanema_dum_unblock_end(struct ipanema_policy *policy,
				    struct process_event *e)
{
}

static void ipanema_dum_terminate(struct ipanema_policy *policy,
				  struct process_event *e)
{
	change_state(e->target, IPANEMA_TERMINATED, e->target->cpu);
}

static void ipanema_dum_schedule(struct ipanema_policy *policy, int cpu)
{
	change_state(ipanema_first_of_state(IPANEMA_READY, cpu), IPANEMA_RUNNING, cpu);
}

static void ipanema_dum_balancing_select(struct ipanema_policy *policy,
					 struct core_event *e)
{
}

static void ipanema_dum_core_entry(struct ipanema_policy *policy,
				   struct core_event *e)
{
}

static int ipanema_dum_init(struct ipanema_policy *policy)
{
	return 0;
}

// TODO: call me
static int ipanema_dum_free_metadata(struct ipanema_policy *policy)
{
	return 0;
}

static int ipanema_dum_can_be_default(struct ipanema_policy *policy)
{
	return true;
}

struct ipanema_module_routines ipanema_dum_routines = {
	.order_process		= ipanema_dum_order_process,
	.get_metric		= ipanema_dum_get_metric,
	.new_prepare		= ipanema_dum_new_prepare,
	.new_place		= ipanema_dum_new_place,
	.new_end        	= ipanema_dum_new_end,
	.tick			= ipanema_dum_tick,
	.yield			= ipanema_dum_yield,
	.block			= ipanema_dum_block,
	.unblock_prepare	= ipanema_dum_unblock_prepare,
	.unblock_place   	= ipanema_dum_unblock_place,
	.unblock_end    	= ipanema_dum_unblock_end,
	.terminate		= ipanema_dum_terminate,
	.schedule		= ipanema_dum_schedule,
	.balancing_select	= ipanema_dum_balancing_select,
	.core_entry		= ipanema_dum_core_entry,
	.init			= ipanema_dum_init,
	.free_metadata		= ipanema_dum_free_metadata,
	.can_be_default		= ipanema_dum_can_be_default,
	.attach			= ipanema_dum_attach
};

int ipanema_dum_init_module(void)
{
	int res;

	module = kcalloc(1, sizeof(struct ipanema_module), GFP_ATOMIC);
	if (!module)
		return -ENOMEM;

	module->name = name;
	module->routines = &ipanema_dum_routines;

	if ((res = ipanema_add_module(module))) {
		switch (res) {
		case -ETOOMANYMODULES:
			IPA_DBG_SAFE("Couldn't load the 'dummy' scheduler, "
				     "because there were too many modules "
				     "loaded. No module should be loaded "
				     "before the 'dummy' scheduler!'.\n");
			break;

		case -EINVAL:
			IPA_DBG_SAFE("Unable to load the 'dummy' scheduler. "
				     "A module named 'dummy' was already "
				     "loaded! No module should be loaded "
				     "before the 'dummy' scheduler.\n");
			break;

		default:
			IPA_DBG_SAFE("Couldn't load the 'dummy' scheduler.\n");
		}

//		kfree(module);
		return res;
	}

	return 0;
}

MODULE_LICENSE("GPL");
