#include "ipanema_common.h"
#include "sched.h"

#include <uapi/linux/sched/types.h>
#include <linux/spinlock.h>
#include <linux/percpu-rwsem.h>
#include <linux/module.h>
#include <linux/kref.h>

struct ipanema_module *ipanema_modules[MAX_IPANEMA_MODULES] = { 0 };
unsigned int num_ipanema_modules = 0;

LIST_HEAD(ipanema_policies);
unsigned int num_ipanema_policies = 0;
unsigned int ipanema_policies_id = 0;

rwlock_t ipanema_rwlock;

void ipanema_lock_core(unsigned int c)
{
	raw_spinlock_t *lock = &cpu_rq(c)->lock;

	raw_spin_lock(lock);
}
EXPORT_SYMBOL(ipanema_lock_core);

int ipanema_trylock_core(unsigned int c)
{
	raw_spinlock_t *lock = &cpu_rq(c)->lock;

	return raw_spin_trylock(lock);
}
EXPORT_SYMBOL(ipanema_trylock_core);

void ipanema_unlock_core(unsigned int c)
{
	raw_spinlock_t *lock = &cpu_rq(c)->lock;

	raw_spin_unlock(lock);
}
EXPORT_SYMBOL(ipanema_unlock_core);

int ipanema_add_module(struct ipanema_module *module)
{
	unsigned long flags;
	unsigned int i, id;
	int ret = 0;

	write_lock_irqsave(&ipanema_rwlock, flags);

	if (num_ipanema_modules == MAX_IPANEMA_MODULES) {
		ret = -ETOOMANYMODULES;
		goto end;
	}

	for (i = 0; i < num_ipanema_modules; i++) {
		if (!strcmp(ipanema_modules[i]->name, module->name)) {
			ret = -EINVAL;
			goto end;
		}
	}

	id = num_ipanema_modules++;
	ipanema_modules[id] = module;

end:
	write_unlock_irqrestore(&ipanema_rwlock, flags);

	if (ret == 0)
		pr_info("ipanema: new module '%s'\n", module->name);

	return ret;
}
EXPORT_SYMBOL(ipanema_add_module);

void ipanema_policy_free(struct kref *ref)
{
	struct ipanema_policy *policy = container_of(ref, struct ipanema_policy,
						     refcount);
	kfree(policy);
}

int ipanema_remove_module(struct ipanema_module *module)
{
	unsigned long flags;
	int i, found = 0;
	struct ipanema_policy *policy;
	int ret = 0;

	write_lock_irqsave(&ipanema_rwlock, flags);

	for (i = 0; i < num_ipanema_modules; i++) {
		if (ipanema_modules[i] == module) {
			found = 1;
			break;
		}
	}

	if (!found) {
		ret = -EMODULENOTFOUND;
		goto end;
	}

	/* If policies use this module, we fail */
	list_for_each_entry(policy, &ipanema_policies, list) {
		if (policy->module == module) {
			ret = -EMODULEINUSE;
			goto end;
		}
	}

	for (; i < num_ipanema_modules; i++) {
		ipanema_modules[i] = ipanema_modules[i + 1];
	}

	num_ipanema_modules--;

end:
	write_unlock_irqrestore(&ipanema_rwlock, flags);

	if (ret == 0)
		pr_info("ipanema: removed module '%s'\n", module->name);

	return ret;
}
EXPORT_SYMBOL(ipanema_remove_module);

int ipanema_set_policy(char *str)
{
	struct ipanema_module *module = NULL;
	struct ipanema_module_routines *routines = NULL;
	struct ipanema_policy *policy = NULL, *policy_cur = NULL;
	cpumask_t cores_allowed, removed_cores, added_cores;
	char *module_name = NULL;
	int ret = 0, i, cpu, exists = 0, remove = 0;
	unsigned long flags;
	unsigned int nr_users;

	pr_info("ipanema_set_policy(%s)\n", str);

	/*
	 * Set module_name to the right position in str and chage str from
	 * "cpulist:name" to "cpulist\nname"
	 * This way, we can use cpulist_parse() to get the mask afterwards
	 * without any copy (cpulist_parse() uses '\n' as a separator)
	 */
	module_name = strchrnul(str, ':');
	if (*module_name != ':') {
		ret = -ESYNTAX;
		goto end_nolock;
	}
	*module_name = '\n';
	module_name++;

	/* Get the cpulist from str. If invalid, try to remove policy */
	ret = cpulist_parse(str, &cores_allowed);
	if (ret != 0)
		remove = 1;

	if (remove)
		pr_info("ipanema_set_policy(): module_name='%s', cpulist='remove'\n",
			module_name);
	else
		pr_info("ipanema_set_policy(): module_name='%s', cpulist='%*pbl'\n",
			module_name, cpumask_pr_args(&cores_allowed));

	/*
	 * From now on, we read or write to ipanema_modules and ipanema_policies
	 * We need to take a lock for writing
	 */
	write_lock_irqsave(&ipanema_rwlock, flags);

	/* Check if module exists as an ipanema module */
	for (i = 0; i < num_ipanema_modules; i++) {
		if (strcmp(module_name, ipanema_modules[i]->name) == 0) {
			module = ipanema_modules[i];
			break;
		}
	}

	if (!module) {
		ret = -EMODULENOTFOUND;
		goto end;
	}

	/* Check if policy already exists */
	list_for_each_entry(policy_cur, &ipanema_policies, list) {
		if (!strcmp(policy_cur->name, module_name)) {
			exists = 1;
		        break;
		}
	}

	/*
	 * If policy exists and cpulist = remove, if policy is still used by
	 * tasks, fail. Else, remove from ipanema_policies and decrement kref
	 * to free the policy.
	 */
	if (exists && remove) {
		nr_users = kref_read(&policy_cur->refcount);
		if (nr_users == 1) {
			/* No task uses policy_cur, remove it */
			list_del(&policy_cur->list);
			kref_put(&policy_cur->refcount, ipanema_policy_free);
			num_ipanema_policies--;
			module_put(policy_cur->module->kmodule);
			ret = 0;
			goto end;
		} else
			pr_info("ipanema: removal of policy %s failed: in use by %u tasks\n",
				policy_cur->name, nr_users - 1);
		ret = -EMODULEINUSE;
		goto end;
	}

	/*
	 * If it already exists, compare the current and the new cpu masks,
	 * for removed cores, trigger core_removal event, change the mask and
	 * for added cores, trigger core_entry event and return
	 */
	if (exists) {
		pr_info("ipanema_set_policy(): policy '%s' found. Modifying...\n",
			policy_cur->name);
		routines = policy_cur->module->routines;
		cpumask_andnot(&removed_cores, &policy_cur->allowed_cores,
			       &cores_allowed);
		for_each_cpu(cpu, &removed_cores) {
			ipanema_routines.core_exit(policy_cur, cpu);
		}
		cpumask_copy(&policy_cur->allowed_cores, &cores_allowed);
		cpumask_andnot(&added_cores, &cores_allowed,
			       &policy_cur->allowed_cores);
		for_each_cpu(cpu, &added_cores) {
			ipanema_routines.core_entry(policy_cur, cpu);
		}
		goto end;
	}

	/* Create the policy instance and take a ref for the kernel module */
	if (!try_module_get(module->kmodule)) {
		ret = -EMODULENOTFOUND;
		goto end;
	}
	policy = kzalloc(sizeof(struct ipanema_policy), GFP_KERNEL);
	if (!policy) {
		ret = -ENOMEM;
		goto end;
	}
	policy->id = ipanema_policies_id++;
	cpumask_copy(&policy->allowed_cores, &cores_allowed);
	policy->name = module->name;
	policy->module = module;
	INIT_LIST_HEAD(&policy->list);
	kref_init(&policy->refcount);

	/* Initialize the policy */
	routines = policy->module->routines;
	if (!routines) {
		ret = -EINVAL;
		goto free_policy;
	}
	if (!num_ipanema_policies && !routines->can_be_default(policy)) {
		ret = -EINVALIDDEFAULT;
		goto free_policy;
	}
	ret = routines->init(policy);
	if (ret < 0) {
		ret = -ENOMEM;
		goto free_policy;
	}
	for_each_cpu(cpu, &cores_allowed) {
		ipanema_routines.core_entry(policy, cpu);
	}

	/* Insert policy into active policies */
	list_add_tail(&policy->list, &ipanema_policies);
	num_ipanema_policies++;

end:
	write_unlock_irqrestore(&ipanema_rwlock, flags);
end_nolock:
	pr_info("ipanema_set_policy(): returning with %d\n", ret);
	return ret;

free_policy:
	kfree(policy);
	pr_info("ipanema_set_policy(): returning with %d\n", ret);
	return ret;
}
EXPORT_SYMBOL(ipanema_set_policy);

void debug_ipanema(void)
{
	ipanema_debug = 1;
}

int ipanema_order_process(struct task_struct *a, struct task_struct *b)
{
	int res = 0;
	struct ipanema_policy *policy;
	int (*handler)(struct ipanema_policy *policy_p,
		       struct task_struct *a,
		       struct task_struct *b);

	if (list_empty(&ipanema_policies)) {
		IPA_EMERG_SAFE("ipanema_order_process(): ipanema_policies == NULL\n");
		return 0;
	}

	if (a->ipanema_metadata.policy != b->ipanema_metadata.policy) {
		IPA_EMERG_SAFE("ipanema_order_process(): tasks a and b have different ipanema policies [%p, %p]\n",
			       a->ipanema_metadata.policy, b->ipanema_metadata.policy);
		BUG();
	}

	policy = a->ipanema_metadata.policy;
	handler = policy->module->routines->order_process;

	if (!handler)
		IPA_EMERG_SAFE("ipanema_order_process(): WARNING: invalid function pointer!\n");
	else
		res = (*handler)(policy, a, b);

	return res;
}

int ipanema_get_metric(struct task_struct *a)
{
	int res = 0;
	struct ipanema_policy *policy;
	int (*handler)(struct ipanema_policy *policy_p,
		       struct task_struct *a);

	if (list_empty(&ipanema_policies)) {
		IPA_EMERG_SAFE("ipanema_order_process(): ipanema_policies == NULL\n");
		return 0;
	}

	policy = a->ipanema_metadata.policy;
	handler = policy->module->routines->get_metric;

	if (!handler)
		IPA_EMERG_SAFE("ipanema_get_metric(): WARNING: invalid function pointer!\n");
	else
		res = (*handler)(policy, a);

	return res;
}

int ipanema_new_prepare(struct process_event *e)
{
	struct task_struct *p = e->target;
	int core = task_cpu(p);
	struct ipanema_policy *policy;
	int (*handler)(struct ipanema_policy *policy_p,
		       struct process_event *e);

	if (list_empty(&ipanema_policies)) {
		IPA_EMERG_SAFE("ipanema_new_prepare(): WARNING: ipanema_policies == NULL\n");
		return core;
	}

	policy = p->ipanema_metadata.policy;
	kref_get(&policy->refcount);
	handler = policy->module->routines->new_prepare;

	if (!handler)
		IPA_EMERG_SAFE("ipanema_new_prepare(): WARNING: invalid function pointer!\n");
	else
		core = (*handler)(policy, e);

	return core;
}

void ipanema_new_place(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct ipanema_policy *policy;
	void (*handler)(struct ipanema_policy *policy_p,
			struct process_event *e);

	if (list_empty(&ipanema_policies)) {
		IPA_EMERG_SAFE("ipanema_new_place(): ipanema_policies == NULL\n");
		return;
	}

	lockdep_assert_held(&task_rq(p)->lock);

	policy = p->ipanema_metadata.policy;
	handler = policy->module->routines->new_place;

	if (handler)
		(*handler)(policy, e);
	else {
		IPA_EMERG_SAFE("ipanema_new_place(): WARNING: invalid function pointer!\n");
		/* Default behavior */
		/* change_state(p, IPANEMA_READY, p->cpu); */
	}
}

void ipanema_new_end(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct ipanema_policy *policy;
	void (*handler)(struct ipanema_policy *policy_p,
			struct process_event *e);

	if (list_empty(&ipanema_policies)) {
		IPA_EMERG_SAFE("ipanema_new_end(): ipanema_policies == NULL\n");
		return;
	}

	policy = p->ipanema_metadata.policy;
	handler = policy->module->routines->new_end;

	if (handler)
		(*handler)(policy, e);
	else
		IPA_EMERG_SAFE("ipanema_new_end(): WARNING: Invalid function pointer!\n");
}

void ipanema_tick(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct rq *rq = task_rq(p);
	struct ipanema_policy *policy;
	void (*handler)(struct ipanema_policy *policy_p,
			struct process_event *e);

	/*
	 * Make sure the rq lock is held, because we will need to call
	 * resched_curr() to schedule another thread.
	 */
	lockdep_assert_held(&rq->lock);

	if (list_empty(&ipanema_policies)) {
		IPA_EMERG_SAFE("ipanema_tick(): ipanema_policies == NULL\n");
		return;
	}

	policy = p->ipanema_metadata.policy;
	handler = policy->module->routines->tick;

	if (handler)
		(*handler)(policy, e);
	else
		IPA_EMERG_SAFE("ipanema_tick(): WARNING: Invalid function pointer!\n");
}

void ipanema_yield(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct rq *rq = task_rq(p);
	struct ipanema_policy *policy;
	void (*handler)(struct ipanema_policy *policy_p,
			struct process_event *e);

	/*
	 * Make sure the rq lock is held, because we will need to call
	 * resched_curr() to schedule another thread.
	 */
	lockdep_assert_held(&rq->lock);

	if (list_empty(&ipanema_policies)) {
		IPA_EMERG_SAFE("ipanema_yield(): ipanema_policies == NULL\n");
		return;
	}

	policy = p->ipanema_metadata.policy;
	handler = policy->module->routines->yield;

	if (handler)
		(*handler)(policy, e);
	else {
		IPA_DBG_SAFE("ipanema_yield(): WARNING: Invalid function pointer\n");
		/* change_state(p, IPANEMA_READY, p->cpu); */
	}
}

void ipanema_block(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct rq *rq = task_rq(p);
	struct ipanema_policy *policy;
	void (*handler)(struct ipanema_policy *policy_p,
			struct process_event *e);

	/*
	 * Make sure the rq lock is held, because we will need to call
	 * resched_curr() to schedule another thread.
	 */
	lockdep_assert_held(&rq->lock);

	if (list_empty(&ipanema_policies)) {
		IPA_EMERG_SAFE("ipanema_block(): ipanema_policies == NULL\n");
		return;
	}

	policy = p->ipanema_metadata.policy;
	handler = policy->module->routines->block;

	if (handler)
		(*handler)(policy, e);
	else {
		IPA_EMERG_SAFE("ipanema_block(): WARNING: invalid function pointer!\n");
		/* Default behavior */
		/* change_state(p, IPANEMA_BLOCKED, p->cpu); */
	}
}

int ipanema_unblock_prepare(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct ipanema_policy *policy;
	int core = task_cpu(p);
	int (*handler)(struct ipanema_policy *policy_p,
		       struct process_event *e);

	lockdep_assert_held(&p->pi_lock);

	if (list_empty(&ipanema_policies)) {
		IPA_EMERG_SAFE("ipanema_unblock_prepare(): ipanema_policies == NULL\n");
		return core;
	}

	policy = p->ipanema_metadata.policy;
	handler = policy->module->routines->unblock_prepare;

	if (handler)
		core = (*handler)(policy, e);
	else
		IPA_EMERG_SAFE("ipanema_unblock_prepare(): WARNING: invalid function pointer!\n");

	return core;
}

void ipanema_unblock_place(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct ipanema_policy *policy;
	void (*handler)(struct ipanema_policy *policy_p,
			struct process_event *e);

	lockdep_assert_held(&task_rq(p)->lock);

	if (list_empty(&ipanema_policies)) {
		IPA_EMERG_SAFE("ipanema_unblock_place(): ipanema_policies == NULL\n");
		return;
	}

	policy = p->ipanema_metadata.policy;
	handler = policy->module->routines->unblock_place;

	if (handler)
		(*handler)(policy, e);
	else {
		IPA_EMERG_SAFE("ipanema_unblock_place(): WARNING: invalid function pointer!\n");
		/* Default behavior */
		/* change_state(p, IPANEMA_READY, p->cpu); */
	}
}

void ipanema_unblock_end(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct ipanema_policy *policy;
	void (*handler)(struct ipanema_policy *policy_p,
			struct process_event *e);

	lockdep_assert_held(&p->pi_lock);

	if (list_empty(&ipanema_policies)) {
		IPA_EMERG_SAFE("ipanema_unblock_end(): ipanema_policies == NULL\n");
		return;
	}

	policy = p->ipanema_metadata.policy;
	handler = policy->module->routines->unblock_end;

	if (handler)
		(*handler)(policy, e);
	else
		IPA_EMERG_SAFE("ipanema_unblock_end(): WARNING: invalid function pointer!\n");
}

void ipanema_terminate(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct rq *rq = task_rq(p);
	struct ipanema_policy *policy;
	void (*handler)(struct ipanema_policy *policy_p,
			struct process_event *e);

	lockdep_assert_held(&rq->lock);

	if (list_empty(&ipanema_policies)) {
		IPA_EMERG_SAFE("ipanema_terminate(): ipanema_policies == NULL\n");
		return;
	}

	policy = p->ipanema_metadata.policy;
	handler = policy->module->routines->terminate;

	if (handler)
		(*handler)(policy, e);
	else
		IPA_EMERG_SAFE("ipanema_terminate(): WARNING: invalid function pointer!\n");

	kref_put(&policy->refcount, ipanema_policy_free);
}

void ipanema_schedule(struct ipanema_policy *policy, unsigned int core)
{
	struct rq *rq = cpu_rq(core);
	void (*handler)(struct ipanema_policy *policy_p, unsigned int cpu);

	/* IRQs are apparently disabled. */
	WARN_ON(!irqs_disabled());

	/*
	 * We *must* hold the rq lock here, otherwise we can make a ready task
	 * running while another thread is stealing it.
	 */
	lockdep_assert_held(&rq->lock);

	handler = policy->module->routines->schedule;
	if (handler)
		(*handler)(policy, core);
	else
		IPA_EMERG_SAFE("ipanema_schedule(): WARNING: invalid function pointer!\n");
}

void ipanema_core_entry(struct ipanema_policy *policy, int core) {
	struct core_event e = { .target = core };
	void (*handler)(struct ipanema_policy *policy, struct core_event *e);

	handler = policy->module->routines->core_entry;

	if (handler)
		(*handler)(policy, &e);
	else
		IPA_EMERG_SAFE("ipanema_core_entry(): WARNING: invalid function pointer!\n");
}

void ipanema_core_exit(struct ipanema_policy *policy, int core) {
	struct core_event e = { .target = core };
	void (*handler)(struct ipanema_policy *policy, struct core_event *e);

	handler = policy->module->routines->core_exit;

	if (handler)
		(*handler)(policy, &e);
	else
		IPA_EMERG_SAFE("ipanema_core_exit(): WARNING: invalid function pointer!\n");
}

void ipanema_balancing_select(void)
{
	unsigned int core = smp_processor_id();
	struct ipanema_policy *policy;
	struct core_event e = { .target = core };
	void (*handler)(struct ipanema_policy *policy_p,
			struct core_event *e);

	read_lock(&ipanema_rwlock);
	list_for_each_entry(policy, &ipanema_policies, list) {
		handler = policy->module->routines->balancing_select;
		if (handler)
			(*handler)(policy, &e);
	}
	read_unlock(&ipanema_rwlock);
}

void ipanema_init(void)
{
	rwlock_init(&ipanema_rwlock);
}

struct task_struct *ipanema_get_task_of(void *proc)
{
	struct ipanema_metadata *ipanema;

	ipanema = container_of(proc, struct ipanema_metadata, policy_metadata);
	return container_of(ipanema, struct task_struct, ipanema_metadata);
}
EXPORT_SYMBOL(ipanema_get_task_of);

struct ipanema_routines ipanema_routines = {
	.order_process = ipanema_order_process,
	.get_metric = ipanema_get_metric,
	.new_prepare = ipanema_new_prepare,
	.new_place = ipanema_new_place,
	.new_end = ipanema_new_end,
	.tick = ipanema_tick,
	.yield = ipanema_yield,
	.block = ipanema_block,
	.unblock_prepare = ipanema_unblock_prepare,
	.unblock_place = ipanema_unblock_place,
	.unblock_end = ipanema_unblock_end,
	.terminate = ipanema_terminate,
	.schedule = ipanema_schedule,
	.init = ipanema_init,
	.balancing_select = ipanema_balancing_select,
	.core_entry = ipanema_core_entry,
	.core_exit = ipanema_core_exit,
};
