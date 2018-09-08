#include "sched.h"
#include "ipanema_common.h"

#include <uapi/linux/sched/types.h>
#include <linux/spinlock.h>
#include <linux/percpu-rwsem.h>
#include <linux/module.h>
#include <linux/kref.h>

struct ipanema_module *ipanema_modules[MAX_IPANEMA_MODULES] = { 0 };
unsigned int num_ipanema_modules;

LIST_HEAD(ipanema_policies);
unsigned int num_ipanema_policies;
unsigned int ipanema_policies_id;

rwlock_t ipanema_rwlock;

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

	for (; i < num_ipanema_modules; i++)
		ipanema_modules[i] = ipanema_modules[i + 1];

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
	unsigned long flags, percpu_flags;
	unsigned int nr_users;

	/*
	 * Set module_name to the right position in str and change str from
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

	/*
	 * Get the cpulist from str. If cpulist is invalid:
	 * if cpulist = '*', use all cpus (wildcard);
	 * else if cpulist = 'r', remove policy;
	 * else, syntax error
	 */
	ret = cpulist_parse(str, &cores_allowed);
	if (ret != 0) {
		if (str[1] == '\n') {
			if (str[0] == '*')
				cpumask_copy(&cores_allowed, cpu_possible_mask);
			else if (str[0] == 'r')
				remove = 1;
			else {
				ret = -ESYNTAX;
				goto end_nolock;
			}
		} else {
			ret = -ESYNTAX;
			goto end_nolock;
		}
	}

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
	if (!exists && remove) {
		ret = -EINVAL;
		goto end;
	}
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
		}
		ret = -EMODULEINUSE;
		goto end;
	}

	/*
	 * If it already exists, change the allowed_cores mask and:
	 * - for removed cores, trigger core_removal event,
	 * - for added cores, trigger core_entry event
	 * after that, directly goto end
	 */
	if (exists) {
		routines = policy_cur->module->routines;
		cpumask_andnot(&removed_cores, &policy_cur->allowed_cores,
			       &cores_allowed);
		cpumask_andnot(&added_cores, &cores_allowed,
			       &policy_cur->allowed_cores);
		/*
		 * unset removed_cores from policy to prevent load-balancing and
		 * schedule, then call core_exit for removed cores
		 */
		cpumask_andnot(&policy_cur->allowed_cores,
			       &policy_cur->allowed_cores,
			       &removed_cores);
		for_each_cpu(cpu, &removed_cores) {
			raw_spin_lock_irqsave(&cpu_rq(cpu)->lock, percpu_flags);
			ipanema_core_exit(policy_cur, cpu);
			raw_spin_unlock_irqrestore(&cpu_rq(cpu)->lock,
						   percpu_flags);
		}
		/*
		 * call core_entry for added_cores, then set them in policy to
		 * enable load balancing and schedule on these cores
		 */
		for_each_cpu(cpu, &added_cores) {
			raw_spin_lock_irqsave(&cpu_rq(cpu)->lock, percpu_flags);
			ipanema_core_entry(policy_cur, cpu);
			raw_spin_unlock_irqrestore(&cpu_rq(cpu)->lock,
						   percpu_flags);
		}
		cpumask_or(&policy_cur->allowed_cores,
			   &policy_cur->allowed_cores,
			   &added_cores);
		goto end;
	}

	/* Create the policy instance and take a ref for the kernel module */
	if (!try_module_get(module->kmodule)) {
		ret = -EMODULENOTFOUND;
		goto end;
	}
	policy = kzalloc(sizeof(struct ipanema_policy), GFP_NOWAIT);
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
		raw_spin_lock_irqsave(&cpu_rq(cpu)->lock, percpu_flags);
		ipanema_core_entry(policy, cpu);
		raw_spin_unlock_irqrestore(&cpu_rq(cpu)->lock, percpu_flags);
	}

	/* Insert policy into active policies */
	list_add_tail(&policy->list, &ipanema_policies);
	num_ipanema_policies++;

end:
	write_unlock_irqrestore(&ipanema_rwlock, flags);
end_nolock:
	return ret;

free_policy:
	kfree(policy);
	return ret;
}
EXPORT_SYMBOL(ipanema_set_policy);

void debug_ipanema(void)
{
	ipanema_debug = 1;
}

enum ipanema_core_state ipanema_get_core_state(struct ipanema_policy *policy,
					       unsigned int core)
{
	struct core_event e = { .target = core };
	enum ipanema_core_state (*handler)(struct ipanema_policy *policy,
					   struct core_event *e);
	int res = 0;

	handler = policy->module->routines->get_core_state;

	if (handler)
		res = (*handler)(policy, &e);
	else
		IPA_EMERG_SAFE("%s: WARNING: invalid function pointer!\n",
			       __func__);

	return res;
}

int ipanema_new_prepare(struct process_event *e)
{
	struct task_struct *p = e->target;
	int core = task_cpu(p);
	struct ipanema_policy *policy;
	int (*handler)(struct ipanema_policy *policy_p,
		       struct process_event *e);
	unsigned long flags;

	/*
	 * we acquire this lock to prevent the policy from being removed before
	 * incrementing the refcount, and prevent change to the
	 * policy->allowed_cores mask, since hierarchy may be walked through by
	 * this event
	 */
	read_lock_irqsave(&ipanema_rwlock, flags);
	policy = ipanema_task_policy(p);
	if (!policy)
		return -1;

	kref_get(&policy->refcount);

	handler = policy->module->routines->new_prepare;

	if (!handler)
		IPA_EMERG_SAFE("%s: WARNING: invalid function pointer!\n",
			       __func__);
	else
		core = (*handler)(policy, e);
	read_unlock_irqrestore(&ipanema_rwlock, flags);

	return core;
}

void ipanema_new_place(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct ipanema_policy *policy;
	void (*handler)(struct ipanema_policy *policy_p,
			struct process_event *e);

	lockdep_assert_held(&task_rq(p)->lock);

	policy = ipanema_task_policy(p);
	handler = policy->module->routines->new_place;

	if (handler)
		(*handler)(policy, e);
	else
		IPA_EMERG_SAFE("%s: WARNING: invalid function pointer!\n",
			       __func__);
}

void ipanema_new_end(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct ipanema_policy *policy;
	void (*handler)(struct ipanema_policy *policy_p,
			struct process_event *e);

	policy = ipanema_task_policy(p);
	handler = policy->module->routines->new_end;

	if (handler)
		(*handler)(policy, e);
	else
		IPA_EMERG_SAFE("%s: WARNING: Invalid function pointer!\n",
			       __func__);
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

	policy = ipanema_task_policy(p);
	handler = policy->module->routines->tick;

	if (handler)
		(*handler)(policy, e);
	else
		IPA_EMERG_SAFE("%s: WARNING: Invalid function pointer!\n",
			       __func__);
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

	policy = ipanema_task_policy(p);
	handler = policy->module->routines->yield;

	if (handler)
		(*handler)(policy, e);
	else
		IPA_DBG_SAFE("%s: WARNING: Invalid function pointer\n",
			     __func__);
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

	policy = ipanema_task_policy(p);
	handler = policy->module->routines->block;

	if (handler)
		(*handler)(policy, e);
	else
		IPA_EMERG_SAFE("%s: WARNING: invalid function pointer!\n",
			       __func__);
}

int ipanema_unblock_prepare(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct ipanema_policy *policy;
	int core = task_cpu(p);
	int (*handler)(struct ipanema_policy *policy_p,
		       struct process_event *e);
	unsigned long flags;

	lockdep_assert_held(&p->pi_lock);

	policy = ipanema_task_policy(p);
	handler = policy->module->routines->unblock_prepare;

	/*
	 * we acquire this lock to prevent a change to the
	 * policy->allowed_cores mask, since hierarchy may be walked through by
	 * this event
	 */
	read_lock_irqsave(&ipanema_rwlock, flags);
	if (handler)
		core = (*handler)(policy, e);
	else
		IPA_EMERG_SAFE("%s: WARNING: invalid function pointer!\n",
			       __func__);

	read_unlock_irqrestore(&ipanema_rwlock, flags);

	return core;
}

void ipanema_unblock_place(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct ipanema_policy *policy;
	void (*handler)(struct ipanema_policy *policy_p,
			struct process_event *e);

	lockdep_assert_held(&task_rq(p)->lock);

	policy = ipanema_task_policy(p);
	handler = policy->module->routines->unblock_place;

	if (handler)
		(*handler)(policy, e);
	else
		IPA_EMERG_SAFE("%s: WARNING: invalid function pointer!\n",
			       __func__);
}

void ipanema_unblock_end(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct ipanema_policy *policy;
	void (*handler)(struct ipanema_policy *policy_p,
			struct process_event *e);

	lockdep_assert_held(&p->pi_lock);

	policy = ipanema_task_policy(p);
	handler = policy->module->routines->unblock_end;

	if (handler)
		(*handler)(policy, e);
	else
		IPA_EMERG_SAFE("%s: WARNING: invalid function pointer!\n",
			       __func__);
}

void ipanema_terminate(struct process_event *e)
{
	struct task_struct *p = e->target;
	struct rq *rq = task_rq(p);
	struct ipanema_policy *policy;
	void (*handler)(struct ipanema_policy *policy_p,
			struct process_event *e);

	lockdep_assert_held(&rq->lock);

	policy = ipanema_task_policy(p);
	handler = policy->module->routines->terminate;

	if (handler)
		(*handler)(policy, e);
	else
		IPA_EMERG_SAFE("%s: WARNING: invalid function pointer!\n",
			       __func__);

	ipanema_task_policy(p) = NULL;
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
		IPA_EMERG_SAFE("%s: WARNING: invalid function pointer!\n",
			       __func__);
}

void ipanema_core_entry(struct ipanema_policy *policy, unsigned int core)
{
	struct core_event e = { .target = core };
	void (*handler)(struct ipanema_policy *policy, struct core_event *e);

	handler = policy->module->routines->core_entry;

	if (handler)
		(*handler)(policy, &e);
	else
		IPA_EMERG_SAFE("%s: WARNING: invalid function pointer!\n",
			       __func__);
}

void ipanema_core_exit(struct ipanema_policy *policy, unsigned int core)
{
	struct core_event e = { .target = core };
	void (*handler)(struct ipanema_policy *policy, struct core_event *e);

	handler = policy->module->routines->core_exit;

	if (handler)
		(*handler)(policy, &e);
	else
		IPA_EMERG_SAFE("%s: WARNING: invalid function pointer!\n",
			       __func__);
}

void ipanema_newly_idle(struct ipanema_policy *policy, unsigned int core,
			struct rq_flags *rf)
{
	struct core_event e = { .target = core };
	void (*handler)(struct ipanema_policy *policy, struct core_event *e);
	struct rq *rq = cpu_rq(core);

	handler = policy->module->routines->newly_idle;

	if (handler) {
		/*
		 * When newly_idle() is called by schedule(), the rq->lock is
		 * held. However, the handler may want to lock multiple rq->lock
		 * (idle balancing for example). To allow this, we unpin and
		 * unlock rq->lock before. We will put everything back to normal
		 * upon returning from the handler.
		 */
		rq_unpin_lock(rq, rf);
		raw_spin_unlock(&rq->lock);

		(*handler)(policy, &e);

		raw_spin_lock(&rq->lock);
		rq_repin_lock(rq, rf);
	} else
		IPA_EMERG_SAFE("%s: WARNING: invalid function pointer!\n",
			       __func__);
}

void ipanema_enter_idle(struct ipanema_policy *policy, unsigned int core)
{
	struct core_event e = { .target = core };
	void (*handler)(struct ipanema_policy *policy, struct core_event *e);

	handler = policy->module->routines->enter_idle;

	if (handler)
		(*handler)(policy, &e);
	else
		IPA_EMERG_SAFE("%s: WARNING: invalid function pointer!\n",
			       __func__);
}

void ipanema_exit_idle(struct ipanema_policy *policy, unsigned int core)
{
	struct core_event e = { .target = core };
	void (*handler)(struct ipanema_policy *policy, struct core_event *e);

	handler = policy->module->routines->exit_idle;

	if (handler)
		(*handler)(policy, &e);
	else
		IPA_EMERG_SAFE("%s: WARNING: invalid function pointer!\n",
			       __func__);
}

void ipanema_balancing_select(void)
{
	unsigned int core = smp_processor_id();
	struct ipanema_policy *policy;
	struct core_event e = { .target = core };
	void (*handler)(struct ipanema_policy *policy_p,
			struct core_event *e);
	unsigned long flags;

	read_lock_irqsave(&ipanema_rwlock, flags);
	list_for_each_entry(policy, &ipanema_policies, list) {
		if (cpumask_test_cpu(core, &policy->allowed_cores)) {
			handler = policy->module->routines->balancing_select;
			if (handler)
				(*handler)(policy, &e);
		}
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
	bool (*handler)(const struct sched_attr *attr);

	handler = policy->module->routines->checkparam_attr;
	if (handler)
		return handler(attr);
	return true;
}

void __setparam_ipanema(struct task_struct *p, const struct sched_attr *attr)
{
	void (*handler)(struct task_struct *p, const struct sched_attr *attr);
	struct ipanema_policy *policy = ipanema_task_policy(p);

	handler =  policy->module->routines->setparam_attr;
	if (handler)
		handler(p, attr);
}

void __getparam_ipanema(struct task_struct *p, struct sched_attr *attr)
{
	void (*handler)(struct task_struct *p, struct sched_attr *attr);
	struct ipanema_policy *policy = ipanema_task_policy(p);

	handler =  policy->module->routines->getparam_attr;
	if (handler)
		handler(p, attr);
}

bool ipanema_attr_changed(struct task_struct *p, const struct sched_attr *attr)
{
	bool (*handler)(struct task_struct *p, const struct sched_attr *attr);
	struct ipanema_policy *policy = ipanema_task_policy(p);

	handler =  policy->module->routines->attr_changed;
	if (handler)
		return handler(p, attr);
	return false;
}
