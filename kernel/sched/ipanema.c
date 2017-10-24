#include "ipanema_common.h"
#include "sched.h"

#include <linux/spinlock.h>
#include <linux/percpu-rwsem.h>
#include <linux/module.h>

struct ipanema_module *ipanema_modules[MAX_IPANEMA_MODULES] = { 0 };
int num_ipanema_modules = 0;

struct ipanema_policy **ipanema_policies;
int num_ipanema_policies;

static int parse_policies_str(char *str, struct ipanema_policy **policies,
			      int *num_policies);
static int parse_core_str(char *cores_str, char **cores);

rwlock_t ipanema_rwlock;

void ipanema_core_entry(struct ipanema_policy *policy_p, int core);

static DEFINE_PER_CPU(spinlock_t, ipa_core_lock);

void ipanema_lock_core(int c)
{
	raw_spinlock_t *lock = &cpu_rq(c)->lock;

	raw_spin_lock(lock);
}
EXPORT_SYMBOL(ipanema_lock_core);

int ipanema_trylock_core(int c)
{
	raw_spinlock_t *lock = &cpu_rq(c)->lock;

	return raw_spin_trylock(lock);
}
EXPORT_SYMBOL(ipanema_trylock_core);

void ipanema_unlock_core(int c)
{
	raw_spinlock_t *lock = &cpu_rq(c)->lock;

	raw_spin_unlock(lock);
}
EXPORT_SYMBOL(ipanema_unlock_core);

int ipanema_add_module(struct ipanema_module *module)
{
	unsigned long flags;
	int i, id;

	write_lock_irqsave(&ipanema_rwlock, flags);

	if (!ipanema_policies) {
		/* Zero-fill the array to detect overflows more easily. */
		ipanema_policies =
			kcalloc(MAX_IPANEMA_POLICIES,
				sizeof(struct ipanema_policy *),
				GFP_ATOMIC);

		if (!ipanema_policies)
			goto enomem;

		ipanema_policies[0] = NULL;
		num_ipanema_policies = 0;
	}

	if (num_ipanema_modules == MAX_IPANEMA_MODULES)
		goto etoomanymodules;

	for (i = 0; i < num_ipanema_modules; i++) {
		if (!strcmp(ipanema_modules[i]->name, module->name))
			goto einval;
	}

	id = num_ipanema_modules++;
	ipanema_modules[id] = module;

	IPA_DBG_SAFE("Added a module with id = %d and name = \"%s\".\n",
		     id, module->name);

	write_unlock_irqrestore(&ipanema_rwlock, flags);
	return 0;

enomem:
	write_unlock_irqrestore(&ipanema_rwlock, flags);
	return -ENOMEM;

etoomanymodules:
	write_unlock_irqrestore(&ipanema_rwlock, flags);
	return -ETOOMANYMODULES;

einval:
	write_unlock_irqrestore(&ipanema_rwlock, flags);
	return -EINVAL;
}
EXPORT_SYMBOL(ipanema_add_module);

int ipanema_remove_module(struct ipanema_module *module)
{
	unsigned long flags;
	int i, found = 0, used = 0;
	struct ipanema_policy **policies_p;

	write_lock_irqsave(&ipanema_rwlock, flags);

	for (i = 0; i < num_ipanema_modules; i++) {
		if (ipanema_modules[i] == module) {
			found = 1;
			break;
		}
	}

	if (!found)
		goto emodulenotfound;

	policies_p = ipanema_policies;

	while (*policies_p) {
		if ((*policies_p)->module == module) {
			used = 1;
			break;
		}

		policies_p++;
	}

	if (used)
		goto emoduleinuse;

	for (; i < num_ipanema_modules; i++) {
		ipanema_modules[i] = ipanema_modules[i + 1];
	}

	num_ipanema_modules--;

	write_unlock_irqrestore(&ipanema_rwlock, flags);
	return 0;

emodulenotfound:
	write_unlock_irqrestore(&ipanema_rwlock, flags);
	return -EMODULENOTFOUND;

emoduleinuse:
	write_unlock_irqrestore(&ipanema_rwlock, flags);
	return -EMODULEINUSE;
}
EXPORT_SYMBOL(ipanema_remove_module);

int ipanema_set_policies(char *policies_str)
{
	unsigned long flags;
	int res, len, module_found, i, num_tmp_policies = 0, name_match,
	  cant_be_default, core;
	struct ipanema_policy **tmp_policies, **policies_p;
	struct ipanema_module_routines *routines;

	write_lock_irqsave(&ipanema_rwlock, flags);

	tmp_policies = kcalloc(MAX_IPANEMA_POLICIES,
			       sizeof(struct ipanema_policy *),
			       GFP_ATOMIC);

	if (!tmp_policies) {
		res = -ENOMEM;
		goto enomem1;
	}

	tmp_policies[0] = NULL;

	IPA_DBG_SAFE("Called parse_policies_str() with arguments %s and %p.\n",
		     policies_str, tmp_policies);

	if ((res = parse_policies_str(policies_str, tmp_policies,
				      &num_tmp_policies)) < 0)
		goto eparsing;

	IPA_DBG_SAFE("Successfully parsed string. Now filling the 'module'"
				 " field for each policy.\n");

	/*
	 * Parsing the 'policies' string worked. We have a valid tmp_policies
	 * array.  All we need to do now is to fill the 'module' field for each
	 * policy.
	 */
	policies_p = tmp_policies;

	while (*policies_p) {
		module_found = 0;

		IPA_DBG_SAFE("Looking for module for the %s command.\n",
			     (*policies_p)->command);

		for (i = 0; i < num_ipanema_modules; i++) {
			len = strlen(ipanema_modules[i]->name);
			IPA_DBG_SAFE("Comparing with module name: %s.\n",
				     ipanema_modules[i]->name);

			name_match = !strncmp((*policies_p)->command,
					      ipanema_modules[i]->name, len);

			if (name_match) {
				routines = ipanema_modules[i]->routines;
				cant_be_default =
					!routines->can_be_default(*policies_p);

				if (i == 0 && cant_be_default) {
					IPA_DBG_SAFE("Error: the first policy "
						     "cannot be a default "
						     "policy!\n");
					res = -EINVALIDDEFAULT;
					goto einvaliddefault;
				}

				IPA_DBG_SAFE("Match!\n");
				module_found = 1;
				(*policies_p)->module = ipanema_modules[i];

				IPA_DBG_SAFE("policy->data = %p\n",
					     (*policies_p)->data);

				res = routines->init(*policies_p);
				if (res < 0) {
					res = -ENOMEM;
					goto enomem2;
				}

				for_each_possible_cpu(core) {
					if ((*policies_p)->cores[core]) {
						ipanema_core_entry(*policies_p, core);
					}
				}

				IPA_DBG_SAFE("policy->data = %p\n",
					     (*policies_p)->data);

				break;
			}

			IPA_DBG_SAFE("Not matching...\n");
		}

		if (!module_found) {
			res = -EMODULENOTFOUND;
			goto emodulenotfound;
		}

		policies_p++;
	}

	IPA_DBG_SAFE("All modules found. Freeing up stuff...\n");

	/*
	 * Everything went well. Free the ipanema_policies array, and replace it
	 * with the newly built tmp_policies array.
	 */
	policies_p = ipanema_policies;

	if (!policies_p) {
		IPA_DBG_SAFE("ipanema_policies was NULL... shouldn't happen! "
			     "Returning zero anyway.\n");

		write_unlock_irqrestore(&ipanema_rwlock, flags);
		return 0;
	}

	while (*policies_p) {
		kfree((*policies_p)->command);
		kfree((*policies_p));
		policies_p++;
	}

	kfree(ipanema_policies);

	IPA_DBG_SAFE("Freed ipanema_policies.\n");

	ipanema_policies = tmp_policies;
	num_ipanema_policies = num_tmp_policies;

	IPA_DBG_SAFE("Replaced ipanema_policies with the newly built "
		     "array.\n");

	write_unlock_irqrestore(&ipanema_rwlock, flags);
	return 0;

eparsing:
	kfree(tmp_policies);
	write_unlock_irqrestore(&ipanema_rwlock, flags);
	return res;

einvaliddefault:
emodulenotfound:
enomem2:
	/*
	 * Parsing the 'policies' worked, but one of the policies requested does
	 * not correspond to a loaded module. Free the tmp_policies array and
	 * return -EINVAL.
	 */
	policies_p = tmp_policies;

	while (*policies_p) {
		kfree((*policies_p)->command);
		kfree((*policies_p));
		policies_p++;
	}

	kfree(tmp_policies);

enomem1:
	write_unlock_irqrestore(&ipanema_rwlock, flags);
	return res;
}

void debug_ipanema(void)
{
   ipanema_debug = 1;
}

static int parse_policies_str(char *policies_str,
			      struct ipanema_policy **policies,
			      int *num_policies)
{
	int i, j, k, res = 0;
	char *in_b, *in_p, *pol_str, *pol_str_b, *pol_str_p;
	char *cores_str, *pol_command, *cores;
	struct ipanema_policy **policies_p;
	char *used_cores;

	used_cores = kcalloc(num_possible_cpus(), sizeof(char), GFP_ATOMIC);
	if (!used_cores)
		goto enomem1;

	in_b = in_p = kstrdup(policies_str, GFP_ATOMIC);
	if (!in_b)
		goto enomem2;

	i = 0;

	pol_str = strsep(&in_p, ";");

	while (pol_str && pol_str[0] != '\0') {
		if (i >= MAX_IPANEMA_POLICIES) {
			res = -ETOOMANYPOLICIES;
			goto etoomanypolicies;
		}

		pol_str_b = pol_str_p = kstrdup(pol_str, GFP_ATOMIC);
		if (!pol_str_b)
			goto enomem3;

		policies[i] = kcalloc(1, sizeof(struct ipanema_policy),
				      GFP_ATOMIC);
		if (!policies)
			goto enomem4;

		cores_str = strsep(&pol_str_p, ":");
		if (!cores_str)
			goto eparsing;

		IPA_DBG_SAFE("Parsing cores_str=%s.\n", cores_str);

		if ((res = parse_core_str(cores_str, &cores)) < 0)
			goto eparsing;

		pol_command = strsep(&pol_str_p, ":");
		if (!pol_command || pol_str_p != NULL) {
			res = -ESYNTAX;
			goto eparsing;
		}

		IPA_DBG_SAFE("Creating policies[%d] with cores=", i);
		for (j = 0; j < num_possible_cpus(); j++)
			IPA_DBG_SAFE("%d", cores[j]);
		IPA_DBG_SAFE(" and pol_command=%s.\n", pol_command);

		policies[i]->cores = cores;
		policies[i]->n_online_cores = 0;

		for (k = 0; k < num_online_cpus(); k++)
			if (cores[k]) policies[i]->n_online_cores++;

		policies[i]->command = kstrdup(pol_command, GFP_ATOMIC);
		if (!policies[i]->command)
			goto enomem5;

		kfree(pol_str_b);

		pol_str = strsep(&in_p, ";");

		i++;
	}

	policies[i] = NULL;
	*num_policies = i;

	IPA_DBG_SAFE("policies[%d] = NULL, num_policies = %d.\n",
		     i, *num_policies);

	for (i = 0; i < num_possible_cpus(); i++)
		used_cores[i] = 0;

	policies_p = policies;

	IPA_DBG_SAFE("Checking for overlaps.\n");

	while (*policies_p) {
		IPA_DBG_SAFE("Checking for overlaps for command '%s'.\n",
					 (*policies_p)->command);

		for (j = 0; j < num_possible_cpus(); j++) {
			IPA_DBG_SAFE("Checking core %d out of %d (%p).\n",
				     j, num_possible_cpus(),
				     (*policies_p)->cores);

			used_cores[j] += (*policies_p)->cores[j];

			IPA_DBG_SAFE("New value = %d.\n", used_cores[j]);

			if (used_cores[j] > 1) {
				IPA_DBG_SAFE("overlap found.\n");
				res = -EOVERLAP;
				goto eoverlap;
			}
		}

		policies_p++;
	}

	IPA_DBG_SAFE("No overlap found.\n");

	kfree(in_b);
	kfree(used_cores);

	IPA_DBG_SAFE("Successfully leaving parse_policies_str().\n");
	return 0;

eparsing:
	kfree(policies[i]);

	policies[i] = NULL;
	kfree(pol_str_b);

etoomanypolicies:
eoverlap:
	policies_p = policies;

	while (*policies_p) {
		kfree((*policies_p)->command);
		kfree((*policies_p));
		policies_p++;
	}

	policies[0] = NULL;

	kfree(in_b);
	kfree(used_cores);

	return res;

enomem5:
	kfree(policies[i]);
	policies[i] = NULL;
enomem4:
	kfree(pol_str_b);
enomem3:
	policies_p = policies;

	while (*policies_p) {
		kfree((*policies_p)->command);
		kfree((*policies_p));
		policies_p++;
	}

	policies[0] = NULL;

	kfree(in_b);

enomem2:
	kfree(used_cores);
enomem1:
	return -ENOMEM;
}

static int parse_core_str(char *cores_str, char **cores)
{
	int len, n_dashes, dash_pos, i, j, res;
	long core, start, end;
	char *cores_str_b, *cores_str_p, *core_group_str;

	*cores = kcalloc(num_possible_cpus(), sizeof(char), GFP_ATOMIC);
	if (!(*cores))
		goto enomem1;

	/* Asterik: all cores */
	if (cores_str[0] == '*' && cores_str[1] == '\0') {
		for (i = 0; i < num_possible_cpus(); i++) (*cores)[i] = 1;
		return 0;
	}

	cores_str_b = cores_str_p = kstrdup(cores_str, GFP_ATOMIC);
	if (!cores_str_b)
		goto enomem2;

	/* Commas */
	while ((core_group_str = strsep(&cores_str_p, ","))) {
		len = strlen(core_group_str);

		n_dashes = 0;

		/* Dash(es) */
		for (i = 0; i < len; i++) {
			if (core_group_str[i] == '-') {
				n_dashes++;
				dash_pos = i;
				break;
			}
		}

		switch (n_dashes) {
		case 0:
			res = kstrtol(core_group_str, 0, &core);

			if (res < 0)
				goto esyntax;

			if (core < 0 || core >= num_possible_cpus())
				goto ebounds;

			(*cores)[core] = 1;
			break;

		case 1:
			core_group_str[i] = '\0';
			res = kstrtol(core_group_str, 0, &start);
			res |= kstrtol(core_group_str + dash_pos + 1, 0, &end);

			if (res < 0)
				goto esyntax;

			if (start < 0 || start >= num_possible_cpus()
				|| end < 0 || end >= num_possible_cpus()
				|| start > end) {
				goto ebounds;
			}

			for (j = start; j < end + 1; j++) {
				(*cores)[j] = 1;
			}

			break;

		default:
			kfree(*cores);
			*cores = NULL;

			goto esyntax;
		}

		i++;
	}

	kfree(cores_str_b);
	return 0;

ebounds:
	kfree(cores_str_b);
	return -EBOUNDS;

esyntax:
	kfree(cores_str_b);
	return -ESYNTAX;

enomem2:
	kfree(*cores);
enomem1:
	return -ENOMEM;
}

int ipanema_order_process(struct task_struct *a, struct task_struct *b)
{
	unsigned long flags;
	int res = 0, core = task_cpu(a);
	struct ipanema_policy **policies_p;
	int i = 0;
	int (*order_process_function)(struct ipanema_policy *policy_p,
				      struct task_struct *a,
				      struct task_struct *b);

	IPA_DBG_SAFE("In ipanema_order_process().\n");

	if (core != smp_processor_id()) {
		IPA_DBG_SAFE("Called ipanema_order_process() for a remote core "
			     "(core =  %d, current core = %d).\n", core,
			     smp_processor_id());
	}

	if (!ipanema_policies)
		return 0;

	read_lock_irqsave(&ipanema_rwlock, flags);

	policies_p = ipanema_policies;

	while (*policies_p) {
		/* Is this policy taking care of the current core? */
		if ((*policies_p)->cores[core]) {
			order_process_function =
				(*policies_p)->module->routines->order_process;

			if (!order_process_function)
				IPA_EMERG_SAFE("WARNING! Invalid function "
					       "pointer!\n");
			else
				res = (*order_process_function)(*policies_p,
								a, b);

			read_unlock_irqrestore(&ipanema_rwlock, flags);

			return res;
		}

		policies_p++;

		if (i++ > 4)
			IPA_DBG_SAFE("Possible infinite loop?\n");
	}

	read_unlock_irqrestore(&ipanema_rwlock, flags);

	return 0;
}

int ipanema_get_metric(struct task_struct *a)
{
	unsigned long flags;
	int res = 0, core = task_cpu(a);
	struct ipanema_policy **policies_p;
	int i = 0;
	int (*get_metric_function)(struct ipanema_policy *policy_p,
				   struct task_struct *a);

	IPA_DBG_SAFE("In ipanema_get_metric().\n");

	if (core != smp_processor_id()) {
		IPA_DBG_SAFE("Called ipanema_get_metric for a remote core "
			     "(core = %d, current core = %d).\n", core,
			     smp_processor_id());
	}

	read_lock_irqsave(&ipanema_rwlock, flags);

	if (!ipanema_policies) return 0;

	policies_p = ipanema_policies;

	while (*policies_p) {
		/* Is this policy taking care of the current core? */
		if ((*policies_p)->cores[core]) {
			get_metric_function =
				(*policies_p)->module->routines->get_metric;

			if (!get_metric_function)
				IPA_EMERG_SAFE("WARNING! Invalid function "
					       "pointer!\n");
			else
				res = (*get_metric_function)(*policies_p, a);

			read_unlock_irqrestore(&ipanema_rwlock, flags);

			return res;
		}

		policies_p++;

		if (i++ > 4)
			IPA_DBG_SAFE("Possible infinite loop?\n");
	}

	read_unlock_irqrestore(&ipanema_rwlock, flags);

	return 0;
}

int ipanema_new_prepare(struct process_event *e)
{
	unsigned long flags;
	int core = ipanema_get_current_cpu(e->target);
	struct ipanema_policy **policies_p;
	int i = 0;
	int (*new_function)(struct ipanema_policy *policy_p,
			    struct process_event *e);

	/*
	 * task_cpu() may not be up to date here: we may just have set
	 * current_cpu to the CPU we want to wake up on in change_state4().
	 */
	// if(task_cpu(e->target) != ipanema_get_current_cpu(e->target))
	// {
	//	 IPA_EMERG_SAFE("WARNING! task_cpu(e->target)=%d "
	//		 "and ipanema_get_current_cpu(e->target)=%d in %s.\n",
	//		 task_cpu(e->target), ipanema_get_current_cpu(e->target),
	//		 __FUNCTION__);
	// }

	/*
	 * No need to hold the rq lock in ipanema_new(). We never perform actual
	 * migrations, in the worst case we simply control where the thread wakes
	 * up.
	 */

	if (core != smp_processor_id()) {
		IPA_DBG_SAFE("Called ipanema_new_prepare for a remote core (core = %d, current core = %d).\n",
			     core, smp_processor_id());
	}

	if (!ipanema_policies)
		return core;

	IPA_DBG_SAFE("ipanema_policies wasn't NULL.\n");

	policies_p = ipanema_policies;

	read_lock_irqsave(&ipanema_rwlock, flags);

	while (*policies_p) {
		IPA_DBG_SAFE("Checking whether policy '%s' is responsible for core %d.\n",
			     (*policies_p)->command, core);

		/* Is this policy taking care of the current core? */
		if ((*policies_p)->cores[core]) {
			IPA_DBG_SAFE("It is. module=%p.\n",
				     (*policies_p)->module);
			IPA_DBG_SAFE("It is. routines=%p.\n",
				     (*policies_p)->module->routines);
			IPA_DBG_SAFE("It is. new_prepare()=%p.\n",
				     (*policies_p)->module->routines->new_prepare);

			new_function = (*policies_p)->module->routines->new_prepare;

			if (!new_function)
				IPA_EMERG_SAFE("WARNING! Invalid function pointer!\n");
			else
				core = (*new_function)(*policies_p, e);

			read_unlock_irqrestore(&ipanema_rwlock, flags);

			return core;
		}

		policies_p++;

		if (i++ > 4)
			IPA_DBG_SAFE("Possible infinite loop?\n");
	}

	read_unlock_irqrestore(&ipanema_rwlock, flags);

	/* Default behavior */
	/* change_state(e->target, IPANEMA_READY); */

	return core;
}

void ipanema_new_place(struct process_event *e)
{
	unsigned long flags;
	int core = ipanema_get_current_cpu(e->target);
	struct ipanema_policy **policies_p;
	int i = 0;
	void (*new_function)(struct ipanema_policy *policy_p,
			     struct process_event *e);

	if (core != smp_processor_id()) {
		IPA_DBG_SAFE("Called ipanema_new_place for a remote core (core = %d, current core = %d).\n",
			     core, smp_processor_id());
	}

	if (!ipanema_policies)
		return;

	IPA_DBG_SAFE("ipanema_policies wasn't NULL.\n");

	policies_p = ipanema_policies;

	lockdep_assert_held(&task_rq(e->target)->lock);

	read_lock_irqsave(&ipanema_rwlock, flags);

	while (*policies_p) {
		IPA_DBG_SAFE("Checking whether policy '%s' is responsible for core %d.\n",
			     (*policies_p)->command, core);

		/* Is this policy taking care of the current core? */
		if ((*policies_p)->cores[core]) {
			IPA_DBG_SAFE("It is. module=%p.\n",
				     (*policies_p)->module);
			IPA_DBG_SAFE("It is. routines=%p.\n",
				     (*policies_p)->module->routines);
			IPA_DBG_SAFE("It is. new_place()=%p.\n",
				     (*policies_p)->module->routines->new_place);

			new_function = (*policies_p)->module->routines->new_place;

			if (!new_function)
				IPA_EMERG_SAFE("WARNING! Invalid function pointer!\n");
			else
				(*new_function)(*policies_p, e);

			read_unlock_irqrestore(&ipanema_rwlock, flags);

			return;
		}

		policies_p++;

		if (i++ > 4)
			IPA_DBG_SAFE("Possible infinite loop?\n");
	}

	read_unlock_irqrestore(&ipanema_rwlock, flags);

	/* Default behavior */
	change_state(e->target, IPANEMA_READY, e->target->cpu);

	return;
}

void ipanema_new_end(struct process_event *e)
{
	unsigned long flags;
	int core = ipanema_get_current_cpu(e->target);
	struct ipanema_policy **policies_p;
	int i = 0;
	void (*new_function)(struct ipanema_policy *policy_p,
			     struct process_event *e);

	if (core != smp_processor_id()) {
		IPA_DBG_SAFE("Called ipanema_new_end for a remote core (core = %d, current core = %d).\n",
			     core, smp_processor_id());
	}

	if (!ipanema_policies)
		return;

	IPA_DBG_SAFE("ipanema_policies wasn't NULL.\n");

	policies_p = ipanema_policies;

	read_lock_irqsave(&ipanema_rwlock, flags);

	while (*policies_p) {
		IPA_DBG_SAFE("Checking whether policy '%s' is responsible for core %d.\n",
			     (*policies_p)->command, core);

		/* Is this policy taking care of the current core? */
		if ((*policies_p)->cores[core]) {
			IPA_DBG_SAFE("It is. module=%p.\n",
				     (*policies_p)->module);
			IPA_DBG_SAFE("It is. routines=%p.\n",
				     (*policies_p)->module->routines);
			IPA_DBG_SAFE("It is. new_end()=%p.\n",
				     (*policies_p)->module->routines->new_end);

			new_function = (*policies_p)->module->routines->new_end;

			if (!new_function)
				IPA_EMERG_SAFE("WARNING! Invalid function pointer!\n");
			else
				(*new_function)(*policies_p, e);

			read_unlock_irqrestore(&ipanema_rwlock, flags);

			return;
		}

		policies_p++;

		if (i++ > 4)
			IPA_DBG_SAFE("Possible infinite loop?\n");
	}

	read_unlock_irqrestore(&ipanema_rwlock, flags);

	/* Default behavior */
	/* change_state(e->target, IPANEMA_READY); */

	return;
}

void ipanema_tick(struct process_event *e)
{
	int core = ipanema_get_current_cpu(e->target);
	struct ipanema_policy **policies_p;
	int i = 0;
	struct rq *rq;
	void (*tick_function)(struct ipanema_policy *policy_p,
			      struct process_event *e);

	/* Make sure that task_cpu() accesses updated info. */
	if(task_cpu(e->target) != ipanema_get_current_cpu(e->target)) {
		IPA_EMERG_SAFE("WARNING! task_cpu(e->target)=%d and "
			       "ipanema_get_current_cpu(e->target)=%d in %s.\n",
			       task_cpu(e->target),
			       ipanema_get_current_cpu(e->target),
			       __FUNCTION__);
	}

	/*
	 * Make sure the rq lock is held, because we will need to call
	 * resched_curr() to schedule another thread.
	 */
	rq = cpu_rq(ipanema_get_current_cpu(e->target));
	lockdep_assert_held(&rq->lock);

	/* Was tick() called for a remote core? */
	if (core != smp_processor_id()) {
		IPA_DBG_SAFE("Called ipanema_tick for a remote core (core = "
			     "%d, current core = %d).\n", core,
			     smp_processor_id());
	}

	if (!ipanema_policies) return;

	/* Disabling IRQs shouldn't be needed in the tick IRQ handler... */
	read_lock(&ipanema_rwlock);

	policies_p = ipanema_policies;

	while (*policies_p) {
		/* Is this policy taking care of the current core? */
		if ((*policies_p)->cores[core]) {
			tick_function = (*policies_p)->module->routines->tick;

			if (!tick_function)
				IPA_EMERG_SAFE("WARNING! Invalid function "
					       "pointer!\n");
			else
				(*tick_function)(*policies_p, e);

			read_unlock(&ipanema_rwlock);

			return;
		}

		policies_p++;

		if (i++ > 4)
			IPA_DBG_SAFE("Possible infinite loop?\n");
	}

	read_unlock(&ipanema_rwlock);
}

void ipanema_yield(struct process_event *e)
{
	unsigned long flags;
	int core = ipanema_get_current_cpu(e->target);
	struct ipanema_policy **policies_p;
	int i = 0;
	struct rq *rq;
	void (*ipanema_yield)(struct ipanema_policy *policy_p,
			      struct process_event *e);

	/* Make sure that task_cpu() accesses updated info. */
	if(task_cpu(e->target) != ipanema_get_current_cpu(e->target)) {
		IPA_EMERG_SAFE("WARNING! task_cpu(e->target)=%d and "
			       "ipanema_get_current_cpu(e->target)=%d in %s.\n",
			       task_cpu(e->target),
			       ipanema_get_current_cpu(e->target),
			       __FUNCTION__);
	}

	/*
	 * Make sure the rq lock is held, because we will need to call
	 * resched_curr() to schedule another thread.
	 */
	rq = cpu_rq(ipanema_get_current_cpu(e->target));
	lockdep_assert_held(&rq->lock);

	IPA_DBG_SAFE("In ipanema_yield().\n");

	if (core != smp_processor_id()) {
		IPA_DBG_SAFE("Called ipanema_yield for a remote core (core =  "
			     "%d, current core = %d).\n", core,
			     smp_processor_id());
	}

	if (!ipanema_policies) return;

	read_lock_irqsave(&ipanema_rwlock, flags);

	policies_p = ipanema_policies;

	while (*policies_p) {
		/* Is this policy taking care of the current core? */
		if ((*policies_p)->cores[core]) {
			ipanema_yield = (*policies_p)->module->routines->yield;

			(*ipanema_yield)(*policies_p, e);

			read_unlock_irqrestore(&ipanema_rwlock, flags);

			return;
		}

		policies_p++;

		if (i++ > 4)
			IPA_DBG_SAFE("Possible infinite loop?\n");
	}

	read_unlock_irqrestore(&ipanema_rwlock, flags);

	// Default behavior
	change_state(e->target, IPANEMA_READY, e->target->cpu);
}

void ipanema_block(struct process_event *e)
{
	unsigned long flags;
	int core = ipanema_get_current_cpu(e->target);
	struct ipanema_policy **policies_p;
	int i = 0;
	struct rq *rq;
	void (*block_function)(struct ipanema_policy *policy_p,
			       struct process_event *e);

	/* Make sure that task_cpu() accesses updated info. */
	if(task_cpu(e->target) != ipanema_get_current_cpu(e->target)) {
		IPA_EMERG_SAFE("WARNING! task_cpu(e->target)=%d and "
			       "ipanema_get_current_cpu(e->target)=%d in %s.\n",
			       task_cpu(e->target),
			       ipanema_get_current_cpu(e->target),
			       __FUNCTION__);
	}

	/*
	 * Make sure the rq lock is held, because we will need to call
	 * resched_curr() to schedule another thread.
	 */
	rq = cpu_rq(ipanema_get_current_cpu(e->target));
	lockdep_assert_held(&rq->lock);

	IPA_DBG_SAFE("In ipanema_block().\n");

	if (core != smp_processor_id()) {
		IPA_DBG_SAFE("Called ipanema_block for a remote core (core = "
			     "%d, current core = %d).\n", core,
			     smp_processor_id());
	}

	if (!ipanema_policies)
		return;

	read_lock_irqsave(&ipanema_rwlock, flags);

	policies_p = ipanema_policies;

	while (*policies_p) {
		IPA_DBG_SAFE("Checking whether policy '%s' is responsible "
			     "for core %d.\n", (*policies_p)->command, core);

		/* Is this policy taking care of the current core? */
		if ((*policies_p)->cores[core]) {
			IPA_DBG_SAFE("It is. module=%p.\n",
				     (*policies_p)->module);

			block_function = (*policies_p)->module->routines->block;

			if (!block_function)
				IPA_EMERG_SAFE("WARNING! Invalid function "
					       "pointer!\n");
			else
				(*block_function)(*policies_p, e);

			read_unlock_irqrestore(&ipanema_rwlock, flags);

			return;
		}

		policies_p++;

		if (i++ > 4)
			IPA_DBG_SAFE("Possible infinite loop?\n");
	}

	read_unlock_irqrestore(&ipanema_rwlock, flags);

	/* Default behavior */
	change_state(e->target, IPANEMA_BLOCKED, e->target->cpu);
}

int ipanema_unblock_prepare(struct process_event *e)
{
	unsigned long flags;
	int core = ipanema_get_current_cpu(e->target);
	struct ipanema_policy **policies_p;
	int i = 0;
	/* struct rq *rq; */
	int (*unblock_function)(struct ipanema_policy *policy_p,
				struct process_event *e);
	/* struct task_struct *p = e->target; */

	/* Make sure that task_cpu() accesses updated info. */
	if(task_cpu(e->target) != ipanema_get_current_cpu(e->target)) {
		IPA_EMERG_SAFE("WARNING! task_cpu(e->target)=%d and ipanema_get_current_cpu(e->target)=%d in %s.\n",
			task_cpu(e->target), ipanema_get_current_cpu(e->target),
			__FUNCTION__);
	}

	lockdep_assert_held(&e->target->pi_lock);

	IPA_DBG_SAFE("In ipanema_unblock().\n");

	if (core != smp_processor_id()) {
		IPA_DBG_SAFE("Called ipanema_unblock_prepare for a remote core (core=%d, current_core=%d).\n",
			     core, smp_processor_id());
	}

	if (!ipanema_policies)
		return core;

	read_lock_irqsave(&ipanema_rwlock, flags);

	policies_p = ipanema_policies;

	while (*policies_p) {
		IPA_DBG_SAFE("Checking whether policy '%s' is responsible for core %d.\n",
			     (*policies_p)->command, core);

		/* Is this policy taking care of the current core? */
		if ((*policies_p)->cores[core]) {
			IPA_DBG_SAFE("It is. module=%p.\n",
				     (*policies_p)->module);

			unblock_function =
				(*policies_p)->module->routines->unblock_prepare;

			if (!unblock_function)
				IPA_EMERG_SAFE("WARNING! Invalid function pointer!\n");
			else
				core = (*unblock_function)(*policies_p, e);

			read_unlock_irqrestore(&ipanema_rwlock, flags);

			return core;
		}

		policies_p++;

		if (i++ > 4)
			IPA_DBG_SAFE("Possible infinite loop?\n");
	}

	read_unlock_irqrestore(&ipanema_rwlock, flags);

	/* Default behavior */
	/* change_state(e->target, IPANEMA_READY); */
	return core;
}

void ipanema_unblock_place(struct process_event *e)
{
	unsigned long flags;
	int core = ipanema_get_current_cpu(e->target);
	struct ipanema_policy **policies_p;
	int i = 0;
	/* struct rq *rq; */
	void (*unblock_function)(struct ipanema_policy *policy_p,
				 struct process_event *e);
	/* struct task_struct *p = e->target; */

	/* Make sure that task_cpu() accesses updated info. */
	if(task_cpu(e->target) != ipanema_get_current_cpu(e->target)) {
		IPA_EMERG_SAFE("WARNING! task_cpu(e->target)=%d and ipanema_get_current_cpu(e->target)=%d in %s.\n",
			task_cpu(e->target), ipanema_get_current_cpu(e->target),
			__FUNCTION__);
	}

	/* lockdep_assert_held(&e->target->pi_lock); */
	lockdep_assert_held(&task_rq(e->target)->lock);

	IPA_DBG_SAFE("In ipanema_unblock().\n");

	if (core != smp_processor_id()) {
		IPA_DBG_SAFE("Called ipanema_unblock_place for a remote core (core=%d, current_core=%d).\n",
			     core, smp_processor_id());
	}

	if (!ipanema_policies)
		return;

	read_lock_irqsave(&ipanema_rwlock, flags);

	policies_p = ipanema_policies;

	while (*policies_p) {
		IPA_DBG_SAFE("Checking whether policy '%s' is responsible for core %d.\n",
			     (*policies_p)->command, core);

		/* Is this policy taking care of the current core? */
		if ((*policies_p)->cores[core]) {
			IPA_DBG_SAFE("It is. module=%p.\n",
				     (*policies_p)->module);

			unblock_function =
				(*policies_p)->module->routines->unblock_place;

			if (!unblock_function)
				IPA_EMERG_SAFE("WARNING! Invalid function pointer!\n");
			else
				(*unblock_function)(*policies_p, e);

			read_unlock_irqrestore(&ipanema_rwlock, flags);

			return;
		}

		policies_p++;

		if (i++ > 4)
			IPA_DBG_SAFE("Possible infinite loop?\n");
	}

	read_unlock_irqrestore(&ipanema_rwlock, flags);

	/* Default behavior */
	change_state(e->target, IPANEMA_READY, e->target->cpu);
}

void ipanema_unblock_end(struct process_event *e)
{
	unsigned long flags;
	int core = ipanema_get_current_cpu(e->target);
	struct ipanema_policy **policies_p;
	int i = 0;
	/* struct rq *rq; */
	void (*unblock_function)(struct ipanema_policy *policy_p,
				 struct process_event *e);
	/* struct task_struct *p = e->target; */

	/* Make sure that task_cpu() accesses updated info. */
	if(task_cpu(e->target) != ipanema_get_current_cpu(e->target)) {
		IPA_EMERG_SAFE("WARNING! task_cpu(e->target)=%d and ipanema_get_current_cpu(e->target)=%d in %s.\n",
			task_cpu(e->target), ipanema_get_current_cpu(e->target),
			__FUNCTION__);
	}

	lockdep_assert_held(&e->target->pi_lock);
	lockdep_assert_held(&task_rq(e->target)->lock);

	IPA_DBG_SAFE("In ipanema_unblock().\n");

	if (core != smp_processor_id()) {
		IPA_DBG_SAFE("Called ipanema_unblock_end for a remote core (core=%d, current_core=%d).\n",
			     core, smp_processor_id());
	}

	if (!ipanema_policies)
		return;

	read_lock_irqsave(&ipanema_rwlock, flags);

	policies_p = ipanema_policies;

	while (*policies_p) {
		IPA_DBG_SAFE("Checking whether policy '%s' is responsible for core %d.\n",
			     (*policies_p)->command, core);

		/* Is this policy taking care of the current core? */
		if ((*policies_p)->cores[core]) {
			IPA_DBG_SAFE("It is. module=%p.\n",
				     (*policies_p)->module);

			unblock_function =
				(*policies_p)->module->routines->unblock_end;

			if (!unblock_function)
				IPA_EMERG_SAFE("WARNING! Invalid function pointer!\n");
			else
				(*unblock_function)(*policies_p, e);

			read_unlock_irqrestore(&ipanema_rwlock, flags);

			return;
		}

		policies_p++;

		if (i++ > 4)
			IPA_DBG_SAFE("Possible infinite loop?\n");
	}

	read_unlock_irqrestore(&ipanema_rwlock, flags);

	/* Default behavior */
	/* change_state(e->target, IPANEMA_READY); */
}

void ipanema_terminate(struct process_event *e)
{
	unsigned long flags;
	int core = task_cpu(e->target);
	struct ipanema_policy **policies_p;
	int i = 0;
	struct rq *rq;
	void (*terminate_function)(struct ipanema_policy *policy_p,
				   struct process_event *e);

	/* Make sure that task_cpu() accesses updated info. */
	if(task_cpu(e->target) != ipanema_get_current_cpu(e->target)) {
		IPA_EMERG_SAFE("WARNING! task_cpu(e->target)=%d and "
			       "ipanema_get_current_cpu(e->target)=%d in %s.\n",
			       task_cpu(e->target),
			       ipanema_get_current_cpu(e->target),
			       __FUNCTION__);
	}

	/*
	 * The reason why the rq lock must be held here is that once the task is
	 * terminated, change_state4() will call resched_curr().
	 */
	rq = cpu_rq(ipanema_get_current_cpu(e->target));

	IPA_DBG_SAFE("In ipanema_terminate().\n");

	if (core != smp_processor_id()) {
		IPA_DBG_SAFE("Calling ipanema_terminate for a remote core "
			     "(core = %d, current core = %d).\n", core,
			     smp_processor_id());
	}

	if (!ipanema_policies)
		return;

	read_lock_irqsave(&ipanema_rwlock, flags);

	policies_p = ipanema_policies;

	while (*policies_p) {
		/* Is this policy taking care of the current core? */
		if ((*policies_p)->cores[core]) {
			terminate_function =
				(*policies_p)->module->routines->terminate;

			if (!terminate_function)
				IPA_EMERG_SAFE("WARNING! Invalid function "
					       "pointer!\n");
			else
				(*terminate_function)(*policies_p, e);

			read_unlock_irqrestore(&ipanema_rwlock, flags);

			return;
		}

		policies_p++;

		if (i++ > 4)
			IPA_DBG_SAFE("Possible infinite loop?\n");
	}

	read_unlock_irqrestore(&ipanema_rwlock, flags);

	/* Default behavior */
	change_state(e->target, IPANEMA_TERMINATED, e->target->cpu);
}

void ipanema_schedule(int core)
{
	struct rq *rq;
	struct ipanema_policy **policies_p;
	int i = 0;
	void (*schedule_function)(struct ipanema_policy *policy_p, int cpu);

	/*
	 * TODO: make sure that the rq lock of the current or first ready task
	 * is held, somehow!
	 */

	/* IRQs are apparently disabled. */
	WARN_ON(!irqs_disabled());

	/*
	 * We *must* hold the rq lock here, otherwise we can make a ready task
	 * running while another thread is stealing it.
	 */
	rq = cpu_rq(core);
	lockdep_assert_held(&rq->lock);

	IPA_DBG_SAFE("ipanema_schedule() on core %d.\n", core);

	if (!ipanema_policies) return;

	/*
	 * Do not disable IRQs here. Otherwise, we may end up in a context
	 * switch that will call spin_unlock_irq(), enabling IRQs at some
	 * point, and we will disable them again when we call
	 * read_unlock_irqrestore(), leaving the system in an inconsistent
	 * state...
	 */
	read_lock(&ipanema_rwlock);

	policies_p = ipanema_policies;

	while (*policies_p) {
		/* Is this policy taking care of the current core ? */
		if ((*policies_p)->cores[core]) {
			schedule_function =
				(*policies_p)->module->routines->schedule;

			/* IRQs must be enabled at this point! */
			if (!schedule_function)
				IPA_EMERG_SAFE("WARNING! Invalid function "
					       "pointer!\n");
			else
				(*schedule_function)(*policies_p, core);

			read_unlock(&ipanema_rwlock);

			return;
		}

		policies_p++;

		if (i++ > 4)
			IPA_DBG_SAFE("Possible infinite loop?\n");
	}

	read_unlock(&ipanema_rwlock);

	/* Default behavior */
	change_state(ipanema_first_of_state(IPANEMA_READY, core), IPANEMA_RUNNING, core);
}

void ipanema_core_entry(struct ipanema_policy *policy_p, int core) {
	struct core_event e = { .target = core};
	void (*core_entry_function)(struct ipanema_policy *policy_p,
					  struct core_event *e);

	core_entry_function = policy_p->module->routines->core_entry;

	if (!core_entry_function) {
		IPA_EMERG_SAFE("WARNING! Invalid function "
			       "pointer for core_entry!\n");
	}
	else {
		(*core_entry_function)(policy_p, &e);
	}
}

void ipanema_init(void)
{
#ifdef IPANEMA_BKL
	spin_lock_init(&ipanema_lock);
#endif
	rwlock_init(&ipanema_rwlock);

	ipanema_dum_init_module();
}

void ipanema_balancing_select(void)
{
	unsigned long flags;
	int core = smp_processor_id();
	struct ipanema_policy **policies_p;
	int i = 0;
	struct ipanema_module_routines *routines;
	struct core_event e = { .target = core};
	void (*balancing_select_function)(struct ipanema_policy *policy_p,
					  struct core_event *e);

//	IPA_DBG_SAFE("ipanema_balancing_select() on core %d.\n", core);

	if (!ipanema_policies) return;

	read_lock_irqsave(&ipanema_rwlock, flags);

	policies_p = ipanema_policies;

	while (*policies_p) {
		/* Is this policy taking care of the current core? */
		if ((*policies_p)->cores[core]) {
			routines = (*policies_p)->module->routines;
			balancing_select_function =
				routines->balancing_select;

			if (balancing_select_function)
				/*
				 * FIXME: NULL must be a pointer to a core_event
				 * where 'core' is retrievable from the target
				 * attribut
				 */
				(*balancing_select_function)(*policies_p, &e);

			read_unlock_irqrestore(&ipanema_rwlock, flags);

			return;
		}

		policies_p++;

		if (i++ > 4)
			IPA_DBG_SAFE("Possible infinite loop?\n");
	}

	read_unlock_irqrestore(&ipanema_rwlock, flags);
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
	.balancing_select = ipanema_balancing_select
};

static int __init ipanema_runtime_init(void)
{
	int cpu;
	int ret = 0;
	spinlock_t *sl = NULL;

	for_each_possible_cpu(cpu) {
		sl = &per_cpu(ipa_core_lock, cpu);
		spin_lock_init(sl);
	}

	return ret;
}
module_init(ipanema_runtime_init);
