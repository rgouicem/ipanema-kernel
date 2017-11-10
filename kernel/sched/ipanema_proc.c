#include <linux/seq_file.h>
#include <linux/cpu.h>

#include "ipanema_common.h"

#define MAX_POLICY_STR_LENGTH 256
#define MAX_BUF_LEN 32768

static char policy_str[MAX_POLICY_STR_LENGTH];

static ssize_t ipanema_debug_proc_write(struct file *file,
					const char __user *buf,
					size_t count,
					loff_t *ppos)
{
	char c;

	if (count) {
		if (get_user(c, buf))
			return -EFAULT;
		if (c == 'd')
			ipanema_debug = 1;
		else if (c == 'D')
			ipanema_debug = 0;
		else if (c == 'p')
			debug_ipanema();
	}

	return count;
}

static ssize_t ipanema_policies_proc_read(struct file *file,
					  char __user *buf,
					  size_t buf_len,
					  loff_t *ppos)
{
	int len, tmp_policy_str_len;
	char tmp_policy_str[MAX_POLICY_STR_LENGTH];
	static int done;

	if (done) {
		done = 0;
		return 0;
	}

	snprintf(tmp_policy_str, MAX_POLICY_STR_LENGTH, "%s\n", policy_str);

	tmp_policy_str_len = strlen(tmp_policy_str);
	len = tmp_policy_str_len < MAX_POLICY_STR_LENGTH ?
		      tmp_policy_str_len : MAX_POLICY_STR_LENGTH;

	if (copy_to_user(buf, tmp_policy_str, len))
		return -EFAULT;

	*ppos += len;
	done = 1;

	return len;
}

static ssize_t ipanema_policies_proc_write(struct file *file,
					   const char __user *buf,
					   size_t count,
					   loff_t *ppos)
{
	int i, res;

	if (count > MAX_POLICY_STR_LENGTH)
		count = MAX_POLICY_STR_LENGTH;

	for (i = 0; i < count; i++)
		get_user(policy_str[i], buf + i);

	/* Remove the newline. */
	policy_str[i - 1] = '\0';

	IPA_DBG_SAFE("Calling ipanema_set_policy() with argument %s.\n",
		     policy_str);

	switch ((res = ipanema_set_policy(policy_str))) {
	case 0:
		return count;

	case -EBOUNDS:
		IPA_DBG_SAFE("ERROR: some core values are out of bounds!\n");
		break;

	case -EOVERLAP:
		IPA_DBG_SAFE("ERROR: some policies use overlapping cores!\n");
		break;

	case -ESYNTAX:
		IPA_DBG_SAFE("ERROR: syntax error!\n");
		break;

	case -ENOMEM:
		IPA_DBG_SAFE("ERROR: out of memory error!\n");
		break;

	case -EMODULENOTFOUND:
		IPA_DBG_SAFE("ERROR: one of the modules wasn't found!\n");
		break;

	default: /* Shouldn't happen */
		IPA_DBG_SAFE("ERROR: couldn't parse the policy string!\n");
		break;
	}

	return count;
}

static ssize_t ipanema_info_proc_read(struct file *file,
				      char __user *buf,
				      size_t buf_len,
				      loff_t *ppos)
{
	int len = 0, i = 0, output_len;
	struct ipanema_policy *policy;
	static int done;
	char *output;

	output = kmalloc_array(MAX_BUF_LEN, sizeof(char), GFP_KERNEL);
	if (!output)
		return -ENOMEM;

	if (done) {
		done = 0;
		return 0;
	}

	snprintf(output, MAX_BUF_LEN,
			"DEBUGGING:\n==========\n");

	snprintf(output + strlen(output), MAX_BUF_LEN - strlen(output),
			"Debugging is %s.\n\n", ipanema_debug ? "on" : "off");

	snprintf(output + strlen(output), MAX_BUF_LEN - strlen(output),
			"MODULES:\n========\n");

	for (i = 0; i < num_ipanema_modules; i++) {
		snprintf(output + strlen(output),
			 MAX_BUF_LEN - strlen(output),
			 "Module #%d: %s\n", i, ipanema_modules[i]->name);
	}

	snprintf(output + strlen(output), MAX_BUF_LEN - strlen(output),
			"\nPOLICIES:\n=========\n");

	policy = ipanema_policies;
	while (policy)  {
		snprintf(output + strlen(output),
			 MAX_BUF_LEN - strlen(output),
			 "Policy #%d \"%s\" on cores [",
			 policy->id, policy->name);

		snprintf(output + strlen(output),
			 MAX_BUF_LEN - strlen(output),
			 "%*pbl",
			 cpumask_pr_args(&policy->allowed_cores));

		snprintf(output + strlen(output),
			 MAX_BUF_LEN - strlen(output),
			 "]\n");

		policy = policy->next;
	}

	output_len = strlen(output);
	len = output_len < MAX_BUF_LEN ? output_len : MAX_BUF_LEN;
	if (copy_to_user(buf, output, len)) {
		len = -EFAULT;
		goto err;
	}

	*ppos += len;
	done = 1;

 err:
	kfree(output);

	return len;
}

static const struct file_operations ipanema_debug_cntrl_fops = {
	.write	= ipanema_debug_proc_write
};

static const struct file_operations ipanema_policies_cntrl_fops = {
	.read	= ipanema_policies_proc_read,
	.write	= ipanema_policies_proc_write
};

static const struct file_operations ipanema_info_cntrl_fops = {
	.read	= ipanema_info_proc_read
};

void ipanema_create_procs(void)
{
	/*
	 * /proc files cannot be created during early init phases. Do that once
	 * the kernel has booted.
	 */
	proc_create("ipanema_debug", 0222, NULL, &ipanema_debug_cntrl_fops);
	IPA_DBG_SAFE("/proc/ipanema_debug was created.\n");

	proc_create("ipanema_policies", 0222, NULL,
				&ipanema_policies_cntrl_fops);
	IPA_DBG_SAFE("/proc/ipanema_policies was created.\n");

	proc_create("ipanema_info", 0444, NULL, &ipanema_info_cntrl_fops);
	IPA_DBG_SAFE("/proc/ipanema_policies was created.\n");
}
