#include <linux/seq_file.h>
#include <linux/cpu.h>

#include "ipanema_common.h"

#define MAX_POLICY_STR_LENGTH 256
#define DEFAULT_POLICY_STR "*:dummy"
#define MAX_BUF_LEN 32768

static char policy_str[MAX_POLICY_STR_LENGTH];
atomic_t ipanema_initialized = ATOMIC_INIT(0);

void ipanema_late_init(void)
{
	int err;

	strcpy(policy_str, DEFAULT_POLICY_STR);
	if ((err = ipanema_set_policies(policy_str))) {
		IPA_DBG_SAFE("Error: couldn't set the '" DEFAULT_POLICY_STR
			     "' policy! Error = %d\n", err);
	}
}

static ssize_t ipanema_debug_proc_write(struct file *file,
					const char __user *buf,
					size_t count,
					loff_t *ppos)
{
	char c;

	if (count) {
		if (get_user(c, buf))
			return -EFAULT;
		if(c == 'd')
			ipanema_debug = 1;
	   	else if(c == 'D')
			ipanema_debug = 0;
	   else if(c == 'p')
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
	static int done = 0;

	if (!atomic_cmpxchg(&ipanema_initialized, 0, 1))
		ipanema_late_init();

	if (done) {
		done = 0;
		return 0;
	}

	snprintf(tmp_policy_str, MAX_POLICY_STR_LENGTH, "%s\n", policy_str);

	tmp_policy_str_len = strlen(tmp_policy_str);
	len = tmp_policy_str_len < MAX_POLICY_STR_LENGTH ?
		      tmp_policy_str_len : MAX_POLICY_STR_LENGTH;

	if(copy_to_user(buf, tmp_policy_str, len))
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

	if (!atomic_cmpxchg(&ipanema_initialized, 0, 1))
		ipanema_late_init();

	if (count > MAX_POLICY_STR_LENGTH)
		count = MAX_POLICY_STR_LENGTH;

	for (i = 0; i < count; i++) {
		get_user(policy_str[i], buf + i);
	}

	/* Remove the newline. */
	policy_str[i - 1] = '\0';

	IPA_DBG_SAFE("Calling ipanema_set_policies() with argument %s.\n",
		     policy_str);

	switch ((res = ipanema_set_policies(policy_str))) {
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
	int len = 0, i = 0, j, output_len;
	struct ipanema_policy **policies_p;
	static int done = 0;
	char *output;

	if (!(output = kmalloc(MAX_BUF_LEN * sizeof(char), GFP_KERNEL)))
		return -ENOMEM;

	if (!atomic_cmpxchg(&ipanema_initialized, 0, 1))
		ipanema_late_init();

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

	i = 0;

	snprintf(output + strlen(output), MAX_BUF_LEN - strlen(output),
			"\nPOLICIES:\n=========\n");

	policies_p = ipanema_policies;

	while (*policies_p) {
		snprintf(output + strlen(output),
			 MAX_BUF_LEN - strlen(output),
			 "Policy #%d%s \"%s\" on cores [", i,
			 (i? "		   " : " [default]:"),
			 (*policies_p)->command);

		for (j = 0; j < num_online_cpus(); j++) {
			snprintf(output + strlen(output),
				 MAX_BUF_LEN - strlen(output),
				 "%d", (*policies_p)->cores[j]);
		}

		snprintf(output + strlen(output),
			 MAX_BUF_LEN - strlen(output),
			 "]\n");

		policies_p++;
		i++;
	}

	output_len = strlen(output);
	len = output_len < MAX_BUF_LEN ? output_len : MAX_BUF_LEN;
	if(copy_to_user(buf, output, len)) {
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
 *	/proc files cannot be created during early init phases. Do that once the
 * 	kernel has booted.
 */
	proc_create("ipanema_debug", S_IWUGO, NULL, &ipanema_debug_cntrl_fops);
	IPA_DBG_SAFE("/proc/ipanema_debug was created.\n");

	proc_create("ipanema_policies", S_IWUGO, NULL,
				&ipanema_policies_cntrl_fops);
	IPA_DBG_SAFE("/proc/ipanema_policies was created.\n");

	proc_create("ipanema_info", S_IRUGO, NULL, &ipanema_info_cntrl_fops);
	IPA_DBG_SAFE("/proc/ipanema_policies was created.\n");
}
