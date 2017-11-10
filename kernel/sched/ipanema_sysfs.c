#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/vmalloc.h>

#include "ipanema_common.h"

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
				      struct kobj_attribute *attr, char *buf)
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

static int __init ipanema_sysfs_init(void)
{
	int error;

	/* Create /sys/kernel/ipanema */
	ipanema_kobj = kobject_create_and_add("ipanema", kernel_kobj);
	if (!ipanema_kobj) {
		pr_err("ipanema: failed to create /sys/kernel/ipanema (ENOMEM)\n");
		error = -ENOMEM;
		goto exit;
	}
	error = sysfs_create_group(ipanema_kobj, &ipanema_attr_group);
	if (error)
		goto kset_exit;

	return 0;

kset_exit:
	kobject_put(ipanema_kobj);
exit:
	return error;
}

core_initcall(ipanema_sysfs_init);
