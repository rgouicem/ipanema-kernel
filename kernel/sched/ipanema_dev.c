#include "ipanema_common.h"
#include "sched.h"

#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <uapi/linux/sched/types.h>

static long dev_ipanema_ioctl(struct file *fd, unsigned int ioctl_num,
			      unsigned long param);

static struct file_operations procfops = {
	.unlocked_ioctl = dev_ipanema_ioctl
};

static struct miscdevice ipanema_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = IPANEMA_DEVICE_NAME,
	.fops = &procfops,
	.mode = S_IRUGO | S_IWUGO,
};

void ipanema_create_dev(void)
{
	if (misc_register(&ipanema_dev))
		IPA_DBG_SAFE("ERROR: unable to register /dev/ipanema!\n");
}

static long
dev_ipanema_ioctl(struct file *fd, unsigned int ioctl_num, unsigned long param)
{
	int i, res;
	bool accepted;
	struct dev_ipanema_attach_info_struct data;
	struct sched_param sched_param;
	struct cpumask set = CPU_MASK_NONE;
	struct task_struct *task_struct;

	IPA_DBG("&ipanema_initialized = %p\n", &ipanema_initialized);

	if (!atomic_cmpxchg(&ipanema_initialized, 0, 1))
		ipanema_late_init();

	/* We only know one type of IOCTL. */
	if (ioctl_num != IOCTL_ATTACH)
		return -EINVAL;

	/* Must be called without held lock - might fault. */
	if(copy_from_user(&data, (struct dev_ipanema_attach_info_struct *)param,
			  sizeof(struct dev_ipanema_attach_info_struct))) {
		IPA_DBG("Error during copy_from_user\n");
		return -EINVAL;
	}

	IPA_DBG("Received ioctl() for thread id = %d, asking to be "
		"placed on policy id = %d, with priority = %d and parameters "
		"= '%s'.\n",
		data.tid, data.policy_id, data.prio, data.command);

	/* We *need* to use RCU in order to use find_task_by_vpid. */
	rcu_read_lock();
	task_struct = find_task_by_vpid(data.tid);
	if (task_struct)
		get_task_struct(task_struct);
	rcu_read_unlock();

	if (task_struct) {
		IPA_DBG("Found task_struct for thread id = %d.\n", data.tid);
	} else {
		res = -EINVAL;
		IPA_DBG("Couldn't find task_struct for thread id = %d.\n",
			data.tid);
		goto err1;
	}

	/*
	 * We need to acquire the spinlock after calling copy_from_user(),
	 * because copy_from_user() might sleep.
	 */
	read_lock(&ipanema_rwlock);

	/*
	 * Admission control
	 * =================
	 * We call the policy's implementation of attach() to let the policy
	 * decide whether it accepts the thread or not.
	 *
	 * (1) If the thread is accepted, we place it on the policy's cores,
	 * and if it is not already in the SCHED_IPANEMA class, we set its
	 * class to SCHED_IPANEMA.
	 *
	 * (2) If the thread is rejected:
	 *
	 *	 (2.1) If the thread is in the SCHED_IPANEMA class, we move it
	 *	 to the default SCHED_IPANEMA policy's cores.
	 *
	 *	 (2.2) If the thread isn't in the SCHED_IPANEMA class, we don't
	 *	 do anything, e.g., a SCHED_NORMAL thread won't be moved and
	 *	 will remain in the SCHED_NORMAL class if it is rejected by an
	 *	 Ipanema policy.
	 *
	 */
	accepted = ipanema_policies[data.policy_id]
			->module
			->routines
			->attach(ipanema_policies[data.policy_id],
				 task_struct, data.command);

retry:
	if (accepted) {
		/*
		 * Case (1): the thread was accepted.
		 * ==================================
		 */
		IPA_DBG("Thread id = %d was accepted by the policy id = %d.",
				data.tid, data.policy_id);

		/* We first place the thread on the policy's cores. */

		if (data.policy_id >= num_ipanema_policies) {
			res = -EINVAL;
			IPA_DBG("Error: policy id = '%d' out of range.\n",
				data.policy_id);
			goto err3;
		}

		for (i = 0; i < num_online_cpus(); i++) {
			if (ipanema_policies[data.policy_id]->cores[i]
				/*
				 * If no policy has been instantiated yet, just
				 * let the thread go anywhere. It will still be
				 * handled correctly by ipanema, using basic
				 * transitions.
				 */
				|| !num_ipanema_policies) {
				cpumask_set_cpu(i, &set);
			}
		}

		/*
		 * We cannot call sched_seffaffinity() in a critical section,
		 * because it indirectly calls schedule(). Which forces us to
		 * release this lock.
		 */
		read_unlock(&ipanema_rwlock);

		IPA_DBG("Now setting affinity for thread id = %d.\n", data.tid);

		res = sched_setaffinity(data.tid, &set);

		if (res < 0) {
			IPA_DBG("Error: unable to change the CPU affinity for "
					"thread id = %d.", data.tid);
			goto err2;
		}


		/*
		 * If the thread is not already using the SCHED_IPANEMA class,
		 * we set its class to SCHED_IPANEMA.
		 */
		if (task_struct->sched_class != &ipanema_sched_class) {
			sched_param.sched_priority = data.prio;

			IPA_DBG("Now setting the scheduling class for thread "
				"id = %d to SCHED_IPANEMA.\n", data.tid);

			/*
			 * Calls schedule(), and ipanema_new(). Cannot be
			 * called in an atomic section, because it indirectly
			 * calls schedule()!
			 */
			res = sched_setscheduler(task_struct, SCHED_IPANEMA,
						 &sched_param);

			if (res < 0) {
				IPA_DBG("Error: unable to change the "
					"scheduling class to SCHED_IPANEMA for "
					"thread id = %d.\n", data.tid);
				goto err2;
			}
		} else {
			IPA_DBG("Thread id = %d is already running in the "
				"SCHED_IPANEMA class. We're done.\n", data.tid);
		}

		return 0;

		/*
		 * TODO: We had to release the ipanema_rwlock in order to call
		 * sched_setaffinity() and sched_setscheduler(). Which means
		 * that we could have a race condition here: the list of
		 * policies could be modified while the thread's affinity or
		 * scheduling class is being modified. The solution to this is
		 * probably to increase a variable that counts the number of
		 * threads each policy has while the lock is still held, and to
		 * refuse policy changes while there are still threads in some
		 * of the policies.
		 */
	} else {
		/*
		 * Case (2): the thread was rejected.
		 * ==================================
		 */

		if (task_struct->sched_class == &ipanema_sched_class) {
			/*
			 * (2.1) If the thread is in the SCHED_IPANEMA class,
			 * we move it to the default SCHED_IPANEMA policy's
			 * cores.
			 */
			IPA_DBG("Thread id = %d was rejected by policy id = %d "
				"(command = '%s'). Since the thread's class is "
				"already SCHED_IPANEMA, we use policy id = 0 "
				"instead (command = '%s').\n", data.tid,
				data.policy_id,
				ipanema_policies[data.policy_id]->command,
				ipanema_policies[0]->command);

			accepted = true;
			data.policy_id = 0;

			/*
			 * TODO: implementing this with a goto is kinda ugly.
			 * Could be improved.
			 */
			goto retry;
		} else {
			/*
			 * (2.2) If the thread isn't in the SCHED_IPANEMA
			 * class, we don't do anything, e.g., a SCHED_NORMAL
			 * thread won't be moved and will remain in the
			 * SCHED_NORMAL class if it is rejected by an Ipanema
			 * policy.
			 */
			IPA_DBG("Thread id = %d was rejected by policy id = %d "
				"(command = '%s'). Since the thread's class is "
				"*not* SCHED_IPANEMA, we don't do anything "
				"special.\n", data.tid, data.policy_id,
				ipanema_policies[data.policy_id]->command);
		}
	}

err3:
	read_unlock(&ipanema_rwlock);
err2:
	/*
	 * Avoid double free's. Call this in ipanema_terminate(). (May not be
	 * required, but we passed task_struct to functions that may still be
	 * using it, safer to not release it now).
	 */
//  put_task_struct(task_struct);
err1:
	return res;
}

