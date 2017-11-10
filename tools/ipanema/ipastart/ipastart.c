#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/syscall.h>

#define SCHED_IPANEMA  7

struct sched_attr {
	uint32_t size;

	uint32_t sched_policy;
	uint64_t sched_flags;

	/* SCHED_NORMAL, SCHED_BATCH */
	int32_t sched_nice;

	/* SCHED_FIFO, SCHED_RR */
	uint32_t sched_priority;

	/* SCHED_DEADLINE */
	uint64_t sched_runtime;
	uint64_t sched_deadline;
	uint64_t sched_period;

	/* SCHED_IPANEMA */
	uint32_t sched_ipa_policy;
};

static int sched_setattr(pid_t pid, const struct sched_attr *attr,
			 unsigned int flags)
{
	return syscall(SYS_sched_setattr, pid, attr, flags);
}

static int sched_getattr(pid_t pid, const struct sched_attr *attr,
			 unsigned int size, unsigned int flags)
{
	return syscall(SYS_sched_getattr, pid, attr, size, flags);
}

static inline void usage()
{
	fprintf(stderr,
		"Usage:\n"
		"\t ipastart policy program [args]\n"
		"\n"
		"\t policy   ipanema policy id (see /proc/ipanema_info)\n"
		"\t program  the program to launch\n"
		"\t args     arguments for program\n");
}

int main(int argc, char **argv)
{
	int ret, ipa_policy = -1;
	char *tmp;
	struct sched_attr attr = {
		.size = sizeof(struct sched_attr),
		.sched_policy = SCHED_IPANEMA,
		.sched_flags = 0,
		.sched_nice = 0,
		.sched_priority = 0,
		.sched_ipa_policy = 0,
	};

	if (argc < 3)
		goto bad_usage;

	ipa_policy = strtol(argv[1], &tmp, 10);
	if (argv[1] == tmp)
		goto bad_usage;
	attr.sched_ipa_policy = ipa_policy;

	ret = sched_setattr(0, &attr, 0);
	if (ret < 0) {
		perror("sched_setattr() failed");
		goto end;
	}

	ret = sched_getattr(0, &attr, sizeof(struct sched_attr), 0);
	if (ret < 0) {
		perror("sched_getattr() failed");
		goto end;
	}

	printf("Switched from %d to %d[%d]\n",
	       ret, attr.sched_policy, attr.sched_ipa_policy);

	ret = execvp(argv[2], argv+2);

end:
	return EXIT_FAILURE;

bad_usage:
	usage();
	return EXIT_FAILURE;
}
