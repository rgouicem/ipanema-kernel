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
	uint32_t sched_ipa_attr_size;
	void *sched_ipa_attr;
};

static int sched_setattr(pid_t pid, const struct sched_attr *attr,
			 unsigned int flags)
{
	return syscall(SYS_sched_setattr, pid, attr, flags);
}

static inline void usage()
{
	fprintf(stderr,
		"Usage:\n"
		"\t ipasetpolicy policy pid\n"
		"\n"
		"\t policy   ipanema policy id (see /proc/ipanema/policies)\n"
		"\t pid      the pid to move to ipanema policy\n");
}

int main(int argc, char **argv)
{
	pid_t pid;
	int ret, ipa_policy = -1;
	char *tmp;
	struct sched_attr attr = {
		.size = sizeof(struct sched_attr),
		.sched_policy = SCHED_IPANEMA,
		.sched_flags = 0,
		.sched_nice = 0,
		.sched_priority = 0,
		.sched_ipa_policy = 0,
		.sched_ipa_attr_size = 0,
		.sched_ipa_attr = NULL,
	};

	if (argc < 2)
		goto bad_usage;

	ipa_policy = strtol(argv[1], &tmp, 10);
	if (argv[1] == tmp)
		goto bad_usage;
	pid = strtol(argv[2], &tmp, 10);
	if (argv[2] == tmp)
		goto bad_usage;

	attr.sched_ipa_policy = ipa_policy;

	ret = sched_setattr(pid, &attr, 0);
	if (ret < 0) {
		perror("sched_setattr() failed");
		goto end;
	}

	return EXIT_SUCCESS;

end:
	return EXIT_FAILURE;

bad_usage:
	usage();
	return EXIT_FAILURE;
}
