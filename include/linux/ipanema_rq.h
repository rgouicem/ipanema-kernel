#ifndef IPANEMA_RBTREE
#define IPANEMA_RBTREE

#include <linux/ipanema.h>

int ipanema_add_task(struct ipanema_rq *rq, struct task_struct *data);
struct task_struct *ipanema_remove_task(struct ipanema_rq *rq,
					struct task_struct *data);
struct task_struct *ipanema_first_task(struct ipanema_rq *rq);

#endif
