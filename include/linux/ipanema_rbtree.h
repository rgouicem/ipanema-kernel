#ifndef IPANEMA_RBTREE
#define IPANEMA_RBTREE

#include <linux/ipanema.h>

/* Bossa runqueue utilities */
typedef int (*order_f)(struct task_struct *a, struct task_struct *b);

struct task_struct *
ipanema_add_task(ipanema_rq *root, struct task_struct *data, order_f order);
struct task_struct *
ipanema_remove_task(ipanema_rq *root, struct task_struct *data, order_f order);
struct task_struct *
ipanema_search_task(ipanema_rq *root, struct task_struct *data, order_f order);
struct task_struct *ipanema_first_task(ipanema_rq *root);
struct task_struct *
ipanema_insert_remove_search_process_in_rbtree_unsafe(ipanema_rq *root,
						      struct task_struct *data,
						      order_f order, int add);

#endif
