#include "sched.h"
#include "ipanema_common.h"

/*
 * Rbtree manipulation
 */
static inline int ipanema_add_task_rbtree(struct rb_root *root,
					  struct task_struct *data,
					  int (*cmp_fn)(struct task_struct *,
							struct task_struct *))
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	while (*new) {
		struct task_struct *t = container_of(*new, struct task_struct,
						     ipanema.node_runqueue);
		int res = cmp_fn(data, t);

		parent = *new;

		/*
		 * We compare with the provided function, but if both threads
		 * are equal, we use the task_struct's address to differenciate.
		 * If the node is already in the rbtree, we stop here.
		 */
		if (res < 0)
			new = &((*new)->rb_left);
		else if (res > 0)
			new = &((*new)->rb_right);
		else if (data < t)
			new = &((*new)->rb_left);
		else if (data > t)
			new = &((*new)->rb_right);
		else
			return -EINVAL;
	}

	rb_link_node(&data->ipanema.node_runqueue, parent, new);
	rb_insert_color(&data->ipanema.node_runqueue, root);

	return 0;
}

static inline struct task_struct *
ipanema_remove_task_rbtree(struct rb_root *root, struct task_struct *data)
{
	rb_erase(&data->ipanema.node_runqueue, root);
	memset(&data->ipanema.node_runqueue, 0,
	       sizeof(data->ipanema.node_runqueue));
	return data;
}

static inline struct task_struct *
ipanema_first_task_rbtree(struct rb_root *root)
{
	struct rb_node *first;

	first = rb_first(root);
	if (!first)
		return NULL;

	return container_of(first, struct task_struct, ipanema.node_runqueue);
}


/*
 * FIFO manipulation
 */
static inline int ipanema_add_task_fifo(struct list_head *head,
					struct task_struct *data,
					int (*cmp_fn)(struct task_struct *,
						      struct task_struct *))
{
	if (!list_empty(&data->ipanema.node_list))
		return -EINVAL;
	list_add_tail(&data->ipanema.node_list, head);
	return 0;
}

static inline struct task_struct *
ipanema_remove_task_fifo(struct list_head *head, struct task_struct *data)
{
	list_del(&data->ipanema.node_list);

	return data;
}

static inline struct task_struct *
ipanema_first_task_fifo(struct list_head *head)
{
	return list_first_entry_or_null(head, struct task_struct,
					ipanema.node_list);
}


/*
 * Generic ipanema_rq API
 */
int ipanema_add_task(struct ipanema_rq *rq, struct task_struct *data)
{
	switch (rq->type) {
	case RBTREE:
		return ipanema_add_task_rbtree(&rq->root, data, rq->order_fn);
	case FIFO:
		return ipanema_add_task_fifo(&rq->head, data, rq->order_fn);
	default:
		return -EINVAL;
	}
}
/* EXPORT_SYMBOL(ipanema_add_task); */

struct task_struct *ipanema_remove_task(struct ipanema_rq *rq,
					struct task_struct *data)
{
	switch (rq->type) {
	case RBTREE:
		return ipanema_remove_task_rbtree(&rq->root, data);
	case FIFO:
		return ipanema_remove_task_fifo(&rq->head, data);
	default:
		return NULL;
	}
}
/* EXPORT_SYMBOL(ipanema_remove_task); */

struct task_struct *ipanema_first_task(struct ipanema_rq *rq)
{
	switch (rq->type) {
	case RBTREE:
		return ipanema_first_task_rbtree(&rq->root);
	case FIFO:
		return ipanema_first_task_fifo(&rq->head);
	default:
		return NULL;
	}
}
EXPORT_SYMBOL(ipanema_first_task);
