#include "ipanema_common.h"

/* Rbtree manipulation */
struct task_struct *
_insert_remove_search_process_in_rbtree(struct rb_root *root,
					struct task_struct *data,
					order_f order, int add)
{
	int cmp;
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct task_struct *this = NULL;

	if (add == -1) {
		/* Remove */
		rb_erase(&data->ipanema_metadata.node_runqueue, root);
		memset(&data->ipanema_metadata.node_runqueue, 0,
		       sizeof(data->ipanema_metadata.node_runqueue));
		return data;
	}

	/* Figure out where to put new node */
	while (*new) {
		this = container_of(*new, struct task_struct,
				    ipanema_metadata.node_runqueue);

		parent = *new;
		cmp = order(data, this);

		if (cmp > 0)
			new = &((*new)->rb_left);
		else if (cmp < 0)
			new = &((*new)->rb_right);
		else if (data < this)
			new = &((*new)->rb_left);
		else if (data > this)
			new = &((*new)->rb_right);
		else
			break;
	}

	/* Perform operation on the tree */
	if (add == 1) {
		if (data != this) {
			/* Insert */
			rb_link_node(&data->ipanema_metadata.node_runqueue,
				     parent, new);
			rb_insert_color(&data->ipanema_metadata.node_runqueue,
					root);
		}

		return data;
	}

	/* Search */
	return (data == this) ? this : NULL;
}

struct task_struct *
insert_remove_search_process_in_rbtree(struct rb_root *root,
				       struct task_struct *data,
				       order_f order, int add)
{
	struct task_struct *result;

	result = _insert_remove_search_process_in_rbtree(root, data, order,
							 add);

	return result;
}

struct task_struct *
ipanema_insert_remove_search_process_in_rbtree_unsafe(struct ipanema_rq *rq,
						      struct task_struct *data,
						      order_f order, int add)
{
	struct rb_root *root = &(rq->root);

	return _insert_remove_search_process_in_rbtree(root, data, order, add);
}
EXPORT_SYMBOL(ipanema_insert_remove_search_process_in_rbtree_unsafe);

struct task_struct *ipanema_add_task(struct ipanema_rq *rq,
				     struct task_struct *data,
				     order_f order)
{
	struct rb_root *root = &(rq->root);

	return _insert_remove_search_process_in_rbtree(root, data, order, 1);
}
EXPORT_SYMBOL(ipanema_add_task);

struct task_struct *ipanema_remove_task(struct ipanema_rq *rq,
					struct task_struct *data,
					order_f order)
{
	struct rb_root *root = &(rq->root);

	return _insert_remove_search_process_in_rbtree(root, data, order, -1);
}
EXPORT_SYMBOL(ipanema_remove_task);

struct task_struct *ipanema_search_task(struct ipanema_rq *rq,
					struct task_struct *data,
					order_f order)
{
	struct rb_root *root = &(rq->root);

	return _insert_remove_search_process_in_rbtree(root, data, order, 0);
}
EXPORT_SYMBOL(ipanema_search_task);

struct task_struct *ipanema_first_task(struct ipanema_rq *rq)
{
	struct rb_root *root = &(rq->root);
	struct rb_node *new;
	struct task_struct *result = NULL;

	new = root->rb_node;
	if (!new)
		goto end;

	while (new) {
		result = container_of(new, struct task_struct,
				      ipanema_metadata.node_runqueue);
		new = new->rb_right;
	}

end:
	return result;
}
EXPORT_SYMBOL(ipanema_first_task);

