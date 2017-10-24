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
	int i = 0;

	if(add == -1) {
		/* Remove */
		rb_erase(&data->ipanema_metadata.node_runqueue, root);
		memset(&data->ipanema_metadata.node_runqueue, 0,
			   sizeof(data->ipanema_metadata.node_runqueue));
		return data;
	}

	/* Figure out where to put new node */
	while (*new) {
		if (i > 10) {
			IPA_DBG_SAFE("Possible infinite loop in "
				     "_insert_remove_search_process_in_rbtree()"
				     ", i=%d.\n", i);
		}

		this = container_of(*new, struct task_struct,
				    ipanema_metadata.node_runqueue);

		parent = *new;
		cmp = order(data, this);

		if (cmp > 0)
			new = &((*new)->rb_left);
		else if (cmp < 0)
			new = &((*new)->rb_right);
		else if(data < this)
			new = &((*new)->rb_left);
		else if(data > this)
			new = &((*new)->rb_right);
		else
			break;

		i++;
	}

	/* Perform operation on the tree */
	if(add == 1) {
		if(data != this) {
			/* Insert */
			rb_link_node(&data->ipanema_metadata.node_runqueue,
				     parent, new);
			rb_insert_color(&data->ipanema_metadata.node_runqueue,
					root);
		}

		return data;
	} else {
		/* Search */
		return (data == this) ? this : NULL;
	}
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
ipanema_insert_remove_search_process_in_rbtree_unsafe(struct rb_root *root,
						      struct task_struct *data,
						      order_f order, int add)
{
	return _insert_remove_search_process_in_rbtree(root, data, order, add);
}
EXPORT_SYMBOL(ipanema_insert_remove_search_process_in_rbtree_unsafe);

struct task_struct *ipanema_add_task(struct rb_root *root,
				     struct task_struct *data,
				     order_f order)
{
	return _insert_remove_search_process_in_rbtree(root, data, order, 1);
}
EXPORT_SYMBOL(ipanema_add_task);

struct task_struct *ipanema_remove_task(struct rb_root *root,
					struct task_struct *data,
					order_f order)
{
	return _insert_remove_search_process_in_rbtree(root, data, order, -1);
}
EXPORT_SYMBOL(ipanema_remove_task);

struct task_struct *ipanema_search_task(struct rb_root *root,
					struct task_struct *data,
					order_f order)
{
	return _insert_remove_search_process_in_rbtree(root, data, order, 0);
}
EXPORT_SYMBOL(ipanema_search_task);

void print_tree(struct rb_node *new, int indent)
{
	struct task_struct *this = NULL;

	/* Figure out where to put new node */
	if (new) {
		this = container_of(new, struct task_struct,
				    ipanema_metadata.node_runqueue);

		printk("%*.*s%p %d\n", indent, indent, "", this,
			   ipanema_routines.get_metric(this));

		print_tree(new->rb_left, indent + 1);
		print_tree(new->rb_right, indent + 1);
	}
}

struct task_struct *ipanema_first_task(struct rb_root *root)
{
	struct rb_node *new;
	struct task_struct *result = NULL;
	int i = 0;

	new = root->rb_node;
	if(!new)
		goto end;

	while(new) {
		if (i > 10)
			IPA_DBG_SAFE("Possible infinite loop in first_task(), "
				     "i=%d.\n", i);

		result = container_of(new, struct task_struct,
				      ipanema_metadata.node_runqueue);
		new = new->rb_right;
	}

// 	print_tree(root->rb_node, 0);
end:
	return result;
}
EXPORT_SYMBOL(ipanema_first_task);

