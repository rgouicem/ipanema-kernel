#
# gdb helper commands and functions for Linux kernel debugging
#
#  rbtree tools
# Copyright (c) Redha Gouicem, 2018
#
# Authors:
#  Redha Gouicem <redha.gouicem@gmail.com>
#
# This work is licensed under the terms of the GNU GPL version 2.
#

import gdb

from linux import utils


rb_node = utils.CachedType("struct rb_node")
rb_root = utils.CachedType("struct rb_root")

def rb_left_deepest_node(node):
    if node.type == rb_node.get_type().pointer():
        node = node.dereference()
    elif node.type != rb_node.get_type():
        raise TypeError("Must be a struct rb_node not {}"
                        .format(node.type))
    while True:
        if node['rb_left'] != 0:
            node = node['rb_left'].dereference()
        elif node['rb_right'] != 0:
            node = node['rb_right'].dereference()
        else:
            return node

def rb_first_postorder(node):
    if node.address == 0:
        return node
    return rb_left_deepest_node(node)

def rb_parent(node):
    ulong_type = gdb.lookup_type("unsigned long")
    mask = gdb.Value(~3).cast(ulong_type)
    newAddr = node['__rb_parent_color'].cast(ulong_type) & mask
    newAddr = newAddr.cast(rb_node.get_type().pointer())
    return newAddr

def rb_next_postorder(node):
    if node.address == 0:
        return node.address
    parent = rb_parent(node)
    if (parent != 0 and
        node == parent.dereference()['rb_left'] and
        parent.dereference()['rb_right'] != 0):
        return rb_left_deepest_node(parent.dereference()['rb_right']).address
    return parent

def rbtree_postorder_for_each(root):
    if root.type == rb_root.get_type().pointer():
        root = root.dereference()
    elif root.type != rb_root.get_type():
        raise gdb.GdbError("Must be a struct rb_root not {}"
                           .format(root.type))

    node = rb_first_postorder(root['rb_node']).address
    while node != 0:
        yield node
        node = rb_next_postorder(node)

def rbtree_postorder_for_each_entry(root, gdbtype, member):
    for node in rbtree_postorder_for_each(root):
        if node.type != rb_node.get_type().pointer():
            raise gdb.GdbError("Must be a struct rb_node not a {}"
                               .format(node.type))
        yield utils.container_of(node, gdbtype, member)


class LxRbtreeFirstFunc(gdb.Function):
    """Return the leftmost node of a rbtree

$lx_rbtree_first(RBTREE): Given RBTREE, return its first (leftmost) node."""

    def __init__(self):
        super(LxRbtreeFirstFunc, self).__init__("lx_rbtree_first")

    def invoke(self, tree):
        if tree.type == rb_root.get_type().pointer():
            tree = tree.dereference()
        elif tree.type != rb_root.get_type():
            raise gdb.GdbError("Must be a struct rb_root not a {}".format(tree.type))

        return rb_first_postorder(tree['rb_node'])

LxRbtreeFirstFunc()


class LxRbtreePostorderFunc(gdb.Function):
    """Print an rbtree in postorder (node addresses)

$lx_rbtree_postorder(RBTREE): Given RBTREE, print its nodes' addresses in postorder."""

    def __init__(self):
        super(LxRbtreePostorderFunc, self).__init__("lx_rbtree_postorder")

    def invoke(self, tree):
        if tree.type == rb_root.get_type().pointer():
            tree = tree.dereference()
        elif tree.type != rb_root.get_type():
            raise gdb.GdbError("Must be a struct rb_root not a {}".format(tree.type))

        i = 0
        for node in rbtree_postorder_for_each(tree):
            gdb.write("{addr} -> ".format(addr=node))
            i += 1
        gdb.write("\n")

        return i

LxRbtreePostorderFunc()


class LxRbtreePostorderIpanemaFunc(gdb.Function):
    """Print an rbtree in postorder (PID for ipanema tasks)

$lx_rbtree_postorder_ipanema(RBTREE): Given RBTREE, print its task PID in postorder."""

    def __init__(self):
        super(LxRbtreePostorderIpanemaFunc, self).__init__("lx_rbtree_postorder_ipanema")

    def invoke(self, tree):
        if tree.type == rb_root.get_type().pointer():
            tree = tree.dereference()
        elif tree.type != rb_root.get_type():
            raise gdb.GdbError("Must be a struct rb_root not a {}".format(tree.type))

        ipa_md_type = gdb.lookup_type("struct ipanema_metadata").pointer()
        ts_type = gdb.lookup_type("struct task_struct").pointer()

        i = 0
        for ipa_md in rbtree_postorder_for_each_entry(tree, ipa_md_type, "node_runqueue"):
            task = utils.container_of(ipa_md, ts_type, "ipanema_metadata")
            gdb.write("{pid} -> ".format(pid=task['pid']))
            i += 1
        gdb.write("\n")

        return i

LxRbtreePostorderIpanemaFunc()

