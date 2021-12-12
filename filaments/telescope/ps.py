# Copyright 2021-2022 by Nedim Sabic (RabbitStack)
# All Rights Reserved.
# http://rabbitstack.github.io

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import collections

from telescope.types import PS


class Node:
    def __init__(self, pid, ps):
        self.id = pid if not ps else ps.id
        self.pid = pid
        self.ps = ps
        self.children = []


def ps_from_kevt(kevt):
    """Constructs a fresh process object from the given event.
    """
    if kevt:
        return PS(
            kevt.kparams.pid,
            kevt.kparams.name,
            kevt.kparams.exe,
            kevt.kparams.comm,
            kevt.cwd,
            kevt.kparams.sid,
            kevt.kparams.start_time
        )


def build_tree(kevents):
    procs = dict()
    trees = []
    tree = collections.defaultdict(list)

    for kevt in kevents:
        pid = kevt.kparams.pid
        ppid = kevt.kparams.ppid
        tree[ppid].append(pid)
        procs[pid] = kevt

    # Avoid endless recursion for PID 0 whose parent is reported as 0
    if 0 in tree and 0 in tree[0]:
        del tree[0]

    # Build process trees
    while len(tree) > 0:
        trees.append(__build_nodes(min(tree), tree, procs))

    return trees


def __build_nodes(ppid, tree, procs):
    """Recursively builds the tree of process nodes.
    """
    node = Node(ppid, ps_from_kevt(procs[ppid]) if ppid in procs else None)
    if ppid not in tree:
        return node
    children = tree.pop(ppid, [])
    for child in children:
        node.children.append(__build_nodes(child, tree, procs))
    return node
