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
from abc import ABC

from filament.http import BaseHandler
from filament.json import jsonify
import collections
from filament.utils import to_ddict
from datetime import datetime


class NavbarItem:
    """Represents the metadata for the item of the navigation bar."""

    def __init__(self, title, route, icon):
        self.title = title
        self.route = route
        self.icon = icon


class NavbarHandler(BaseHandler, ABC):
    def get(self):
        items = [
            NavbarItem("Processes", "/processes", "terminal"),
            NavbarItem("Directories", "/directories", "folder"),
            NavbarItem("Registry", "/registry", "cube"),
            NavbarItem("Files", "/files", "file-tray-full"),
            NavbarItem("Connections", "/connections", "wifi"),
            NavbarItem("Threads", "/threads", "flash"),
            NavbarItem("Errors", "/errors", "close-circle"),
            NavbarItem("Handles", "/handles", "bag-handle"),
            NavbarItem("Modules", "/modules", "apps"),
            NavbarItem("Ingress Packets", "/ingress", "cloud-download"),
            NavbarItem("Egress Packets", "/egress", "cloud-upload"),
            NavbarItem("Slow File I/O", "/slowio", "stats-chart"),
            NavbarItem("PE", "/pe", "stats-chart"),
        ]
        self.write(jsonify(items))


class Node:
    def __init__(self, pid, ps):
        self.id = pid if not ps else ps.id
        self.pid = pid
        self.ps = ps
        self.children = []


class PS:
    def __init__(self, pid, name, exe, sid, start_time):
        self.pid = pid
        self.name = name
        self.exe = exe
        self.sid = sid
        self.start_time = start_time.isoformat() if isinstance(start_time, datetime) else ""

        # Unique value used for table row keys
        self.id = self.name + str(self.pid) + self.start_time

    def __str__(self):
        return f"pid: {self.pid}, name: {self.name}"


def ps_from_kevt(kevt):
    if kevt:
        return PS(
            kevt.kparams.pid,
            kevt.kparams.name,
            kevt.kparams.exe,
            kevt.kparams.sid,
            kevt.kparams.start_time
        )


def build_tree(ppid, tree, procs):
    node = Node(ppid, ps_from_kevt(procs[ppid]) if ppid in procs else None)
    if ppid not in tree:
        return node
    children = tree.pop(ppid, [])
    for child in children:
        node.children.append(build_tree(child, tree, procs))
    return node


class ProcessTreeHandler(BaseHandler, ABC):
    def get(self):
        procs = dict()
        tree = collections.defaultdict(list)
        kevents = map(to_ddict, self.read_kcap("kevt.name in ('EnumProcess', 'CreateProcess')"))

        for kevt in kevents:
            pid = kevt.kparams.pid
            if pid in procs:
                continue
            ppid = kevt.kparams.ppid
            tree[ppid].append(pid)
            procs[pid] = kevt

        if 0 in tree and 0 in tree[0]:
            del tree[0]

        # Avoid endless recursion for PID 0 whose parent is 0
        trees = []
        # Build process trees
        while len(tree) > 0:
            trees.append(build_tree(min(tree), tree, procs))

        self.set_header("Content-Type", "application/json")
        self.write(jsonify(trees))


class ProcessHandler(BaseHandler, ABC):
    def get(self, pid):
        events = list(map(to_ddict, self.read_kcap(f"ps.snapshot.id = {pid} or kevt.pid = {pid}")))
        ps = None
        for evt in events:
            match evt.name:
                case 'EnumProcess':
                    ps = ps_from_kevt(evt)

        self.set_header("Content-Type", "application/json")
        self.write(jsonify(ps))
