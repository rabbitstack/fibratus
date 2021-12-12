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
from filament.utils import to_ddict
from telescope.ps import ps_from_kevt, build_tree
from filament import ktypes
from collections import Counter
from telescope.types import Packets


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


class ProcessTreeHandler(BaseHandler, ABC):
    _tree = None

    def get(self):
        if not ProcessTreeHandler._tree:
            kevents = map(to_ddict, self.read_kcap("kevt.name in ('EnumProcess', 'CreateProcess')"))
            ProcessTreeHandler._tree = build_tree(kevents)

        self.set_header("Content-Type", "application/json")
        self.write(jsonify(ProcessTreeHandler._tree))


class ProcessHandler(BaseHandler, ABC):
    def get(self, pid):
        # Get all events originated from the given pid
        kevents = list(map(to_ddict, self.read_kcap(f"ps.pid = {pid} or kevt.pid = {pid}")))
        kevt = next(iter([kevt for kevt in kevents if kevt.name in (ktypes.CREATE_PROCESS, ktypes.ENUM_PROCESS)]),
                    None)
        if not kevt:
            self.write_error(500, message=f"process with pid #{pid} not found")

        ps = ps_from_kevt(kevt)

        for kevent in kevents:
            match kevent.name:
                case ktypes.LOAD_IMAGE | ktypes.ENUM_IMAGE:
                    ps.add_module(kevent)

        self.set_header("Content-Type", "application/json")
        self.write(jsonify(ps))


class PacketHandler(BaseHandler, ABC):
    _packets = None

    def get(self):
        if not PacketHandler._packets:
            kevents = list(map(to_ddict, self.read_kcap("kevt.name in ('Accept', 'Recv')")))

            by_dport = Counter()
            by_sport = Counter()

            for kevent in kevents:
                by_dport.update(
                    ['%d (%s)' % (kevent.kparams.dport, kevent.kparams.dport_name)] if kevent.kparams.dport_name else [
                        (kevent.kparams.dport,)])
                by_sport.update((kevent.kparams.sport,))

            PacketHandler._packets = Packets(
                [{"port": c[0], "count": c[1], "pct": (c[1] * 100) / len(kevents)} for c in by_dport.most_common()],
                by_sport.most_common()
            )

        self.set_header("Content-Type", "application/json")
        self.write(jsonify(PacketHandler._packets))
