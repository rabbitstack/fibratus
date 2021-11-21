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
from datetime import datetime
import os
from filament.utils import sizeof_fmt


class PS:
    def __init__(self, pid, name, exe, cmdline, cwd, sid, start_time):
        self.pid = pid
        self.name = name
        self.exe = exe
        self.cmdline = cmdline
        self.cwd = cwd
        self.sid = sid
        self.start_time = start_time.isoformat() if isinstance(start_time, datetime) else ""

        # Unique value used for table row keys
        self.id = self.name + str(self.pid) + self.start_time

        self.modules = []

    def add_module(self, kevt):
        filename = os.path.basename(kevt.kparams.file_name)
        if filename != self.name:
            self.modules.append(Module(filename, kevt.kparams.file_name, sizeof_fmt(kevt.kparams.image_size)))

    def __str__(self):
        return f"pid: {self.pid}, name: {self.name}"


class Module:
    def __init__(self, name, path, size):
        self.name = name
        self.path = path
        self.size = size


class Packets:
    def __init__(self, dport, sport):
        self.dport = dport
        self.sport = sport
