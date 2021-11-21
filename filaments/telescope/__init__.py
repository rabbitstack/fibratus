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

"""
Inspects your
"""

from filament.http import HttpServer
from telescope.handlers import NavbarHandler, ProcessTreeHandler, ProcessHandler, IngressPacketsHandler
import os
import signal
import sys


__headless__ = True


class Telescope:
    def __init__(self):
        self.http_server = HttpServer(
            os.path.dirname(__file__),
            {},
            [
                (r'/navbar', NavbarHandler),
                (r'/processes', ProcessTreeHandler),
                (r'/processes/(\d+)', ProcessHandler),
                (r'/ingress', IngressPacketsHandler)
            ],
        )

    def run(self):
        self.http_server.start()


if __name__ == 'telescope.__init__':
    telescope = Telescope()


def on_init():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    if not __is_kcap__:
        print(f"error: {sys.argv[0]} filament needs a capture file. To produce the capture file "
              f"run `fibratus capture -o {sys.argv[0]}`. Use the resulting capture to run the filament "
              f"with `fibratus replay -f {sys.argv[0]} -k {sys.argv[0]}` command")
        sys.exit(0)
    # Augment handler classes with the read_kcap method
    for kclass in [ProcessTreeHandler, ProcessHandler, IngressPacketsHandler]:
        kclass.read_kcap = read_kcap
    telescope.run()


def on_stop():
    telescope.http_server.stop()

