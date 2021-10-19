from filament.utils import dotdictify
from filament.http import HttpServer
from tornado.web import RequestHandler

import os
import json
import signal
import sys

from datetime import date, datetime

__headless__ = True

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError ("Type %s not serializable" % type(obj))

class ProfileHandler(RequestHandler):
    def get(self):
        events = self.read_kcap("kevt.name = 'CreateFile'")
        return self.write(json.dumps(events, default=json_serial))

class Telescope:
    def __init__(self):
        self.procs = {}
        self.http_server = HttpServer(
            os.path.dirname(__file__),
            {},
            [
                (r'/profile', ProfileHandler)
            ]
        )


    def process_kevt(self, kevent):
        match kevent.name:
            case 'EnumProcess':
                self.procs[kevent.seq] = {"name": kevent.kparams.name, "pid": kevent.kparams.pid,
                                          "ppid": kevent.kparams.ppid, "cmdline": kevent.kparams.comm}

    def run(self):
        self.http_server.start()


if __name__ == 'telescope.__init__':
    telescope = Telescope()


def on_init():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    if not __kcapped__:
        print(f"error: {sys.argv[0]} filament needs a capture file. To produce the capture file "
              f"run `fibratus capture -o {sys.argv[0]}`. Use the resulting capture to run the filament "
              f"with `fibratus replay -f {sys.argv[0]} -k {sys.argv[0]}` command")
        sys.exit(0)
    ProfileHandler.read_kcap = read_kcap
    telescope.run()


def on_stop():
    telescope.http_server.stop()

