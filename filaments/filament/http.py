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

import threading
from abc import ABC

import tornado.web
import tornado.httpserver
import tornado.ioloop

import os


class BaseHandler(tornado.web.RequestHandler, ABC):
    """The base handler that contains a common functionality such as
    initializing the CORS headers.
    """

    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "x-requested-with")
        self.set_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')

    def write_error(self, status_code, **kwargs):
        err_cls, err, traceback = kwargs['exc_info']
        self.write(f"Something went wrong. {err}")
        self.finish()


class IndexHandler(tornado.web.RequestHandler, ABC):
    def get(self):
        self.render("index.html")


class HttpServer(threading.Thread):
    """A convenient wrapper around Tornado HTTP server
    to allow running the I/O loop in a separate thread.
    """

    def __init__(self, base_dir, config, handlers):
        super().__init__()
        self.address = config.pop("address", "127.0.0.1")
        self.port = config.pop("port", 8081)
        self.static_prefix = config.pop("static_prefix", "dist")
        self.app = tornado.web.Application([
            (r"/", IndexHandler),
            *handlers,
            (r"/(.*)", tornado.web.StaticFileHandler, {"path": os.path.join(base_dir, self.static_prefix)})
        ],
            static_url_prefix=f"/{self.static_prefix}/",
            static_path=os.path.join(base_dir, self.static_prefix),
            template_path=os.path.join(base_dir, self.static_prefix)
        )
        self.srv = tornado.httpserver.HTTPServer(self.app)

    def run(self):
        """Bootstraps the Tornado web server and starts the I/O loop.
        """
        import asyncio
        from tornado.platform.asyncio import AnyThreadEventLoopPolicy
        # To allow starting the I/O loop in any thread
        asyncio.set_event_loop_policy(AnyThreadEventLoopPolicy())

        # Bootstrap the HTTP server on given address/port
        self.srv.listen(
            self.port,
            self.address
        )
        tornado.ioloop.IOLoop.instance().start()

    def stop(self):
        """Stops the HTTP server and the IO loop.
        """
        self.srv.stop()
        tornado.ioloop.IOLoop.current().stop()
