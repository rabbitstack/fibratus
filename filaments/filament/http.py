import threading
import tornado.web
import tornado.httpserver
import tornado.ioloop

import os


class IndexHandler(tornado.web.RequestHandler):
    def get(self):
        self.render("index.html")


class HttpServer(threading.Thread):
    """A convenient wrapper around Tornado HTTP server
    to allow running the I/O loop in a separate thread.
    """
    def __init__(self, base_dir, config, handlers):
        super().__init__()
        self.address = config.pop("address", "127.0.0.1")
        self.port = config.pop("port", 8080)
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
        self.srv.stop()
        tornado.ioloop.IOLoop.current().stop()



