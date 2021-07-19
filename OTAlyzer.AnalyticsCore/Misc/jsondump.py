from threading import Lock, Thread
from queue import Queue
import base64
import json

from mitmproxy import ctx

FILE_WORKERS = 1
HTTP_WORKERS = 10

# Modified version of https://github.com/mitmproxy/mitmproxy/blob/41199622db6a5f9dc2f0b74e2d38a0d6cd74baa6/examples/complex/jsondump.py
# use it like this: mitmdump -r INPUTFILE.mitm -s jsondump.py --set jsonfilename=./OUTPUTFILE.json


class JSONDumper:
    def __init__(self):
        self.outfile = None
        self.transformations = None
        self.encode = None
        self.url = None
        self.lock = None
        self.auth = None
        self.queue = Queue()

    def done(self):
        self.queue.join()
        if self.outfile:
            self.outfile.close()

    fields = {
        "timestamp": (
            ("error", "timestamp"),
            ("request", "timestamp_start"),
            ("request", "timestamp_end"),
            ("response", "timestamp_start"),
            ("response", "timestamp_end"),
            ("client_conn", "timestamp_start"),
            ("client_conn", "timestamp_end"),
            ("client_conn", "timestamp_tls_setup"),
            ("server_conn", "timestamp_start"),
            ("server_conn", "timestamp_end"),
            ("server_conn", "timestamp_tls_setup"),
            ("server_conn", "timestamp_tcp_setup"),
        ),
        "ip": (
            ("server_conn", "source_address"),
            ("server_conn", "ip_address"),
            ("server_conn", "address"),
            ("client_conn", "address"),
        ),
        "ws_messages": (("messages",),),
        "headers": (("request", "headers"), ("response", "headers"),),
        "content": (("request", "content"), ("response", "content"),),
    }

    def _init_transformations(self):
        self.transformations = [
            {"fields": self.fields["headers"], "func": dict,},
            {"fields": self.fields["timestamp"], "func": lambda t: int(t * 1000),},
            {
                "fields": self.fields["ip"],
                "func": lambda addr: {
                    "host": addr[0].replace("::ffff:", ""),
                    "port": addr[1],
                },
            },
            {
                "fields": self.fields["ws_messages"],
                "func": lambda ms: [
                    {
                        "type": m[0],
                        "from_client": m[1],
                        "content": base64.b64encode(bytes(m[2], "utf-8"))
                        if self.encode
                        else m[2],
                        "timestamp": int(m[3] * 1000),
                    }
                    for m in ms
                ],
            },
        ]

        if self.encode:
            self.transformations.append(
                {"fields": self.fields["content"], "func": base64.b64encode,}
            )

    @staticmethod
    def transform_field(obj, path, func):
        for key in path[:-1]:
            if not (key in obj and obj[key]):
                return
            obj = obj[key]
        if path[-1] in obj and obj[path[-1]]:
            obj[path[-1]] = func(obj[path[-1]])

    @classmethod
    def convert_to_strings(cls, obj):
        if isinstance(obj, dict):
            return {
                cls.convert_to_strings(key): cls.convert_to_strings(value)
                for key, value in obj.items()
            }
        elif isinstance(obj, list) or isinstance(obj, tuple):
            return [cls.convert_to_strings(element) for element in obj]
        elif isinstance(obj, bytes):
            return str(obj)[2:-1]
        return obj

    def worker(self):
        while True:
            frame = self.queue.get()
            self.dump(frame)
            self.queue.task_done()

    def dump(self, frame):
        for tfm in self.transformations:
            for field in tfm["fields"]:
                self.transform_field(frame, field, tfm["func"])
        frame = self.convert_to_strings(frame)

        self.lock.acquire()
        self.outfile.write(json.dumps(frame) + "\n")
        self.lock.release()

    @staticmethod
    def load(loader):
        loader.add_option(
            "jsonfilename", str, "jsonfilename", "Output destination: path to a file."
        )

    def configure(self, _):
        if ctx.options.jsonfilename:
            self.outfile = open(ctx.options.jsonfilename, "a")
            self.url = None
            self.lock = Lock()
            ctx.log.info("Writing all data frames to %s" % ctx.options.jsonfilename)

            self._init_transformations()

            for i in range(FILE_WORKERS if self.outfile else HTTP_WORKERS):
                t = Thread(target=self.worker)
                t.daemon = True
                t.start()

    def response(self, flow):
        self.queue.put(flow.get_state())

    def error(self, flow):
        self.queue.put(flow.get_state())

    def websocket_end(self, flow):
        self.queue.put(flow.get_state())

    def websocket_error(self, flow):
        self.queue.put(flow.get_state())


addons = [JSONDumper()]
