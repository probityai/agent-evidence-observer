"""Read-only native A2A callback capture; no early returns or request changes."""

from google.protobuf.json_format import MessageToJson
from google.protobuf.message import Message
from a2a.client import ClientCallInterceptor

from .contract import encode, require


def native(value):
    if isinstance(value, Message):
        raw = MessageToJson(value, preserving_proto_field_name=True).encode()
        return {"protobufJSONHex": raw.hex(),
                "protobufHex": value.SerializeToString(deterministic=True).hex(),
                "protobufType": value.DESCRIPTOR.full_name}
    if isinstance(value, (tuple, list)):
        return [native(v) for v in value]
    if value is None:
        return None
    raise TypeError("unselected-native-callback-type")


class Capture(ClientCallInterceptor):
    def __init__(self):
        self.records = []
        self.closed = False
        self.failures = 0

    async def before(self, args):
        self.append("before", args.method, args.input)
        require(args.early_return is None, "unselected-early-return")

    async def after(self, args):
        self.append("after", args.method, args.result)
        require(args.early_return is False, "unselected-early-return")

    def append(self, phase, method, value):
        try:
            require(not self.closed, "capture-after-close")
            self.records.append({"sequence": len(self.records), "phase": phase,
                                 "method": method, "native": native(value)})
        except Exception:
            self.failures += 1
            raise

    def close(self):
        self.closed = True
        return {"records": self.records, "closed": self.closed,
                "failures": self.failures, "mutatesRequests": False}
