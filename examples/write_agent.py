"""A small workload that writes through the host broker."""

import json
import socket
import sys


message = sys.argv[1] if len(sys.argv) > 1 else "one observed write"
request = {"requestId": "sample-1", "path": "/work/result.txt", "contentHex": (message + "\n").encode("ascii").hex()}
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.connect("/broker/write.sock")
    client.sendall(json.dumps(request, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n")
    response = json.loads(client.makefile("rb").readline(65537))
if not response.get("ok"):
    raise SystemExit(1)
print("done")
