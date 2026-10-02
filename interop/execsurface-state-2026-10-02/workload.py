"""One silent, declared overwrite; snapshots are taken by the companion."""
import os
import sys

fd = os.open(sys.argv[1], os.O_WRONLY)
try:
    if os.write(fd, b"updated1\n") != 9:
        raise RuntimeError("short write")
    os.fsync(fd)
finally:
    os.close(fd)
