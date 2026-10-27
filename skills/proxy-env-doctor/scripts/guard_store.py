"""Durable private JSON and a crash-releasing exclusive OS file lock."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile
import time


def save(path, value):
    write_bytes(path, json.dumps(value, ensure_ascii=False, indent=2).encode('utf-8'))


def write_bytes(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        # Windows scanners can briefly open a newly replaced file without delete
        # sharing. Retry only that bounded sharing/access failure, never truncate.
        for attempt in range(10):
            try:
                os.replace(temporary, path)
                break
            except PermissionError:
                if os.name != 'nt' or attempt == 9:
                    raise
                time.sleep(0.03)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def lock(path):
    with open(path, 'a+b') as stream:
        stream.seek(0, 2)
        if stream.tell() == 0:
            stream.write(b'0'); stream.flush()
        stream.seek(0)
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            if os.name == 'nt':
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)
