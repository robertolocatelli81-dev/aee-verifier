"""What the tests need from the system, with its equivalent where a system lacks it (2026-11-27).

- An address-space limit for a child (resource.RLIMIT_AS through preexec_fn) is enforced on Linux only: macOS accepts
  and ignores it, Windows has neither resource nor preexec_fn. ``memory_limit`` gives the preexec function on Linux and
  None elsewhere; the branch the limit reaches (MemoryError) is also reached by fault injection on every system.
- An endless input: /dev/zero (Linux, macOS); on Windows a named pipe that a thread fills with zeros until the reader
  closes it (``Endless``)."""

import os
import sys
import threading
import uuid

try:
    import resource
except ImportError:                     # Windows
    resource = None

LIMITS_MEMORY = sys.platform.startswith("linux") and resource is not None


def memory_limit(nbytes):
    if not LIMITS_MEMORY:
        return None

    def limit():
        resource.setrlimit(resource.RLIMIT_AS, (nbytes, nbytes))
    return limit


class Endless:
    """``with Endless() as path``: a path that reads zeros without end."""

    def __enter__(self):
        if os.path.exists("/dev/zero"):
            return "/dev/zero"
        import _winapi
        path = r"\\.\pipe\aee-endless-" + uuid.uuid4().hex
        # PIPE_ACCESS_OUTBOUND (0x2), PIPE_TYPE_BYTE | PIPE_WAIT (0), one instance
        handle = _winapi.CreateNamedPipe(path, 0x2, 0, 1, 1 << 16, 1 << 16, 0, _winapi.NULL)

        def serve():
            try:
                try:
                    _winapi.ConnectNamedPipe(handle, False)
                except OSError as e:
                    if getattr(e, "winerror", None) != 535:       # ERROR_PIPE_CONNECTED: the reader came first
                        return
                block = bytes(1 << 16)
                while True:
                    _winapi.WriteFile(handle, block)
            except OSError:                                         # the reader closed the pipe
                pass
            finally:
                _winapi.CloseHandle(handle)
        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()
        return path

    def __exit__(self, *exc):
        if getattr(self, "thread", None) is not None:
            self.thread.join(10)
