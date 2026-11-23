"""Child-process OS limits, applied before importing cryptographic decoders."""

import os


class ProcessGuard:
    def __init__(self, memory_bytes, cpu_seconds, cpu_percent):
        self.handle = None
        if os.name == "posix":
            import resource
            import sys

            if sys.platform.startswith("linux"):
                import ctypes as c

                class Header(c.Structure):
                    _fields_ = [("version", c.c_uint32), ("pid", c.c_int)]

                class Caps(c.Structure):
                    _fields_ = [
                        ("effective", c.c_uint32),
                        ("permitted", c.c_uint32),
                        ("inheritable", c.c_uint32),
                    ]

                libc = c.CDLL(None, use_errno=True)
                header = Header(0x20080522, 0)
                caps = (Caps * 2)()
                if (
                    libc.prctl(47, 4, 0, 0, 0) != 0
                    or libc.capset(c.byref(header), c.byref(caps)) != 0
                    or libc.prctl(38, 1, 0, 0, 0) != 0
                ):
                    raise RuntimeError("cannot drop child capabilities")
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
            self.mode = "rlimit_as_cpu"
        elif os.name == "nt":
            self._windows(memory_bytes, cpu_seconds, cpu_percent)
            self.mode = "windows_job_memory_cpu"
        else:
            raise RuntimeError("OS resource isolation unavailable")

    def _windows(self, memory_bytes, cpu_seconds, cpu_percent):
        import ctypes as c
        from ctypes import wintypes as w

        class Basic(c.Structure):
            _fields_ = [
                ("process_time", c.c_int64),
                ("job_time", c.c_int64),
                ("flags", w.DWORD),
                ("min_ws", c.c_size_t),
                ("max_ws", c.c_size_t),
                ("active", w.DWORD),
                ("affinity", c.c_size_t),
                ("priority", w.DWORD),
                ("scheduling", w.DWORD),
            ]

        class IO(c.Structure):
            _fields_ = [
                (name, c.c_uint64)
                for name in (
                    "read_ops",
                    "write_ops",
                    "other_ops",
                    "read_bytes",
                    "write_bytes",
                    "other_bytes",
                )
            ]

        class Extended(c.Structure):
            _fields_ = [
                ("basic", Basic),
                ("io", IO),
                ("process_memory", c.c_size_t),
                ("job_memory", c.c_size_t),
                ("peak_process", c.c_size_t),
                ("peak_job", c.c_size_t),
            ]

        class CPU(c.Structure):
            _fields_ = [("flags", w.DWORD), ("rate", w.DWORD)]

        kernel = c.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = [c.c_void_p, w.LPCWSTR]
        kernel.CreateJobObjectW.restype = w.HANDLE
        kernel.SetInformationJobObject.argtypes = [
            w.HANDLE,
            c.c_int,
            c.c_void_p,
            w.DWORD,
        ]
        kernel.SetInformationJobObject.restype = w.BOOL
        kernel.GetCurrentProcess.restype = w.HANDLE
        kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        kernel.AssignProcessToJobObject.restype = w.BOOL
        kernel.CloseHandle.argtypes = [w.HANDLE]
        job = kernel.CreateJobObjectW(None, None)
        if not job:
            raise OSError(c.get_last_error(), "cannot create job")
        limits = Extended()
        limits.basic.flags = 0x100 | 0x2000 | 0x2
        limits.basic.process_time = cpu_seconds * 10000000
        limits.process_memory = memory_bytes
        rate = CPU(1 | 4, cpu_percent * 100)
        try:
            if not kernel.SetInformationJobObject(
                job, 9, c.byref(limits), c.sizeof(limits)
            ):
                raise OSError(c.get_last_error(), "job memory/CPU-time limit failed")
            if not kernel.SetInformationJobObject(
                job, 15, c.byref(rate), c.sizeof(rate)
            ):
                raise OSError(c.get_last_error(), "job CPU-rate limit failed")
            if not kernel.AssignProcessToJobObject(job, kernel.GetCurrentProcess()):
                raise OSError(c.get_last_error(), "job assignment failed")
        except Exception:
            kernel.CloseHandle(job)
            raise
        self.handle = job


def usage():
    if os.name == "posix":
        from pathlib import Path
        import resource

        rss = int(Path("/proc/self/statm").read_text().split()[1]) * os.sysconf(
            "SC_PAGE_SIZE"
        )
        return rss, resource.getrusage(
            resource.RUSAGE_SELF
        ).ru_utime + resource.getrusage(resource.RUSAGE_SELF).ru_stime
    import ctypes as c
    from ctypes import wintypes as w

    class Memory(c.Structure):
        _fields_ = [("size", w.DWORD), ("faults", w.DWORD)] + [
            (n, c.c_size_t)
            for n in (
                "peak",
                "rss",
                "peak_paged",
                "paged",
                "peak_nonpaged",
                "nonpaged",
                "pagefile",
                "peak_pagefile",
            )
        ]

    class Times(c.Structure):
        _fields_ = [("low", w.DWORD), ("high", w.DWORD)]

    kernel = c.WinDLL("kernel32")
    kernel.GetCurrentProcess.restype = w.HANDLE
    psapi = c.WinDLL("psapi")
    psapi.GetProcessMemoryInfo.argtypes = [w.HANDLE, c.c_void_p, w.DWORD]
    value = Memory()
    value.size = c.sizeof(value)
    if not psapi.GetProcessMemoryInfo(
        kernel.GetCurrentProcess(), c.byref(value), value.size
    ):
        raise OSError("process memory unavailable")
    import time

    return value.rss, time.process_time()
