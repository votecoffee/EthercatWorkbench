"""Read-only Windows EtherCAT Workbench snapshot example; Python standard library only."""
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
import os
import re
import struct
import time

SIZE = 2560
HEADER = 512
CAPACITY = 1024
if os.name == "nt":
    K = C.WinDLL("kernel32", use_last_error=True)
    for name, result, arguments in [
        ("OpenFileMappingW", W.HANDLE, [W.DWORD, W.BOOL, W.LPCWSTR]),
        ("OpenMutexW", W.HANDLE, [W.DWORD, W.BOOL, W.LPCWSTR]),
        ("MapViewOfFile", C.c_void_p, [W.HANDLE, W.DWORD, W.DWORD, W.DWORD, C.c_size_t]),
        ("UnmapViewOfFile", W.BOOL, [C.c_void_p]),
        ("CloseHandle", W.BOOL, [W.HANDLE]),
        ("WaitForSingleObject", W.DWORD, [W.HANDLE, W.DWORD]),
        ("ReleaseMutex", W.BOOL, [W.HANDLE]),
        ("QueryPerformanceCounter", W.BOOL, [C.POINTER(C.c_int64)]),
        ("QueryPerformanceFrequency", W.BOOL, [C.POINTER(C.c_int64)]),
        ("OpenProcess", W.HANDLE, [W.DWORD, W.BOOL, W.DWORD]),
        ("GetProcessTimes", W.BOOL, [W.HANDLE, *[C.POINTER(W.FILETIME)] * 4]),
    ]:
        function = getattr(K, name)
        function.restype, function.argtypes = result, arguments


class AbandonedMutexError(RuntimeError):
    pass


def qpc():
    value, frequency = C.c_int64(), C.c_int64()
    if not K.QueryPerformanceCounter(C.byref(value)) or not K.QueryPerformanceFrequency(C.byref(frequency)):
        raise C.WinError(C.get_last_error())
    return value.value, frequency.value


def process_matches(pid, expected_created):
    handle = K.OpenProcess(0x00101000, False, pid)  # SYNCHRONIZE | QUERY_LIMITED_INFORMATION
    if not handle:
        return False  # Unknown/inaccessible/dead is never usable current input.
    try:
        created, exited, kernel, user = [W.FILETIME() for _ in range(4)]
        if not K.GetProcessTimes(handle, C.byref(created), C.byref(exited), C.byref(kernel), C.byref(user)):
            return False
        actual = (created.dwHighDateTime << 32) | created.dwLowDateTime
        return actual == expected_created and K.WaitForSingleObject(handle, 0) == 258
    finally:
        K.CloseHandle(handle)


def decode(data, now_qpc, frequency, alive):
    if len(data) != SIZE:
        raise ValueError("wrong snapshot size")
    if data == bytes(SIZE):
        return None  # Names reserved; backend/publisher not ready.
    u32 = lambda offset: struct.unpack_from("<I", data, offset)[0]
    u64 = lambda offset: struct.unpack_from("<Q", data, offset)[0]
    u16 = lambda offset: struct.unpack_from("<H", data, offset)[0]
    if data[:8] != b"ECWBIN01" or [u32(n) for n in (8, 12, 16, 20)] != [1, SIZE, HEADER, CAPACITY]:
        raise ValueError("unsupported shared-memory schema/layout")
    flags = u32(268)
    tx, size, last_size = [u32(n) for n in (284, 288, 292)]
    if flags & ~0xfff or tx > CAPACITY or size != (tx if flags & 4 else 0) or last_size != (tx if flags & 8 else 0):
        raise ValueError("invalid snapshot flags/lengths")
    if flags & 4 and (flags & 0x72 != 0x72 or u16(272) != u16(274) or u16(276) & 31 != 4 or u16(278) != 0):
        raise ValueError("inconsistent valid input quality")
    if any(data[HEADER + size:HEADER + CAPACITY]) or any(data[HEADER + CAPACITY + last_size:]):
        raise ValueError("nonzero unused/invalid payload bytes")
    def text(offset):
        raw = data[offset:offset + 64]
        end = raw.find(b"\0")
        if end < 0 or any(raw[end:]):
            raise ValueError("unterminated snapshot text")
        return raw[:end].decode("utf-8")
    counter_ok = frequency > 0 and frequency == u64(256) and now_qpc >= u64(248)
    publication_age = (now_qpc - u64(248)) * 1_000_000 // frequency if counter_ok else None
    sample_age = max(0, u64(48) - u64(80)) + publication_age if publication_age is not None and flags & 2 else None
    usable = bool(alive and counter_ok and flags & 1 and flags & 4 and flags & 256 and
                  u64(64) == u64(56) and sample_age is not None and sample_age <= u32(324) * 1000)
    return dict(schema=1, stream_id=text(344), backend=text(440), publisher_pid=u32(264),
        publisher_created=u64(336), publisher_alive=bool(alive), utc_start_us=struct.unpack_from("<q", data, 32)[0],
        generation=u64(40), publication_index=u64(24), publication_elapsed_us=u64(48), publication_age_us=publication_age,
        active=bool(flags & 1), fresh_at_publication=bool(flags & 256), current_usable=usable,
        event_index=u64(64), cycle_index=u64(72), elapsed_us=u64(80), sample_age_us=sample_age,
        valid=bool(flags & 4), received=bool(flags & 16), expected_wkc=u16(272),
        actual_wkc=u16(274) if flags & 32 else None, al_status=u16(276) if flags & 64 else None,
        al_code=u16(278) if flags & 64 else None, issue=u32(280), tx_bytes=tx,
        payload_hex=data[HEADER:HEADER + size].hex().upper() if flags & 4 else None,
        last_valid=dict(event_index=u64(88), cycle_index=u64(96), elapsed_us=u64(104),
            age_us=max(0, u64(48) - u64(104)) + publication_age if publication_age is not None else None,
            payload_hex=data[HEADER + CAPACITY:HEADER + CAPACITY + last_size].hex().upper()) if flags & 8 else None,
        profile_sha256=data[408:440].hex() if flags & 512 else None,
        expected_identity=[u32(n) for n in (296, 300, 304)] if flags & 128 else None,
        observed_identity=[u32(n) for n in (308, 312, 316)] if flags & 1024 else None,
        station=u16(332), position=u16(334), requested_cycle_us=u32(320), freshness_ms=u32(324), period_ms=u32(328),
        offered=u64(56), drained=u64(120), queue_drops=u64(112), queue_pending=u64(152), coalesced=u64(128),
        written_events=u64(144), writes=u64(160), lock_misses=u64(136), abandoned_recoveries=u64(504),
        cycles=u64(168), valid_exchanges=u64(176), timeouts=u64(184), wkc_mismatches=u64(192), al_mismatches=u64(200),
        transport_errors=u64(208), missed_deadlines=u64(216),
        csv=dict(selected=u64(224), written=u64(232), overruns=u64(240)) if flags & 2048 else None)


class Reader:
    def __init__(self, name):
        if os.name != "nt":
            raise OSError("Windows required")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
            raise ValueError("invalid shared-memory name")
        self.file = self.lock = self.view = None
        prefix = "Local\\EtherCATWorkbench." + name
        try:
            self.file = K.OpenFileMappingW(4, False, prefix + ".data")  # FILE_MAP_READ; never create.
            if not self.file:
                raise C.WinError(C.get_last_error())
            self.lock = K.OpenMutexW(0x00100001, False, prefix + ".lock")  # SYNCHRONIZE | MUTEX_MODIFY_STATE
            if not self.lock:
                raise C.WinError(C.get_last_error())
            self.view = K.MapViewOfFile(self.file, 4, 0, 0, SIZE)
            if not self.view:
                raise C.WinError(C.get_last_error())
        except Exception:
            self.close()
            raise

    def read(self):
        result = K.WaitForSingleObject(self.lock, 0)
        if result == 258:
            return None
        if result not in (0, 128):
            raise C.WinError(C.get_last_error())
        try:
            if result == 128:
                raise AbandonedMutexError("abandoned mutex: discard this snapshot; do not infer live valid input")
            data = C.string_at(self.view, SIZE)
        finally:
            if not K.ReleaseMutex(self.lock):
                raise C.WinError(C.get_last_error())
        now, frequency = qpc()
        pid = struct.unpack_from("<I", data, 264)[0]
        created = struct.unpack_from("<Q", data, 336)[0]
        return decode(data, now, frequency, process_matches(pid, created))

    def close(self):
        if self.view:
            K.UnmapViewOfFile(self.view)
            self.view = None
        for name in ("lock", "file"):
            handle = getattr(self, name, None)
            if handle:
                K.CloseHandle(handle)
                setattr(self, name, None)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="bench")
    parser.add_argument("--seconds", type=float, default=5)
    parser.add_argument("--interval-ms", type=int, default=100)
    args = parser.parse_args()
    if not 0 < args.seconds <= 86400 or not 1 <= args.interval_ms <= 60000:
        parser.error("invalid duration/interval")
    with Reader(args.name) as reader:
        end = time.monotonic() + args.seconds
        while time.monotonic() < end:
            value = reader.read()
            if value is not None:
                print(json.dumps(value), flush=True)
            time.sleep(args.interval_ms / 1000)


if __name__ == "__main__":
    main()
