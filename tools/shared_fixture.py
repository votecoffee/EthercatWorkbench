"""Windows shared-memory interoperability and loss tests, without an EtherCAT NIC."""
import ctypes as C
from ctypes import wintypes as W
import http.client
import importlib.util
import json
import hashlib
import re
import subprocess
import struct
import sys
import time
if __package__:
    from .mqtt_fixture import Broker
else:
    from mqtt_fixture import Broker


def historical_active_fixture(original):
    """Author a coherent zero-age historical publication; never alter the raw receipt."""
    active = bytearray(original)
    flags = struct.unpack_from("<I", active, 268)[0]
    publication, offered, latest_event, _, latest_elapsed = struct.unpack_from("<QQQQQ", active, 48)
    qpc, frequency = struct.unpack_from("<QQ", active, 248)
    assert flags & 4 and latest_event == offered and publication >= latest_elapsed
    age_ticks = (publication - latest_elapsed) * frequency // 1_000_000
    assert qpc >= age_ticks
    struct.pack_into("<Q", active, 48, latest_elapsed)
    struct.pack_into("<Q", active, 248, qpc - age_ticks)
    struct.pack_into("<I", active, 268, flags | 0x101)
    return active


def verify_shared_memory(cli, root, destination, cli_call):
    spec = importlib.util.spec_from_file_location("shared_reader", root / "examples/read_shared_memory.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    K = module.K
    name = "verify_" + str(__import__("os").getpid()) + "_" + str(time.time_ns())
    broker = Broker()

    def acl(reader):
        adv = C.WinDLL("advapi32", use_last_error=True)
        adv.GetSecurityInfo.argtypes = [W.HANDLE, C.c_int, W.DWORD, *[C.POINTER(C.c_void_p)] * 5]
        adv.GetSecurityInfo.restype = W.DWORD
        adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [C.c_void_p, W.DWORD, W.DWORD, C.POINTER(C.c_void_p), C.POINTER(W.DWORD)]
        adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = W.BOOL
        K.LocalFree.argtypes, K.LocalFree.restype = [C.c_void_p], C.c_void_p
        handle = K.OpenFileMappingW(0x20004, False, "Local\\EtherCATWorkbench." + name + ".data")
        assert handle
        sd, text = C.c_void_p(), C.c_void_p()
        try:
            assert adv.GetSecurityInfo(handle, 6, 4, None, None, None, None, C.byref(sd)) == 0
            assert adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, 4, C.byref(text), None)
            value = C.wstring_at(text)
            assert "D:P" in value and ";;;OW)" in value and ";;;SY)" in value
            assert all(";;;" + sid + ")" not in value for sid in ["WD", "AU", "BU", "BA"])
            return value
        finally:
            if text.value:
                K.LocalFree(text)
            if sd.value:
                K.LocalFree(sd)
            K.CloseHandle(handle)

    def http_cycles(errors):
        match = re.search(r"HTTP input feed bound at http://127\.0\.0\.1:(\d+)", errors.read_text(encoding="utf-8"))
        if not match:
            return None
        client = http.client.HTTPConnection("127.0.0.1", int(match.group(1)), timeout=.5)
        try:
            client.request("GET", "/v1/status")
            response = client.getresponse()
            data = json.loads(response.read())
            return data["data"]["acquisition"]["cycles"] if data["data"]["acquisition"] else None
        except (OSError, http.client.HTTPException):
            return None
        finally:
            client.close()

    def run(label, profile, seconds=2, extra=(), stalled=False, kill=False, stop_locked=False):
        base = destination / label
        config = base.with_suffix(".profile.json")
        config.write_text(json.dumps(profile), encoding="utf-8")
        output, errors = base.with_suffix(".stdout.json"), base.with_suffix(".stderr.txt")
        reader = None
        holding = False
        records = []
        with output.open("wb") as stdout, errors.open("wb") as stderr:
            proc = subprocess.Popen([str(cli), "run", str(config), "--seconds", str(seconds),
                "--csv", str(base.with_suffix(".csv")), "--report", str(base.with_suffix(".json")), *extra], stdout=stdout, stderr=stderr)
            try:
                until = time.monotonic() + 5
                while time.monotonic() < until:
                    try:
                        if reader is None:
                            reader = module.Reader(name)
                        value = reader.read()
                        if value and value["event_index"] and value["valid"]:
                            break
                    except OSError:
                        pass
                    assert proc.poll() is None, errors.read_text(encoding="utf-8")
                    time.sleep(.005)
                else:
                    raise AssertionError("shared snapshot never became ready")
                descriptor = acl(reader)
                # The native CLI is a separate consumer process, using the same byte contract.
                native = None
                for _ in range(30):
                    native = cli_call(cli, "read-shared", name, "--profile", config)
                    if native["status"] == "ready" and native["snapshot"]["latest"]:
                        break
                    time.sleep(.005)
                assert native["status"] == "ready" and native["snapshot"]["latest"]
                assert native["decoding"]["profile_sha256"] == native["snapshot"]["profile_sha256"]
                if stop_locked:
                    assert K.WaitForSingleObject(reader.lock, 100) == 0
                    holding = True
                if stalled:
                    assert K.WaitForSingleObject(reader.lock, 100) == 0
                    try:
                        before = http_cycles(errors)
                        time.sleep(.18)
                        stale = reader.read()  # Recursive mutex acquisition on this same reader thread.
                        busy = cli_call(cli, "read-shared", name)
                        assert busy["status"] == "busy" and busy["snapshot"] is None and busy["raw_sha256"] is None and not busy["current_usable"]
                        blocked = base.with_suffix(".busy.bin")
                        cli_call(cli, "read-shared", name, "--save-raw", blocked, success=False)
                        assert not blocked.exists()
                        after = http_cycles(errors)
                        assert stale["valid"] and not stale["current_usable"]
                        assert after is not None and before is not None and after > before
                    finally:
                        assert K.ReleaseMutex(reader.lock)
                if kill:
                    proc.kill()
                    proc.wait(timeout=3)
                    value = reader.read()
                    assert value["active"] and value["valid"] and not value["publisher_alive"] and not value["current_usable"]
                    dead = cli_call(cli, "read-shared", name, "--profile", config)
                    assert dead["snapshot"]["active"] and not dead["current_usable"]
                    assert dead["observation"]["process"] in ("exited", "identity_mismatch")
                    return reader, value, records, descriptor
                while proc.poll() is None:
                    value = reader.read()
                    if value:
                        records.append(value)
                    time.sleep(.005)
                proc.wait(timeout=3)
                assert proc.returncode == 0, errors.read_text(encoding="utf-8")
                if holding:
                    assert K.ReleaseMutex(reader.lock)
                    holding = False
                final = reader.read()
                assert final["active"] == stop_locked and not final["current_usable"]
                assert K.WaitForSingleObject(reader.lock, 100) == 0
                try:
                    base.with_suffix(".snapshot.bin").write_bytes(C.string_at(reader.view, module.SIZE))
                finally:
                    assert K.ReleaseMutex(reader.lock)
                report = json.loads(base.with_suffix(".json").read_bytes())
                memory = report["shared_memory"]
                assert not memory["active"] and not memory["worker_failed"] and memory["worker_error"] is None and memory["shutdown_written"] != stop_locked
                assert memory["offered"] == report["cycles"] == memory["drained"] + memory["queue_drops"] + memory["queue_pending"]
                assert memory["drained"] == memory["coalesced"] + memory["written_events"] + memory["unsent_events"]
                assert memory["queue_pending"] == 0 and memory["unsent_events"] == int(stop_locked)
                assert report["capture"]["overruns"] == 0 and report["capture"]["written"] == report["valid"]
                assert report["http"]["queue_drops"] == 0 and report["mqtt"]["write_completions"] > 0
                audit = cli_call(cli, "verify-capture", base.with_suffix(".json"), base.with_suffix(".csv"))
                assert audit["rows"] == report["valid"]
                saved = base.with_suffix(".native.bin")
                exported = base.with_suffix(".native.json")
                native = cli_call(cli, "read-shared", name, "--run-report", base.with_suffix(".json"), "--save-raw", saved, "--out", exported)
                assert native == json.loads(exported.read_bytes()) and not native["current_usable"]
                assert native["snapshot"]["stream_id"] == final["stream_id"]
                assert saved.read_bytes() == base.with_suffix(".snapshot.bin").read_bytes()
                offline = cli_call(cli, "inspect-shared", saved, "--run-report", base.with_suffix(".json"))
                assert offline["source"]["kind"] == "saved_file" and offline["observation"] is None and not offline["current_usable"]
                assert offline["raw_sha256"] == native["raw_sha256"] and offline["decoding"] == native["decoding"]
                if native["snapshot"]["latest"]["valid_at_exchange"]:
                    latest = native["snapshot"]["latest"]["data"]
                    count = int.from_bytes(bytes.fromhex(latest["payload_hex"])[:2], "little")
                    assert latest["values"]["Counter"] == str(count)
                    assert latest["values"]["Scaled counter"] == str(count / 4).removesuffix(".0")
                if stalled:
                    assert memory["lock_misses"] > 0 and memory["coalesced"] > 0
                (base.with_suffix(".observed.json")).write_text(json.dumps(records[-32:], indent=2), encoding="utf-8")
                return reader, report, records, descriptor
            except Exception:
                if holding:
                    K.ReleaseMutex(reader.lock)
                    holding = False
                if reader:
                    reader.close()
                raise
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()

    def settings(profile):
        profile.update(shared_memory=dict(name=name, period_ms=5, freshness_ms=20), http=dict(port=0), mqtt=dict(port=broker.port, period_ms=10))
        return profile

    reports = []
    try:
        for schedule in ["deadline", "relative"]:
            profile = settings(json.loads((root / "samples/synthetic.json").read_bytes()))
            profile["scheduler"] = schedule  # Persist the exact effective profile for typed readers.
            profile["tx"][2]["log"] = False
            reader, report, records, descriptor = run(schedule, profile, extra=["--scheduler", schedule], stalled=True)
            try:
                for record in records:
                    assert record["stream_id"] == report["shared_memory"]["stream_id"]
                    assert record["profile_sha256"] == report["context"]["profile_sha256"]
                    if record["valid"]:
                        payload = bytes.fromhex(record["payload_hex"])
                        assert len(payload) == 8 and record["actual_wkc"] == 1 and record["al_status"] == 4
                # Retained reader handles must prevent a new writer before any virtual ESC setup.
                old = reader.read()
                rejected = cli_call(cli, "run", root / "samples/virtual.json", "--backend", "virtual", "--shared-memory", name, "--seconds", 1, success=False)
                assert rejected["cycles"] == 0 and rejected["virtual_esc"] is None and "name already exists" in rejected["error"]
                assert reader.read()["publication_index"] == old["publication_index"]
            finally:
                reader.close()
            reports.append(report)
        assert reports[0]["shared_memory"]["stream_id"] != reports[1]["shared_memory"]["stream_id"]
        compared = cli_call(cli, "compare-runs", destination / "deadline.json", destination / "relative.json", "--csv", destination / "deadline.csv", "--csv", destination / "relative.csv")
        assert all(t["shared_memory"]["lock_misses"] > 0 for t in compared["trials"])
        assert any("shared memory loss" in w for w in compared["warnings"])
        (destination / "comparison.json").write_text(json.dumps(compared, indent=2), encoding="utf-8")
        profile = settings(json.loads((root / "samples/synthetic.json").read_bytes()))
        reader, busy_stop, _, _ = run("busy-stop", profile, stop_locked=True)
        assert busy_stop["shared_memory"]["lock_misses"] > 0
        reader.close()
        profile = settings(json.loads((root / "samples/virtual.json").read_bytes()))
        profile["input_loss_timeout_ms"] = 0
        reader, lost, records, _ = run("lost", profile, 1, ["--backend", "virtual", "--virtual-fault", "io-lost", "--input-loss-timeout-ms", "0"])
        try:
            invalid = [r for r in records if not r["valid"]]
            assert invalid and all(r["payload_hex"] is None and r["actual_wkc"] is None and r["al_status"] is None and r["last_valid"] and not r["current_usable"] for r in invalid)
            assert lost["stopped_al"] == [1, 0]
            assert all(lost["virtual_esc"][key] == 0 for key in ["logical_writes", "physical_output_writes", "coe_downloads", "op_requests", "dc_enable_requests"])
        finally:
            reader.close()
        profile = settings(json.loads((root / "samples/synthetic.json").read_bytes()))
        reader, dead, _, _ = run("killed", profile, 20, kill=True)
        try:
            # A separate reader process dies owning the mutex, after the writer is gone.
            script = "import importlib.util,sys; s=importlib.util.spec_from_file_location('r',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);r=m.Reader(sys.argv[2]);assert m.K.WaitForSingleObject(r.lock,100)==0"
            subprocess.run([sys.executable, "-B", "-c", script, str(root / "examples/read_shared_memory.py"), name], check=True, timeout=5)
            abandoned = cli_call(cli, "read-shared", name)
            assert abandoned["status"] == "abandoned" and abandoned["snapshot"] is None and abandoned["raw_sha256"] is None
            subprocess.run([sys.executable, "-B", "-c", script, str(root / "examples/read_shared_memory.py"), name], check=True, timeout=5)
            try:
                reader.read()
            except module.AbandonedMutexError:
                pass
            else:
                raise AssertionError("abandoned reader snapshot was accepted")
            assert not reader.read()["current_usable"]
        finally:
            reader.close()
        try:
            module.Reader(name)
        except OSError:
            pass
        else:
            raise AssertionError("mapping survived all handles closing")
        cli_call(cli, "read-shared", name, success=False)
        # Saved-file CLI checks are independent of current IPC and process liveness.
        original = (destination / "deadline.native.bin").read_bytes()
        run_file = destination / "deadline.json"
        original_hash = hashlib.sha256(original).hexdigest()
        raw = cli_call(cli, "inspect-shared", destination / "deadline.native.bin")
        assert raw["raw_sha256"] == original_hash and raw["decoding"] is None and raw["snapshot"]["latest"]["data"]["values"] is None
        flags = struct.unpack_from("<I", original, 268)[0]
        active = historical_active_fixture(original)
        active_file = destination / "historical-active.bin"
        active_file.write_bytes(active)
        historical = cli_call(cli, "inspect-shared", active_file, "--run-report", run_file)
        assert historical["snapshot"]["active"] and historical["snapshot"]["fresh_at_publication"] and not historical["current_usable"]
        assert historical["snapshot"]["latest"]["age_us_at_publication"] == 0
        assert historical["publication_age_us"] is None and historical["observation"] is None
        assert historical["snapshot"]["latest"]["observed_age_us"] is None
        stale = bytearray(active)
        elapsed = struct.unpack_from("<Q", stale, 48)[0]
        qpc, frequency = struct.unpack_from("<QQ", stale, 248)
        age_us = struct.unpack_from("<I", stale, 324)[0] * 1000 + 1
        struct.pack_into("<Q", stale, 48, elapsed + age_us)
        struct.pack_into("<Q", stale, 248, qpc + age_us * frequency // 1_000_000)
        stale_file = destination / "historical-invalid-fresh.bin"
        stale_file.write_bytes(stale)
        assert "inconsistent fresh-at-publication flag" in cli_call(cli, "inspect-shared", stale_file, success=False)
        assert (destination / "deadline.native.bin").read_bytes() == original
        wrong = json.loads(run_file.read_bytes())["context"]["profile"]
        wrong["tx"][0]["name"] = "Changed mapping"
        wrong_file = destination / "wrong-profile.json"
        wrong_file.write_text(json.dumps(wrong), encoding="utf-8")
        failed_out = destination / "must-not-export.json"
        cli_call(cli, "inspect-shared", active_file, "--profile", wrong_file, "--out", failed_out, success=False)
        assert not failed_out.exists()
        for index, (offset, replacement) in enumerate([(12, 2559), (268, flags | 4096), (284, 1025), (256, 0)]):
            malformed = bytearray(original)
            struct.pack_into("<I", malformed, offset, replacement)
            path = destination / f"bad-header-{index}.bin"
            path.write_bytes(malformed)
            cli_call(cli, "inspect-shared", path, "--out", failed_out, success=False)
            assert not failed_out.exists()
        for label, data in [("short", original[:-1]), ("long", original + b"\0")]:
            path = destination / f"{label}.bin"
            path.write_bytes(data)
            cli_call(cli, "inspect-shared", path, success=False)
        reserved = destination / "reserved.bin"
        reserved.write_bytes(bytes(2560))
        assert cli_call(cli, "inspect-shared", reserved)["status"] == "not_ready"
        cli_call(cli, "read-shared", name, "--save-raw", destination / "deadline.native.bin", "--out", failed_out, success=False)
        assert not failed_out.exists() and hashlib.sha256((destination / "deadline.native.bin").read_bytes()).hexdigest() == original_hash
        cli_call(cli, "inspect-shared", active_file, "--out", destination / "deadline.native.json", success=False)
        cli_call(cli, "compare-runs", run_file, destination / "deadline.native.json", success=False)
        summary = dict(trials=[dict(cycles=r["cycles"], valid=r["valid"], shared_memory=r["shared_memory"], csv_overruns=r["capture"]["overruns"]) for r in reports],
            dacl=descriptor, virtual_invalid_init="passed", retained_handle_collision="passed", restart_identity="passed", writer_death="passed", abandoned_reader="passed", busy_shutdown=busy_stop["shared_memory"], native_reader_and_typed_review="passed", offline_rejections="passed")
        (destination / "shared-verification.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return summary
    finally:
        broker.close()
