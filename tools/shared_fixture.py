"""Windows shared-memory interoperability and loss tests, without an EtherCAT NIC."""
import ctypes as C
from ctypes import wintypes as W
import http.client
import importlib.util
import json
import re
import subprocess
import sys
import time
if __package__:
    from .mqtt_fixture import Broker
else:
    from mqtt_fixture import Broker


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
                if stop_locked:
                    assert K.WaitForSingleObject(reader.lock, 100) == 0
                    holding = True
                if stalled:
                    assert K.WaitForSingleObject(reader.lock, 100) == 0
                    try:
                        before = http_cycles(errors)
                        time.sleep(.18)
                        stale = reader.read()  # Recursive mutex acquisition on this same reader thread.
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
        summary = dict(trials=[dict(cycles=r["cycles"], valid=r["valid"], shared_memory=r["shared_memory"], csv_overruns=r["capture"]["overruns"]) for r in reports],
            dacl=descriptor, virtual_invalid_init="passed", retained_handle_collision="passed", restart_identity="passed", writer_death="passed", abandoned_reader="passed", busy_shutdown=busy_stop["shared_memory"])
        (destination / "shared-verification.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return summary
    finally:
        broker.close()
