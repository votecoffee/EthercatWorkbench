"""Verify the Windows CLI, synthetic capture pipeline and optional GUI smoke run."""
import argparse
import csv
import ctypes
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import subprocess
import struct
import socket
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__:
    from .mqtt_fixture import verify_mqtt
    from .shared_fixture import verify_shared_memory
else:
    from mqtt_fixture import verify_mqtt
    from shared_fixture import verify_shared_memory


def cli_call(cli, *args, success=True):
    result = subprocess.run([cli, *map(str, args)], text=True, encoding="utf-8",
                            capture_output=True, timeout=40)
    assert (result.returncode == 0) == success, (args, result.stdout, result.stderr)
    return json.loads(result.stdout) if result.stdout else result.stderr


def rows(path):
    result = []
    parts = sorted(path.parent.glob(f"{path.stem}.*.csv"))
    for part in parts:
        with part.open(encoding="utf-8", newline="") as stream:
            record = list(csv.DictReader(stream, strict=True))
            assert record and len(record) <= 500, part
            result.extend(record)
    return parts, result


def verify_csv(report, base, generation=1, change=False, faults=False, virtual=False):
    assert report["error"] is None, report
    assert report["valid"] > 0 and report["expected_wkc"] == 1
    assert report["send_spacing"]["count"] == report["cycles"] - 1
    assert report["receive_spacing"]["count"] == report["replies"] - 1
    valid_spacing = report["valid_receive_spacing"]
    assert valid_spacing["count"] == report["valid"] - 1
    values = [valid_spacing[k] for k in ("p50_us", "p95_us", "p99_us", "longest_gap_us")]
    if valid_spacing["count"]:
        assert all(v is not None for v in values) and values == sorted(values)
        assert values[-1] <= report["cyclic_elapsed_us"]
    else:
        assert values == [None] * 4
    if report["valid"] == report["replies"]:
        assert valid_spacing == report["receive_spacing"]
    assert report["requested_cycle_us"] == 1000
    parts, entries = rows(base)
    cap = report["capture"]
    assert len(parts) == cap["parts"]
    assert cap["overruns"] == 0
    assert len(entries) == cap["written"] == cap["selected"] > 0
    times = [int(r["elapsed_us"]) for r in entries]
    assert all(a <= b for a, b in zip(times, times[1:]))
    if not change:
        assert len(entries) == report["valid"]
        if len(times) > 1:
            # Difference of two truncated elapsed timestamps differs from a truncated interval by at most 1 us.
            assert abs(max(b - a for a, b in zip(times, times[1:])) - valid_spacing["longest_gap_us"]) <= 1
    cycles = [int(r["cycle_index"]) for r in entries]
    assert all(a < b for a, b in zip(cycles, cycles[1:]))
    assert datetime.datetime.fromisoformat(cap["utc_start"]).utcoffset() == datetime.timedelta()
    previous_counter = -1
    for index, (row, cycle) in enumerate(zip(entries, cycles), 1):
        assert int(row["connection_generation"]) == generation
        assert int(row["sample_index"]) == index
        assert row["capture_start_utc"] == cap["utc_start"]
        counter = int(row["Counter"])
        if virtual:
            # The authored ESC advances per LRD, while cycle_index includes skipped deadline slots.
            if change:
                assert previous_counter < counter <= (report["cycles"] - 1) // 4
                if report["timeouts"] == 0:
                    assert counter == index - 1
            else:
                assert (index - 1) // 4 <= counter <= (index - 1 + report["timeouts"]) // 4
            previous_counter = counter
        else:
            assert counter == ((cycle - 1) // 4) % 65536
        assert row["Sensor active"] == str(bool(counter & 1)).lower()
        assert float(row["Scaled counter"]) == counter / 4
        if faults:
            assert cycle % 97 and cycle % 149
    if faults:
        assert report["timeouts"] > 0 and report["wkc_mismatches"] > 0
        assert report["cycles"] == report["valid"] + report["wkc_mismatches"] + report["timeouts"]
    pairs = zip(entries, entries[1:])
    if change:
        assert len(entries) < report["valid"]
        assert all(a["Counter"] != b["Counter"] for a, b in pairs)
    else:
        assert len(entries) == report["valid"]
        assert any(a["Counter"] == b["Counter"] for a, b in pairs)


def gui_trial(gui, profile, destination, scheduler, seconds):
    case = destination / f"gui-{scheduler}"
    report = case.with_suffix(".json")
    base = case.with_suffix(".csv")
    saved = case.with_suffix(".profile.json")
    config = json.loads(profile.read_text(encoding="utf-8"))
    config["scheduler"] = scheduler
    saved.write_text(json.dumps(config), encoding="utf-8")
    with subprocess.Popen([gui, "--profile", saved, "--simulate-seconds", str(seconds),
                           "--csv", base, "--report", report]) as process:
        try:
            user32 = ctypes.windll.user32
            user32.FindWindowW.restype = ctypes.c_void_p
            user32.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
            user32.IsWindowVisible.argtypes = [ctypes.c_void_p]
            deadline = time.monotonic() + 15
            found = False
            while process.poll() is None and time.monotonic() < deadline:
                window = user32.FindWindowW(None, "EtherCAT Workbench")
                if window and user32.IsWindowVisible(window):
                    pid = ctypes.c_ulong()
                    user32.GetWindowThreadProcessId(window, ctypes.byref(pid))
                    if pid.value == process.pid:
                        found = True
                        break
                time.sleep(0.05)
            assert found, "expected visible Workbench window owned by the test process"
            assert process.wait(timeout=seconds + 15) == 0
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    result = json.loads(report.read_text(encoding="utf-8"))
    assert result["scheduler"] == scheduler
    verify_csv(result, base)
    return result



def audit_capture(cli, report_path, base, report):
    receipt = cli_call(cli, "verify-capture", report_path, base)
    assert receipt["report_sha256"] == hashlib.sha256(report_path.read_bytes()).hexdigest()
    assert receipt["profile_sha256"] == report["context"]["profile_sha256"]
    assert receipt["rows"] == report["capture"]["written"]
    assert receipt["selected"] == report["capture"]["selected"]
    assert receipt["valid_exchanges"] == report["valid"]
    assert receipt["invalid_exchanges"] == report["cycles"] - report["valid"]
    assert receipt["reply_timeouts"] == report["timeouts"]
    assert receipt["wkc_mismatches"] == report["wkc_mismatches"]
    assert receipt["state_mismatches"] == report["state_mismatches"]
    assert receipt["transport_errors"] == report["transport_errors"]
    assert receipt["logger_overruns"] == report["capture"]["overruns"]
    assert receipt["connection_generation"] == report["connection_generation"]
    assert receipt["run_error"] == report["error"] and receipt["run_cancelled"] == report["cancelled"]
    for part in receipt["parts"]:
        path = Path(part["file"])
        assert part["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert part["bytes"] == path.stat().st_size
    return receipt


def verify_virtual(cli, profile, destination, reports, model="coe"):
    model_flags = ["--virtual-model", model]
    prefix = "virtual" if model == "coe" else f"virtual-{model}"
    for on_change in (False, True):
        base = destination / ("virtual-change.csv" if on_change else "virtual-every.csv")
        flags = ["--on-change"] if on_change else []
        report = cli_call(cli, "run", profile, "--backend", "virtual", *model_flags, "--seconds", 1, "--csv", base, *flags)
        (destination / (base.stem + ".json")).write_text(json.dumps(report, indent=2), encoding="utf-8")
        audit_capture(cli, destination / (base.stem + ".json"), base, report)
        assert report["error"] is None and report["valid"] >= 100, report
        assert report["cycles"] == report["valid"] + report["timeouts"], report
        assert report["wkc_mismatches"] == report["state_mismatches"] == 0, report
        assert report["stopped_al"] == [1, 0] and report["setup_failure_al"] is None
        esc = report["virtual_esc"]
        assert esc["state_requests"] == [1, 2, 4, 1]
        assert esc["sii_reads"] > 0
        assert esc["coe_uploads"] >= 24 if model != "sii" else esc["coe_uploads"] == 0
        assert esc["model"] == model.replace("-", "_")
        sync = report["synchronization"]
        dc = sync["dc"]
        assert dc["requested_sync"] == "disabled"
        assert dc["enhanced_sync_supported"] == (model == "coe-dc")
        assert dc["static_sync_iterations"] == 0 and dc["cyclic_clock_distribution"] is False
        if model == "coe-dc":
            assert dc["support"] == "Bits64" and dc["initial_offset_setup_attempted"] is True
            assert dc["activation"] == {"value": 0, "unavailable": None}
            assert dc["assign_activate"] == {"value": 0, "unavailable": None}
            assert dc["sync0_cycle_ns"] == dc["sync1_cycle_ns"] == {"value": 0, "unavailable": None}
            assert dc["system_time_offset_ns"]["value"] > 0
            assert dc["transmission_delay_ns"] == {"value": 0, "unavailable": None}
            assert esc["dc_latches"] == 1 and esc["dc_offset_writes"] == esc["dc_delay_writes"] == 2
            assert esc["dc_activation_writes"] == 1
        else:
            assert dc["support"] == "None" and dc["initial_offset_setup_attempted"] is False
            assert dc["activation"] is dc["sync0_cycle_ns"] is dc["sync1_cycle_ns"] is None
            assert dc["system_time_offset_ns"] is dc["transmission_delay_ns"] is None
        assert esc["dc_enable_requests"] == esc["dc_clock_distribution"] == 0
        if model != "sii":
            assert sync["tx_sync_type"]["value"] == sync["rx_sync_type"]["value"] == 0
            assert sync["coe_cycle"]["tx"] == dict(object_index=0x1c33, cycle_ns=dict(value=2_000_000, unavailable=None), minimum_cycle_ns=dict(value=0, unavailable=None))
            assert sync["coe_cycle"]["rx"] == dict(object_index=0x1c32, cycle_ns=dict(value=1_000_000, unavailable=None), minimum_cycle_ns=dict(value=250_000, unavailable=None))
        else:
            assert sync["tx_sync_type"] is sync["rx_sync_type"] is None
            assert sync.get("coe_cycle") is None
        assert esc["sync_manager_writes"] == (20 if model != "sii" else 18) and esc["fmmu_writes"] == 18
        assert esc["logical_reads"] == report["cycles"]
        assert esc["coe_downloads"] == esc["logical_writes"] == esc["physical_output_writes"] == esc["op_requests"] == 0
        assert esc["error_acknowledgements"] == 2
        assert esc["final_al_status"] == 1 and esc["final_al_code"] == 0
        verified = report["pdo_verification"]
        assert verified["source"] == ("Virtual ESC CoE assignment reads" if model != "sii" else "Virtual ESC SII PDO descriptors")
        assert verified["readback"]["tx"]["mapping_source"] == ("sii" if model == "sii" else "coe")
        assert all(f["state"] == "matched" for direction in ("tx", "rx") for f in verified[direction]["fields"])
        parts, entries = rows(base)
        cap = report["capture"]
        assert len(parts) == cap["parts"] and len(entries) == cap["selected"] == cap["written"]
        assert cap["overruns"] == 0 and entries
        elapsed = [int(r["elapsed_us"]) for r in entries]
        assert all(a <= b for a, b in zip(elapsed, elapsed[1:]))
        previous_counter = -1
        for index, row in enumerate(entries, 1):
            counter = int(row["Counter"])
            assert int(row["sample_index"]) == index
            if report["timeouts"] == 0:
                assert counter == (index - 1 if on_change else (index - 1) // 4)
            elif on_change:
                assert previous_counter < counter <= (report["cycles"] - 1) // 4
            else:
                assert (index - 1) // 4 <= counter <= (index - 1 + report["timeouts"]) // 4
            assert previous_counter <= counter
            previous_counter = counter
            assert row["Sensor active"] == str(bool(counter & 1)).lower()
            assert float(row["Scaled counter"]) == counter / 4
        if not on_change:
            assert len(entries) == report["valid"]
        reports[prefix + ("-change" if on_change else "-every")] = report

    faults = {}
    for fault, text, states, failed_al in [
        ("pdo-order", "layout differs", [1, 2, 1], [2, 0]),
        ("safeop-reject", "SAFEOP confirmation failed", [1, 2, 4, 1], [0x14, 0x1d]),
        ("mailbox-abort", "aborted", [1, 2, 1], [2, 0]),
        ("setup-timeout", "timeout: PDU", [1, 1], [1, 0]),
    ]:
        if model == "sii" and fault == "mailbox-abort":
            continue
        base = destination / f"virtual-{fault}.csv"
        report = cli_call(cli, "run", profile, "--backend", "virtual", *model_flags, "--virtual-fault", fault,
                          "--seconds", 1, "--csv", base, success=False)
        (destination / f"virtual-{fault}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        assert report["cycles"] == 0 and report["capture"] is None and text in report["error"], report
        assert report["setup_failure_al"] == failed_al and report["stopped_al"] == [1, 0]
        assert report["virtual_esc"]["state_requests"] == states
        assert not list(destination.glob(f"{base.stem}*.csv"))
        faults[fault] = report

    if model != "sii":
        unknown = cli_call(cli, "run", profile, "--backend", "virtual", *model_flags,
                           "--virtual-fault", "readback-unavailable", "--seconds", 1)
        assert unknown["error"] is None and unknown["valid"] > 0
        assert all(f["state"] == "unavailable" for direction in ("tx", "rx")
                   for f in unknown["pdo_verification"][direction]["fields"])
        faults["readback-unavailable"] = unknown

    failed_stop = cli_call(cli, "run", profile, "--backend", "virtual", *model_flags,
                           "--virtual-fault", "cleanup-reject", "--seconds", 1, success=False)
    assert failed_stop["valid"] > 0 and failed_stop["stopped_al"] is None
    assert "0x0014 code 0x0011" in failed_stop["error"]
    assert failed_stop["virtual_esc"]["final_al_status"] == 0x14
    faults["cleanup-reject"] = failed_stop

    lost_base = destination / "lost-io.csv"
    lost = cli_call(cli, "run", profile, "--backend", "virtual", *model_flags,
                    "--virtual-fault", "io-timeout", "--seconds", 1, "--csv", lost_base)
    assert lost["error"] is None and lost["valid"] > 0 and lost["timeouts"] > 0
    assert lost["cycles"] == lost["valid"] + lost["timeouts"]
    assert lost["virtual_esc"]["dropped_replies"] > 0
    assert lost["timeouts"] >= lost["virtual_esc"]["dropped_replies"]
    assert lost["stopped_al"] == [1, 0]
    _, lost_rows = rows(lost_base)
    assert len(lost_rows) == lost["valid"] == lost["capture"]["written"]
    assert lost["capture"]["overruns"] == 0
    for index, row in enumerate(lost_rows, 1):
        counter = int(row["Counter"])
        assert int(row["sample_index"]) == index
        assert (index - 1) // 4 <= counter <= (index - 1 + lost["timeouts"]) // 4
        assert row["Sensor active"] == str(bool(counter & 1)).lower()
        assert float(row["Scaled counter"]) == counter / 4
    faults["io-timeout"] = lost

    changed = json.loads(profile.read_text(encoding="utf-8"))
    changed["expected_identity"]["revision"] = 9
    mismatch = destination / "wrong-identity.json"
    mismatch.write_text(json.dumps(changed), encoding="utf-8")
    report = cli_call(cli, "run", mismatch, "--backend", "virtual", *model_flags, "--seconds", 1, success=False)
    assert "identity" in report["error"] and report["virtual_esc"]["state_requests"] == [1, 2, 1]
    assert report["stopped_al"] == [1, 0] and report["cycles"] == 0
    faults["identity-mismatch"] = report

    collision = destination / "virtual-collision.0001.csv"
    collision.write_bytes(b"keep this capture\n")
    report = cli_call(cli, "run", profile, "--backend", "virtual", *model_flags, "--seconds", 1,
                      "--csv", destination / "virtual-collision.csv", success=False)
    assert report["error"] and report["cycles"] == 0 and report["stopped_al"] == [1, 0]
    assert collision.read_bytes() == b"keep this capture\n"
    assert report["virtual_esc"]["state_requests"] == [1, 2, 4, 1]
    faults["capture-collision"] = report
    if model == "coe-dc":
        for fault, text in [("dc-active", "unexpected active DC synchronization"),
                            ("dc-readback-unavailable", "cannot confirm disabled DC synchronization")]:
            base = destination / (fault + ".csv")
            report = cli_call(cli, "run", profile, "--backend", "virtual", *model_flags,
                              "--virtual-fault", fault, "--seconds", 1, "--csv", base, success=False)
            assert text in report["error"] and report["cycles"] == 0 and report["capture"] is None, report
            assert report["stopped_al"] == [1, 0] and report["setup_failure_al"] == [4, 0]
            activation = report["synchronization"]["dc"]["activation"]
            assert activation["value"] == (3 if fault == "dc-active" else None)
            assert bool(activation["unavailable"]) == (fault == "dc-readback-unavailable")
            assert not list(destination.glob(f"{base.stem}*.csv"))
            faults[fault] = report
    for report in faults.values():
        audit = report["virtual_esc"]
        assert audit["coe_downloads"] == audit["logical_writes"] == audit["physical_output_writes"] == audit["op_requests"] == 0
        assert audit["error_acknowledgements"] == 2
        assert audit["dc_enable_requests"] == audit["dc_clock_distribution"] == 0
    (destination / "virtual-faults.json").write_text(json.dumps(faults, indent=2), encoding="utf-8")


def verify_coe_uploads(cli, destination, reports):
    def audit(report, cyclic):
        esc = report["virtual_esc"]
        assert report["stopped_al"] == [1, 0], report
        assert esc["state_requests"] == ([1, 2, 4, 1] if cyclic else [1, 2, 1])
        assert all(esc[key] == 0 for key in ["coe_downloads", "logical_writes",
            "physical_output_writes", "op_requests", "mailbox_counter_errors",
            "coe_duplicate_requests", "dc_enable_requests", "dc_clock_distribution"]), esc

    def matched(report):
        assert report["virtual_esc"].get("initial_mapping_upload") is None
        assert all(f["state"] == "matched" for d in ("tx", "rx")
                   for f in report["pdo_verification"][d]["fields"]), report
        sync = report["synchronization"]
        assert sync["tx_sync_type"]["value"] == sync["rx_sync_type"]["value"] == 0

    for model in ("normal", "segmented"):
        profile = ROOT / f"samples/virtual-{model}.json"
        for change in (False, True):
            label = f"coe-{model}-{'change' if change else 'every'}"
            base = destination / (label + ".csv")
            report = cli_call(cli, "run", profile, "--backend", "virtual",
                "--virtual-model", f"coe-{model}", "--seconds", 1, "--csv", base,
                *(["--on-change"] if change else []))
            verify_csv(report, base, change=change, virtual=True)
            audit(report, True)
            matched(report)
            assert report["devices"][0]["coe_name"] == {
                "value": "Workbench CoE transfer fixture", "unavailable": None}
            esc = report["virtual_esc"]
            assert esc[f"coe_{model}_uploads"] >= 14
            assert esc["coe_segments"] >= 18 if model == "segmented" else esc["coe_segments"] == 0
            reports[label] = report

    profile = ROOT / "samples/virtual-segmented.json"
    faults = {}
    for fault, text in [("segment-toggle", "toggle"), ("segment-size", "object bound"),
                        ("segment-timeout", "500 ms"), ("mailbox-counter", "counter"),
                        ("segment-abort", None), ("segment-initial-data", None)]:
        base = destination / (fault + ".csv")
        start = time.monotonic()
        report = cli_call(cli, "run", profile, "--backend", "virtual", "--virtual-model", "coe-segmented",
            "--virtual-fault", fault, "--seconds", 1, "--csv", base, success=text is None)
        assert time.monotonic() - start < 5, "bounded CoE failure or run took too long"
        audit(report, text is None)
        if text:
            assert "CoE readback integrity failed" in report["error"] and text in report["error"], report
            assert report["cycles"] == report["valid"] == 0 and report["capture"] is None
            assert report["setup_failure_al"] == [2, 0] and not list(destination.glob(f"{fault}*.csv"))
        else:
            verify_csv(report, base, virtual=True)
            matched(report)
            name = report["devices"][0]["coe_name"]
            if fault == "segment-abort":
                assert name["value"] is None and "0x08000020" in name["unavailable"]
            else:
                assert name["value"] == "Workbench CoE transfer fixture"
        faults[fault] = report
    (destination / "coe-faults.json").write_text(json.dumps(faults, indent=2), encoding="utf-8")


def verify_input_loss(cli, profile, destination, model="coe"):
    flags = ["--backend", "virtual", "--virtual-model", model]
    reports = {}
    for fault, limit, change, ok in [
        ("io-burst", 1000, False, True),
        ("io-burst", 1000, True, True),
        ("io-lost", 100, False, False),
        ("io-lost", 0, False, True),
        ("transport-error", 1000, False, False),
        ("transport-lost", 1000, False, False),
    ]:
        name = f"health-{fault}-{limit}-{'change' if change else 'every'}"
        base = destination / (name + ".csv")
        report = cli_call(cli, "run", profile, *flags, "--virtual-fault", fault,
                          "--input-loss-timeout-ms", limit, "--seconds", 1, "--generation", 17,
                          "--csv", base, *(["--on-change"] if change else []), success=ok)
        (destination / (name + ".json")).write_text(json.dumps(report, indent=2), encoding="utf-8")
        audit_capture(cli, destination / (name + ".json"), base, report)
        health = report["input_health"]
        audit = report["virtual_esc"]
        assert report["input_loss_timeout_ms"] == limit
        assert report["cycles"] == report["valid"] + report["timeouts"] + report["transport_errors"]
        assert report["connection_generation"] == 17 and health["invalid_periods"] >= 1
        assert health["last_valid_cycle"] is not None and health["last_valid_elapsed_us"] is not None
        assert health["last_valid_age_us"] is not None
        assert audit["state_requests"] == ([1, 2, 4] if fault == "transport-lost" else [1, 2, 4, 1])
        assert all(audit[key] == 0 for key in ["coe_downloads", "logical_writes", "physical_output_writes",
                                               "op_requests", "dc_enable_requests", "dc_clock_distribution"])
        _, entries = rows(base)
        assert len(entries) == report["capture"]["written"] == report["capture"]["selected"] > 0
        assert report["capture"]["overruns"] == 0
        if not change:
            assert len(entries) == report["valid"]
        else:
            assert len(entries) < report["valid"]
            assert all(a["Counter"] != b["Counter"] for a, b in zip(entries, entries[1:]))
        cycle_indexes = [int(row["cycle_index"]) for row in entries]
        times = [int(row["elapsed_us"]) for row in entries]
        assert all(a < b for a, b in zip(cycle_indexes, cycle_indexes[1:]))
        assert all(a <= b for a, b in zip(times, times[1:]))
        for index, row in enumerate(entries, 1):
            counter = int(row["Counter"])
            assert int(row["sample_index"]) == index and int(row["connection_generation"]) == 17
            assert row["Sensor active"] == str(bool(counter & 1)).lower()
            assert float(row["Scaled counter"]) == counter / 4
        if fault == "io-burst":
            assert audit["dropped_replies"] == 40 and report["timeouts"] >= 40
            assert report["valid"] > 100 and health["recoveries"] >= 1
            assert health["longest_invalid_streak"] >= 40
            assert health["longest_invalid_us"] >= 70_000
            assert any(int(row["Counter"]) >= 12 for row in entries)
            assert any(b-a >= 40 for a,b in zip(cycle_indexes,cycle_indexes[1:]))
        elif fault == "io-lost":
            assert 0 < report["valid"] <= 8 and health["current_issue"] == "timeout"
            assert health["consecutive_invalid"] > 0 and health["longest_invalid_us"] >= 100_000
            assert health["last_valid_age_us"] >= 100_000
            if limit:
                assert "input loss timeout" in report["error"]
        else:
            assert "cyclic Ethernet transport failed" in report["error"]
            assert "virtual Ethernet transport failed during cyclic input" in report["error"]
            assert report["transport_errors"] == 1 and audit["transport_errors"] >= 1
            assert health["current_issue"] == "transport_error" and report["actual_wkc"] is None
        if fault == "transport-lost":
            assert report["stopped_al"] is None
            assert "also failed" in report["error"] and "transport remains unavailable" in report["error"]
        else:
            assert report["stopped_al"] == [1, 0]
            assert report["devices"][0]["al_status"] == 1
        reports[name] = report
    (destination / "input-health.json").write_text(json.dumps(reports, indent=2), encoding="utf-8")


def verify_runtime_check(cli, destination):
    """Collect host prerequisites without calling the capture API or probing a NIC."""
    path = destination / "host-prerequisites.json"
    report = cli_call(cli, "check-runtime", "--out", path)
    assert json.loads(path.read_bytes()) == report and not path.read_bytes().startswith(b"\xef\xbb\xbf")
    assert report["schema"] == 1 and report["scope"] == "host_prerequisites_only"
    assert report["application_architecture"] == "x86_64" and report["pointer_bits"] == 64
    assert report["capture_access"] == "not_probed" and report["service_name"] == "npcap"
    assert datetime.datetime.fromisoformat(report["captured_at_utc"]).utcoffset() == datetime.timedelta()
    assert report["npcap_modules_before"] == report["npcap_modules_after"] == {"wpcap": False, "packet": False}
    assert len(report["dlls"]) == 2 and [d["name"] for d in report["dlls"]] == ["wpcap.dll", "Packet.dll"]
    observations = [report["system_directory"], report["service"], report["admin_only"]]
    for dll in report["dlls"]:
        observations += [dll["image"], dll["file_version"]]
        if report["system_directory"]["value"]:
            assert Path(dll["path"]) == Path(report["system_directory"]["value"]) / "Npcap" / dll["name"]
        if dll["image"]["state"] == "available":
            # Independent raw-byte check of the reported installed header, without loading it.
            with Path(dll["path"]).open("rb") as stream:
                assert Path(dll["path"]).stat().st_size == dll["image"]["value"]["bytes"]
                dos = stream.read(64); assert dos[:2] == b"MZ"
                stream.seek(struct.unpack_from("<I", dos, 60)[0]); pe = stream.read(26)
                assert pe[:4] == b"PE\0\0"
                assert struct.unpack_from("<H", pe, 4)[0] == dll["image"]["value"]["machine"]
                assert (struct.unpack_from("<H", pe, 24)[0] == 0x20b) == dll["image"]["value"]["pe32_plus"]
                assert bool(struct.unpack_from("<H", pe, 22)[0] & 0x2000) == dll["image"]["value"]["dll"]
        if dll["file_version"]["state"] == "available":
            parts = dll["file_version"]["value"].split(".")
            assert len(parts) == 4 and all(p.isdecimal() and 0 <= int(p) <= 65535 for p in parts)
    for observation in observations:
        assert observation["state"] in ["available", "missing", "unavailable", "invalid", "not_queried"]
        if observation["state"] == "available":
            assert observation["value"] is not None and observation["detail"] is None and observation["os_error"] is None
        else:
            assert observation["value"] is None and observation["detail"]
    if report["admin_only"]["value"] is not None:
        assert type(report["admin_only"]["value"]) is bool
    original = path.read_bytes()
    cli_call(cli, "check-runtime", "--out", path, success=False)
    assert path.read_bytes() == original
    invalid = destination / "wrong-extension.txt"
    cli_call(cli, "check-runtime", "--out", invalid, success=False)
    assert not invalid.exists()


def verify_esi_identity(cli, destination):
    """Independent multi-product/revision XML checks for exact import selection."""
    from copy import deepcopy
    import xml.etree.ElementTree as ET

    base = (ROOT / "samples/mode-pdo-staging.esi.xml").read_bytes()
    tree = ET.fromstring(base)
    container = tree.find("Descriptions/Devices")
    first = container[0]
    second = deepcopy(first)
    second.find("Type").set("RevisionNo", "#x00000002")
    second.find("TxPdo/Entry/Name").text = "Revision two input"
    third = deepcopy(first)
    third.find("Type").set("ProductCode", "#x00000004")
    container.extend([second, third])
    source = destination / "multiple-revisions.esi.xml"
    source.write_bytes(ET.tostring(tree, encoding="utf-8", xml_declaration=True))
    original = source.read_bytes()
    entries = cli_call(cli, "esi-list", source)
    target = entries[1]["source"]["identity"]
    assert [(e["source"]["identity"]["product"], e["source"]["identity"]["revision"]) for e in entries] == [(3, 1), (3, 2), (4, 1)]
    selector = "0x00ff1000/0x00000003/0x00000002"
    extras = ["--dc-mode", 1, "--sync-unit-cycle-ns", 1000000, "--tx-pdo", "0x1a01@3"]
    profiles = []
    for label, args in [
        ("legacy", ["--device", 1]),
        ("exact", ["--identity", selector]),
        ("guarded", ["--device", 1, "--identity", selector]),
        ("decimal", ["--identity", f'{target["vendor"]}/3/2']),
        ("esi-hex", ["--identity", "#x00FF1000/#x3/#x2"]),
    ]:
        path = destination / f"{label}.json"
        cli_call(cli, "esi-import", source, *args, *extras, "--out", path)
        profile = cli_call(cli, "validate", path)
        assert profile["expected_identity"] == profile["esi"]["identity"] == target
        assert profile["esi"]["sha256"] == hashlib.sha256(original).hexdigest()
        assert profile["staged_esi_dc_mode"] == 1 and profile["sync_unit_cycle_ns"] == 1000000
        assert profile["esi_pdo_selection"]["tx"] == [{"index": 0x1a01, "sm": 3}]
        profiles.append(profile)
    assert all(p == profiles[0] for p in profiles)

    failures = [
        ("missing-selector", [], "required arguments"),
        ("bad-format", ["--identity", "1/2"], "VENDOR/PRODUCT/REVISION"),
        ("overflow", ["--identity", "4294967296/3/2"], "invalid value"),
        ("zero-literal", ["--identity", "0x00ff1000/3/0"], "was not found"),
        ("unknown-vendor", ["--identity", "1/3/2"], "was not found"),
        ("unknown-product", ["--identity", "0x00ff1000/5/2"], "was not found"),
        ("guard-mismatch", ["--device", 0, "--identity", selector], "expected"),
        ("bad-index", ["--device", 3, "--identity", selector], "index out of range"),
    ]
    for label, args, message in failures:
        path = destination / f"rejected-{label}.json"
        error = cli_call(cli, "esi-import", source, *args, "--out", path, success=False)
        assert message in error, (label, error)
        assert not path.exists() and source.read_bytes() == original

    # Reordering changes source provenance but not exact-selection configuration.
    container[:] = [third, first, second]
    reordered = destination / "reordered.esi.xml"
    reordered.write_bytes(ET.tostring(tree, encoding="utf-8", xml_declaration=True))
    out = destination / "reordered.json"
    cli_call(cli, "esi-import", reordered, "--identity", selector, *extras, "--out", out)
    selected = cli_call(cli, "validate", out)
    expected = deepcopy(profiles[0])
    expected["esi"]["file_name"] = reordered.name
    expected["esi"]["sha256"] = hashlib.sha256(reordered.read_bytes()).hexdigest()
    assert selected == expected
    stale = destination / "stale-index.json"
    assert "expected" in cli_call(cli, "esi-import", reordered, "--device", 1, "--identity", selector, "--out", stale, success=False)
    assert not stale.exists()

    # Duplicate exact identities can have distinct entries. Never silently choose the first.
    duplicate = deepcopy(second)
    duplicate.find("Name").text = "Explicit duplicate entry"
    container.append(duplicate)
    duplicates = destination / "duplicates.esi.xml"
    duplicates.write_bytes(ET.tostring(tree, encoding="utf-8", xml_declaration=True))
    ambiguous = destination / "ambiguous.json"
    assert "matches multiple entries" in cli_call(cli, "esi-import", duplicates, "--identity", selector, "--out", ambiguous, success=False)
    assert not ambiguous.exists()
    chosen = destination / "explicit-duplicate.json"
    cli_call(cli, "esi-import", duplicates, "--device", 3, "--identity", selector, "--out", chosen)
    assert cli_call(cli, "validate", chosen)["name"] == "Explicit duplicate entry"
    collision = (destination / "exact.json").read_bytes()
    cli_call(cli, "esi-import", source, "--identity", selector, "--out", destination / "exact.json", success=False)
    assert (destination / "exact.json").read_bytes() == collision and source.read_bytes() == original
    (destination / "identity-selection-check.json").write_text(json.dumps({"identity": target,
        "equivalent_imports": len(profiles), "rejected_selectors": len(failures),
        "reordered_selection": selected, "explicit_duplicate": str(chosen)}, indent=2), encoding="utf-8")


def verify_mode_pdo_staging(cli, destination):
    """Exercise offline candidate saving and independent actual-mapping rejection."""
    esi = ROOT / "samples/mode-pdo-staging.esi.xml"
    results = {}
    for mode in range(4):
        source = destination / f"mode-{mode}.json"
        cli_call(cli, "esi-import", esi, "--device", 0, "--dc-mode", mode, "--out", source)
        profile = json.loads(source.read_bytes())
        profile["staged_rx_hex"] = "FEFF"
        profile["tx"][0].update(name="Custom input", log=False, big_endian=True, source="override")
        profile["rx"][0].update(name="Custom output", source="override")
        source.write_text(json.dumps(profile), encoding="utf-8")
        before = source.read_bytes()
        target = destination / f"candidate-{mode}.json"
        if mode == 3:
            error = cli_call(cli, "stage-mode-pdos", source, "--out", target, success=False)
            assert "unsupported annotations" in error and not target.exists()
            assert source.read_bytes() == before
            continue
        review = cli_call(cli, "stage-mode-pdos", source)
        assert source.read_bytes() == before and not target.exists()
        assert review["scope"] == "offline_profile_only" and review["mode_index"] == mode
        assert review["tx_layout_changed"] == (mode == 1)
        assert review["rx_layout_changed"] == review["staged_rx_will_clear"] == (mode == 2)
        args = []
        if mode == 2:
            error = cli_call(cli, "stage-mode-pdos", source, "--out", target, success=False)
            assert "--clear-staged-rx" in error and not target.exists()
            assert source.read_bytes() == before
            args = ["--clear-staged-rx"]
        assert cli_call(cli, "stage-mode-pdos", source, "--out", target, *args) == review
        saved = cli_call(cli, "validate", target)
        assert saved["tx"] == review["after"]["tx_fields"]
        assert saved["rx"] == review["after"]["rx_fields"]
        assert saved["esi_pdo_selection"] == review["after"]["selection"]
        assert saved["staged_rx_hex"] == ("" if mode == 2 else "FEFF")
        expected = dict(profile)
        for key in ("tx", "rx", "tx_bytes", "rx_bytes", "esi_pdo_selection", "staged_rx_hex"):
            expected[key] = saved[key]
        assert saved == expected  # All other settings remain exact.
        if mode != 1:
            assert saved["tx"] == profile["tx"]
        if mode != 2:
            assert saved["rx"] == profile["rx"]
            decoded = cli_call(cli, "decode", target, "FEFF", "--rx")
            assert decoded  # Same typed Rx decoder still accepts the saved bytes.
        offline = cli_call(cli, "review-sync", target)
        assert all(sm["pdo_state"] == "matched" for sm in offline["sync_managers"])
        assert cli_call(cli, "review-pdos", target)["selection"] == saved["esi_pdo_selection"]
        existing = target.read_bytes()
        cli_call(cli, "stage-mode-pdos", source, "--out", target, *args, success=False)
        assert target.read_bytes() == existing and source.read_bytes() == before
        results[str(mode)] = review
        if mode == 1:
            # Equal image lengths and matched offline hints cannot prove the actual device map.
            base = destination / "actual-map-mismatch.csv"
            rejected = cli_call(cli, "run", target, "--backend", "virtual", "--virtual-model",
                                "coe-dc", "--seconds", 1, "--csv", base, success=False)
            assert "device PDO layout differs from profile" in rejected["error"]
            assert rejected["cycles"] == rejected["valid"] == 0
            verification = rejected["pdo_verification"]
            assert verification["tx"]["image_bytes"] == saved["tx_bytes"] == 8
            assert verification["tx"]["fields"][0]["state"] == "mismatch"
            assert not verification["rx"]["errors"]
            assert rejected["stopped_al"] == [1, 0] and rejected["capture"] is None
            assert rejected["virtual_esc"]["state_requests"] == [1, 2, 1]
            assert not list(destination.glob("actual-map-mismatch*.csv"))
            esc = rejected["virtual_esc"]
            assert all(esc[k] == 0 for k in ["coe_downloads", "logical_writes",
                "physical_output_writes", "op_requests", "dc_enable_requests", "dc_clock_distribution"])
            results["actual_mapping_rejection"] = rejected
    detached = json.loads(before)
    detached["esi_pdo_selection"] = None
    path = destination / "detached.json"
    path.write_text(json.dumps(detached), encoding="utf-8")
    assert "attached ESI PDO selection" in cli_call(cli, "stage-mode-pdos", path, success=False)
    (destination / "mode-pdo-staging-review.json").write_text(json.dumps(results, indent=2), encoding="utf-8")


def verify_sync_modes(cli, destination):
    esi = ROOT / "samples/sync-modes.esi.xml"
    modes = cli_call(cli, "esi-list", esi)[0]["source"]["dc_modes"]
    assert len(modes) == 4 and modes[1]["assign_activate"] == 0x300
    assert modes[1]["shift_sync0"]["value_ns"] == -1250
    assert modes[3]["xml_path"] == "Device/OpMode/Dc"
    utf16 = destination / "sync-utf16.xml"
    utf16.write_text(esi.read_text(encoding="utf-8").replace("UTF-8", "UTF-16"), encoding="utf-16")
    assert cli_call(cli, "esi-list", utf16)[0]["source"]["dc_modes"] == modes
    imported = destination / "sync-review.json"
    cli_call(cli, "esi-import", esi, "--device", 0, "--dc-mode", 2,
             "--sync-unit-cycle-ns", 1_000_000, "--out", imported)
    profile = cli_call(cli, "validate", imported)
    assert profile["esi"]["sha256"] == hashlib.sha256(esi.read_bytes()).hexdigest()
    preview = cli_call(cli, "review-sync", imported)
    assert preview["cycle_sync0"]["value_ns"] == 500_000
    assert preview["cycle_sync1"]["value_ns"] == 2_000_000
    assert preview["shift_sync0"]["value_ns"] == -25000 and preview["shift_sync1"]["value_ns"] is None
    assert preview["applied"] is False and preview["mode_source"] == "esi"
    assert preview["sync_unit_source"] == "manual"
    assert all(c["state"] == "unavailable" for c in preview["checks"])
    profile["requested_cycle_us"] = 2000
    changed_host = destination / "changed-host-cycle.json"
    changed_host.write_text(json.dumps(profile), encoding="utf-8")
    assert cli_call(cli, "review-sync", changed_host)["cycle_sync0"] == preview["cycle_sync0"]
    profile["requested_cycle_us"] = 1000
    profile["rotate_rows"] = 500
    imported.write_text(json.dumps(profile), encoding="utf-8")
    base = destination / "staged-dc.csv"
    report = cli_call(cli, "run", imported, "--backend", "virtual", "--virtual-model", "coe-dc",
                      "--seconds", 1, "--csv", base)
    report_path = destination / "staged-dc.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    assert report["valid"] > 100 and report["error"] is None and report["stopped_al"] == [1, 0]
    assert report["sync_review"]["applied"] is False
    assert [c["state"] for c in report["sync_review"]["checks"]] == ["different"] * 3
    assert report["synchronization"]["dc"]["assign_activate"]["value"] == 0
    assert all(report["virtual_esc"][k] == 0 for k in ["dc_enable_requests", "dc_clock_distribution",
               "coe_downloads", "logical_writes", "physical_output_writes", "op_requests"])
    _, entries = rows(base)
    assert len(entries) == report["valid"] == report["capture"]["written"] and report["capture"]["overruns"] == 0
    counter_name, bool_name, float_name = [f["name"] for f in profile["tx"]]
    for index, row in enumerate(entries, 1):
        value = int(row[counter_name])
        assert int(row["sample_index"]) == index
        assert (index-1)//4 <= value <= (index-1+report["timeouts"])//4
        assert row[bool_name] == str(bool(value & 1)).lower() and float(row[float_name]) == value/4
    compared = cli_call(cli, "review-sync", imported, "--readback", report_path)
    assert compared["readback_source"].startswith("Saved run report") and compared["applied"] is False
    assert [c["state"] for c in compared["checks"]] == ["different"] * 3
    profile["staged_esi_dc_mode"] = 0
    free = destination / "free-run-review.json"
    free.write_text(json.dumps(profile), encoding="utf-8")
    matched = cli_call(cli, "review-sync", free, "--readback", report_path)
    assert [c["state"] for c in matched["checks"]] == ["matched"] * 3 and matched["applied"] is False
    older = json.loads(json.dumps(report))
    older["synchronization"]["dc"].pop("assign_activate")
    old_report = destination / "old-sync-report.json"
    old_report.write_text(json.dumps(older), encoding="utf-8")
    assert cli_call(cli, "review-sync", free, "--readback", old_report)["checks"][0]["state"] == "unavailable"
    older["devices"][0]["identity"]["revision"] = 9
    old_report.write_text(json.dumps(older), encoding="utf-8")
    assert "matching the profile" in cli_call(cli, "review-sync", free, "--readback", old_report, success=False)
    profile["staged_esi_dc_mode"] = 1
    profile["sync_unit_cycle_ns"] = None
    unresolved = destination / "unresolved-mode.json"
    unresolved.write_text(json.dumps(profile), encoding="utf-8")
    assert cli_call(cli, "review-sync", unresolved)["cycle_sync0"]["value_ns"] is None
    for index, key, value in [(1, "staged_esi_dc_mode", 99), (2, "sync_unit_cycle_ns", 0),
                              (3, "expected_identity", {"vendor": 1, "product": 3, "revision": 1})]:
        bad = json.loads(json.dumps(profile)); bad[key] = value
        bad_path = destination / f"bad-staged-{index}.json"
        bad_path.write_text(json.dumps(bad), encoding="utf-8")
        assert cli_call(cli, "validate", bad_path, success=False)
    impossible = destination / "must-not-exist.json"
    cli_call(cli, "esi-import", esi, "--device", 0, "--dc-mode", 99, "--out", impossible, success=False)
    assert not impossible.exists()
    verify_mode_sync_managers(cli, destination, report_path)
    (destination / "sync-checks.json").write_text(json.dumps({"preview": preview, "compared": compared, "matched": matched}, indent=2), encoding="utf-8")


def verify_mode_sync_managers(cli, destination, report_path):
    esi = ROOT / "samples/mode-sync-managers.esi.xml"
    modes = cli_call(cli, "esi-list", esi)[0]["source"]["dc_modes"]
    assert len(modes) == 3 and [s["index"] for s in modes[0]["sync_managers"]] == [2, 3]
    assert [s["pdo_indexes"] for s in modes[0]["sync_managers"]] == [[0x1600], [0x1a00]]
    assert modes[1]["sync_managers"][0]["sync_type"] == 2
    assert any("OSFac" in n for n in modes[2]["sync_managers"][0]["notes"])
    utf16 = destination / "mode-sm-utf16.xml"; utf16.write_bytes(esi.read_text(encoding="utf-8").replace('encoding="UTF-8"', 'encoding="UTF-16"').encode("utf-16"))
    assert cli_call(cli, "esi-list", utf16)[0]["source"]["dc_modes"] == modes
    imported = destination / "mode-sm-profile.json"
    cli_call(cli, "esi-import", esi, "--device", 0, "--dc-mode", 0, "--out", imported)
    original = imported.read_bytes(); profile = json.loads(original)
    baseline_selection = profile["esi_pdo_selection"]; baseline_fields = profile["tx"]
    offline = cli_call(cli, "review-sync", imported)
    assert offline["applied"] is False and [s["pdo_state"] for s in offline["sync_managers"]] == ["matched"] * 2
    assert [s["sync_type"]["state"] for s in offline["sync_managers"]] == ["unavailable"] * 2
    matched = cli_call(cli, "review-sync", imported, "--readback", report_path)
    assert matched["readback_source"].startswith("Saved run report") and matched["applied"] is False
    assert [s["sync_type"]["state"] for s in matched["sync_managers"]] == ["matched"] * 2
    assert [s["sync_type"]["actual"] for s in matched["sync_managers"]] == [0, 0]
    results = {"offline": offline, "matched": matched}
    native_path = destination / "mode-sm-virtual-run.json"
    modeled = cli_call(cli, "run", imported, "--backend", "virtual", "--virtual-model", "coe-dc", "--seconds", 1, "--report", native_path)
    assert modeled["valid"] > 100 and modeled["error"] is None and modeled["stopped_al"] == [1, 0]
    assert modeled["sync_review"]["applied"] is False
    assert all(s["pdo_state"] == s["sync_type"]["state"] == "matched" for s in modeled["sync_review"]["sync_managers"])
    audit = modeled["virtual_esc"]
    assert all(audit[k] == 0 for k in ["coe_downloads", "logical_writes", "physical_output_writes", "op_requests", "dc_enable_requests", "dc_clock_distribution"])
    assert modeled["context"]["profile"]["esi_pdo_selection"] == baseline_selection
    assert imported.read_bytes() == original

    def review_variant(label, changed):
        path = destination / f"mode-sm-{label}.json"; path.write_text(json.dumps(changed), encoding="utf-8")
        before = path.read_bytes(); result = cli_call(cli, "review-sync", path, "--readback", report_path)
        assert path.read_bytes() == before and result["applied"] is False
        assert changed["tx"] == baseline_fields
        results[label] = result
        return result

    changed = json.loads(original); changed["esi_pdo_selection"] = None
    assert all(s["pdo_state"] == "unavailable" and s["configured_pdos"] is None for s in review_variant("detached", changed)["sync_managers"])
    changed = json.loads(original); changed["esi"]["dc_modes"][0]["sync_managers"][1]["pdo_indexes"] = [0x1a01, 0x1a00]
    different = review_variant("different", changed)["sync_managers"][1]
    assert different["pdo_state"] == "different" and different["configured_pdos"] == [0x1a00]
    assert changed["esi_pdo_selection"] == baseline_selection
    changed = json.loads(original); changed["staged_esi_dc_mode"] = 1
    sync0 = review_variant("sync0", changed)["sync_managers"][0]
    assert sync0["sync_type"]["state"] == "different" and sync0["pdo_state"] == "not_declared"
    changed["staged_esi_dc_mode"] = 2
    unresolved = review_variant("unresolved", changed)["sync_managers"][0]
    assert unresolved["sync_type"]["state"] == unresolved["pdo_state"] == "unresolved"
    changed["esi"]["dc_modes"][2]["sync_managers"][0]["notes"] = []
    missing = review_variant("sm4-unavailable", changed)["sync_managers"][0]
    assert missing["sync_type"]["state"] == "unavailable" and missing["sync_type"]["actual"] is None
    assert imported.read_bytes() == original
    text = esi.read_text(encoding="utf-8")
    invalid = {"sm-range": text.replace('<Sm No="2">', '<Sm No="16">', 1),
               "sm-duplicate": text.replace('<Sm No="2">', '<Sm No="3">', 1),
               "sync-range": text.replace('<SyncType>0</SyncType>', '<SyncType>65536</SyncType>', 1),
               "sync-duplicate": text.replace('<SyncType>0</SyncType>', '<SyncType>0</SyncType><SyncType>1</SyncType>', 1),
               "pdo-duplicate": text.replace('<Pdo>#x1600</Pdo>', '<Pdo>#x1600</Pdo><Pdo>#x1600</Pdo>', 1)}
    for label, xml in invalid.items():
        path = destination / f"bad-mode-sm-{label}.xml"; path.write_text(xml, encoding="utf-8")
        output = path.with_suffix(".json")
        cli_call(cli, "esi-import", path, "--device", 0, "--out", output, success=False)
        assert not output.exists()
    (destination / "mode-sm-checks.json").write_text(json.dumps(results, indent=2), encoding="utf-8")


def verify_pdo_choices(cli, destination):
    esi = ROOT / "samples/pdo-choices.esi.xml"
    listing = cli_call(cli, "esi-list", esi)[0]
    catalog = listing["source"]["pdo_catalog"]
    assert len(catalog) == 5 and catalog[2]["default_sm"] is None
    assert catalog[0]["mandatory"] and catalog[0]["entries"][0]["fixed"]
    assert catalog[4]["unsupported"] is True
    default = destination / "default.json"
    cli_call(cli, "esi-import", esi, "--device", 0, "--out", default)
    profile = cli_call(cli, "validate", default)
    assert profile["esi"]["sha256"] == hashlib.sha256(esi.read_bytes()).hexdigest()
    assert len(profile["esi_pdo_selection"]["tx"]) == len(profile["esi_pdo_selection"]["rx"]) == 1
    preview = cli_call(cli, "review-pdos", default)
    assert preview["applied"] is False and preview["tx_bytes"] == 8 and preview["rx_bytes"] == 2
    assert preview["tx"]["sync_managers"][0]["pdos"][0]["entries"] == [0x60000110, 0x60000201, 15, 0x60000320]
    checked = cli_call(cli, "verify-pdo", default, ROOT / "samples/synthetic-pdo.json")
    assert checked["tx"]["expected_selection"]["mapping_source"] == "esi"
    for name, mutate in [("sm", lambda x: x["tx"]["sync_managers"][0].update(index=4)),
                          ("padding", lambda x: x["tx"]["sync_managers"][0]["pdos"][0]["entries"].__setitem__(2, 0x600f000f))]:
        data = json.loads((ROOT / "samples/synthetic-pdo.json").read_text(encoding="utf-8")); mutate(data)
        path = destination / (name + "-readback.json"); path.write_text(json.dumps(data), encoding="utf-8")
        result = cli_call(cli, "verify-pdo", default, path, success=False)
        assert result["tx"]["errors"] and all(f["state"] == "matched" for f in result["tx"]["fields"])
    profile["rotate_rows"] = 500
    default.write_text(json.dumps(profile), encoding="utf-8")
    base = destination / "default.csv"
    report = cli_call(cli, "run", default, "--backend", "virtual", "--seconds", 1, "--csv", base)
    (destination / "default-run.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    assert report["valid"] > 100 and report["stopped_al"] == [1,0] and report["error"] is None
    _, entries = rows(base)
    assert len(entries) == report["valid"] == report["capture"]["written"] and report["capture"]["overruns"] == 0
    counter_name, bool_name, float_name = [f["name"] for f in profile["tx"]]
    for i,row in enumerate(entries,1):
        counter=int(row[counter_name]); assert (i-1)//4 <= counter <= (i-1+report["timeouts"])//4
        assert row[bool_name] == str(bool(counter&1)).lower() and float(row[float_name]) == counter/4
    alt = destination / "alternative.json"
    cli_call(cli, "select-pdos", default, "--tx-pdo", "0x1a01@3", "--out", alt)
    selected = cli_call(cli, "validate", alt)
    assert selected["tx_bytes"] == 8 and selected["tx"][0]["source"] == "override"
    assert len(selected["esi_pdo_selection"]["rx"]) == 1
    failed = cli_call(cli, "run", alt, "--backend", "virtual", "--seconds", 1, success=False)
    (destination / "mismatch-run.json").write_text(json.dumps(failed, indent=2), encoding="utf-8")
    assert "layout differs" in failed["error"] and failed["cycles"] == 0 and failed["stopped_al"] == [1,0]
    assert failed["virtual_esc"]["state_requests"] == [1,2,1]
    assert report["virtual_esc"]["coe_downloads"] == failed["virtual_esc"]["coe_downloads"] == 0
    assert report["virtual_esc"]["logical_writes"] == failed["virtual_esc"]["logical_writes"] == 0
    # Different SMs align to bytes; selected order remains stable within an SM.
    ordered = destination / "ordered.json"
    cli_call(cli, "select-pdos", default, "--tx-pdo", "0x1a02@4", "--tx-pdo", "0x1a00@3", "--out", ordered)
    changed = cli_call(cli, "validate", ordered)
    assert changed["tx_bytes"] == 9 and [f["bit"] for f in changed["tx"]] == [0,16,32,64]
    combined = destination / "same-sm.json"
    cli_call(cli, "select-pdos", default, "--tx-pdo", "0x1a02@3", "--tx-pdo", "0x1a00@3", "--out", combined)
    assert [f["bit"] for f in cli_call(cli, "validate", combined)["tx"]] == [0,8,24,40]
    for i, flags in enumerate([
        ["--tx-pdo","0x1a00@3","--tx-pdo","0x1a01@4"],
        ["--rx-pdo","none"], ["--tx-pdo","0x1a00@2"],
        ["--tx-pdo","0x1a00@3","--tx-pdo","0x1a00@3"],
        ["--tx-pdo","0x1a03@3"], ["--tx-pdo","0x1aff@3"],
    ]):
        out = destination / f"invalid-choice-{i}.json"
        cli_call(cli, "select-pdos", default, *flags, "--out", out, success=False)
        assert not out.exists()
    # A mandatory PDO without a default SM can be listed, then explicitly assigned.
    text = esi.read_text(encoding="utf-8").replace('Sm="2" Mandatory="true"', 'Mandatory="true"')
    unassigned = destination / "mandatory-unassigned.xml"
    unassigned.write_text(text, encoding="utf-8")
    assert cli_call(cli, "esi-list", unassigned)[0]["source"]["default_tx_bytes"] is None
    explicit = destination / "explicit.json"
    cli_call(cli, "esi-import", unassigned, "--device", 0, "--rx-pdo", "0x1600@2", "--out", explicit)
    assert cli_call(cli, "validate", explicit)["rx"][0]["source"] == "override"
    # Frozen older profiles still load without catalog fields.
    legacy = json.loads(json.dumps(profile)); legacy.pop("esi_pdo_selection"); legacy["esi"].pop("pdo_catalog")
    legacy_path = destination / "legacy.json"; legacy_path.write_text(json.dumps(legacy), encoding="utf-8")
    assert cli_call(cli, "validate", legacy_path)["esi_pdo_selection"] is None


def verify_valid_spacing_boundaries(cli, destination):
    fixture = json.loads((ROOT / "samples/synthetic-replay.json").read_bytes())
    for name, exchange_index in [("one-valid", 0), ("zero-valid", 2)]:
        sample = dict(fixture)
        sample["exchanges"] = [fixture["exchanges"][exchange_index]]
        path = destination / f"{name}.json"
        path.write_text(json.dumps(sample), encoding="utf-8")
        report = cli_call(cli, "run", ROOT / "samples/synthetic.json", "--backend", "replay",
            "--replay", path, "--seconds", 1, success=name == "one-valid")
        spacing = report["valid_receive_spacing"]
        assert report["valid"] == int(name == "one-valid") and spacing["count"] == 0
        assert all(spacing[k] is None for k in ("p50_us", "p95_us", "p99_us", "longest_gap_us"))
    setup_failure = cli_call(cli, "run", ROOT / "samples/virtual.json", "--backend", "virtual",
        "--virtual-fault", "init-normal-upload", "--seconds", 1, success=False)
    assert setup_failure["cycles"] == 0 and setup_failure["valid_receive_spacing"] is None


def verify_comparison_file_hashes(cli, destination, comparison_path):
    receipt_path = destination / "comparison-source-hashes.json"
    check = cli_call(cli, "check-comparison", comparison_path, "--out", receipt_path)
    assert check == json.loads(receipt_path.read_bytes())
    assert check["all_match"] and check["csv_hashes_recorded"]
    assert check["comparison_sha256"] == hashlib.sha256(comparison_path.read_bytes()).hexdigest()
    assert all(entry["observed_sha256"] == entry["expected_sha256"] ==
               hashlib.sha256(Path(entry["resolved_path"]).read_bytes()).hexdigest()
               for entry in check["files"])
    assert "already exists" in cli_call(cli, "check-comparison", comparison_path,
                                        "--out", receipt_path, success=False)

    data = json.loads(comparison_path.read_bytes())
    base = destination / "comparison-relative-fixture"
    base.mkdir()
    for index, (trial, audit) in enumerate(zip(data["trials"], data["csv_audits"])):
        path = Path(trial["file"])
        trial["file"] = audit["report"] = path.name
        report_bytes = path.read_bytes()
        if index == 0:
            # Same length, different SHA-256. The check reads bytes rather than parsing this report.
            report_bytes = b"!" + report_bytes[1:]
        (base / path.name).write_bytes(report_bytes)
        for part_index, part in enumerate(audit["parts"]):
            source = Path(part["file"])
            part["file"] = source.name
            if part_index == 0:
                if index == 0:
                    (base / source.name).mkdir()  # Unreadable as a file.
            else:
                (base / source.name).write_bytes(source.read_bytes())
    relative = destination / "relative-comparison.json"
    relative.write_text(json.dumps(data), encoding="utf-8")
    unresolved = cli_call(cli, "check-comparison", relative)
    assert not unresolved["all_match"] and all(e["status"] == "unresolved" for e in unresolved["files"])
    changed = cli_call(cli, "check-comparison", relative, "--base", base)
    assert not changed["all_match"]
    assert {e["status"] for e in changed["files"]} == {"match", "changed", "missing", "unreadable"}
    first = changed["files"][0]
    assert first["status"] == "changed" and first["observed_sha256"] != first["expected_sha256"]
    short_part = base / data["csv_audits"][1]["parts"][0]["file"]
    short_part.write_bytes(b"")
    resized = cli_call(cli, "check-comparison", relative, "--base", base)
    entry = next(e for e in resized["files"] if e["trial"] == 2 and e["csv_part"] == 1)
    assert entry["status"] == "changed" and entry["observed_sha256"] is None
    assert entry["observed_bytes"] == 0 < entry["expected_bytes"]

    rejected = destination / "rejected-bundle"
    assert "source check found" in cli_call(cli, "bundle-comparison", relative,
                                           "--base", base, "--out", rejected, success=False)
    assert not rejected.exists()

    inconsistent = destination / "inconsistent-audit-comparison.json"
    data["csv_audits"][0]["report_sha256"] = "0" * 64
    inconsistent.write_text(json.dumps(data), encoding="utf-8")
    assert "CSV audit does not match" in cli_call(cli, "check-comparison", inconsistent,
                                                  "--base", base, success=False)


def verify_comparison_bundle(cli, destination, comparison_path):
    original = comparison_path.read_bytes()
    data = json.loads(original)
    audits = data["csv_audits"]
    root = destination / f"{comparison_path.stem}-bundle"
    receipt = cli_call(cli, "bundle-comparison", comparison_path, "--out", root)
    marker = root / "bundle.json"
    marker_bytes = marker.read_bytes()
    assert receipt == json.loads(marker_bytes) and receipt["schema"] == 1
    assert receipt["csv_hashes_recorded"] == (audits is not None)
    assert receipt["reports"] == len(data["trials"])
    assert receipt["csv_parts"] == sum(len(audit["parts"]) for audit in audits or [])
    assert (root / receipt["original_comparison"]).read_bytes() == original == comparison_path.read_bytes()
    for key in ("original_comparison", "portable_comparison", "trial_set"):
        assert receipt[f"{key}_sha256"] == hashlib.sha256((root / receipt[key]).read_bytes()).hexdigest()
    assert len(list(root.rglob("*.csv"))) == receipt["csv_parts"]
    assert "already exists" in cli_call(cli, "bundle-comparison", comparison_path, "--out", root, success=False)
    assert marker.read_bytes() == marker_bytes

    relocated = destination / f"{root.name} relocated"
    shutil.copytree(root, relocated)
    portable = relocated / receipt["portable_comparison"]
    checked = cli_call(cli, "check-comparison", portable, "--base", relocated)
    assert checked["all_match"] and checked["csv_hashes_recorded"] == receipt["csv_hashes_recorded"]
    assert len(checked["files"]) == receipt["reports"] + receipt["csv_parts"]
    assert all(Path(entry["resolved_path"]).is_relative_to(relocated.resolve()) for entry in checked["files"])

    manifest = relocated / receipt["trial_set"]
    verified = cli_call(cli, "verify-bundle", relocated)
    assert Path(verified["directory"]) == relocated.resolve()
    assert verified["receipt"] == receipt and verified["comparison"] == checked
    assert verified["receipt_sha256"] == hashlib.sha256(marker_bytes).hexdigest()

    rows = json.loads(manifest.read_bytes())["trials"]
    assert all(not Path(row["report"]).is_absolute() for row in rows)
    assert all(not Path(row["csv"]).is_absolute() for row in rows)
    rerun = cli_call(cli, "compare-runs", "--trial-set", manifest)
    fresh_path = destination / f"{root.name}-fresh.json"
    fresh = cli_call(cli, "compare-runs", "--bundle", relocated, "--out", fresh_path)
    assert fresh == rerun == json.loads(fresh_path.read_bytes())
    assert "already exists" in cli_call(cli, "compare-runs", "--bundle", relocated,
                                        "--out", fresh_path, success=False)
    assert "cannot be used with" in cli_call(cli, "compare-runs", "--bundle", relocated,
                                             "--trial-set", manifest, success=False)
    assert rerun["schedules"] == data["schedules"]
    assert [trial["sha256"] for trial in rerun["trials"]] == [trial["sha256"] for trial in data["trials"]]
    if audits is None:
        assert rerun["csv_audits"] is None
    else:
        def part_hashes(items):
            return [[part["sha256"] for part in audit["parts"]] for audit in items]
        assert part_hashes(rerun["csv_audits"]) == part_hashes(audits)
        relative_copy = destination / "relative-source-bundle"
        relative = cli_call(cli, "bundle-comparison", portable, "--base", relocated, "--out", relative_copy)
        assert (relative_copy / relative["original_comparison"]).read_bytes() == portable.read_bytes()
        assert cli_call(cli, "check-comparison", relative_copy / relative["portable_comparison"],
                        "--base", relative_copy)["all_match"]
        verify_bundle_failures(cli, relocated, receipt, checked["files"])
        verify_bundle_comparison_rejects_changed_bytes(cli, relocated, checked["files"])


def verify_bundle_failures(cli, root, receipt, files):
    marker = root / "bundle.json"
    marker_bytes = marker.read_bytes()
    for key in ("original_comparison", "portable_comparison", "trial_set"):
        path = root / receipt[key]
        original = path.read_bytes()
        path.write_bytes(original + b"\n")
        try:
            assert f"{path.name} SHA-256" in cli_call(cli, "verify-bundle", root, success=False)
        finally:
            path.write_bytes(original)

    for entry in (files[0], next(entry for entry in files if entry["csv_part"])):
        path = Path(entry["resolved_path"])
        original = path.read_bytes()
        path.write_bytes(b"!" + original[1:])
        try:
            assert "source check found Changed" in cli_call(cli, "verify-bundle", root, success=False)
        finally:
            path.write_bytes(original)

    partial = root.parent / "incomplete-bundle"
    partial.mkdir()
    assert "bundle.json" in cli_call(cli, "verify-bundle", partial, success=False)

    for name, path_key, row_key in (
        ("portable_comparison", "trials", "file"),
        ("trial_set", "trials", "report"),
    ):
        path = root / receipt[name]
        original = path.read_bytes()
        edited = json.loads(original)
        edited[path_key][0][row_key] = "../outside.json"
        changed = json.dumps(edited).encode()
        path.write_bytes(changed)
        marker.write_text(json.dumps({**receipt, f"{name}_sha256": hashlib.sha256(changed).hexdigest()}),
                          encoding="utf-8")
        try:
            assert "paths do not match the bundle layout" in cli_call(cli, "verify-bundle", root, success=False)
        finally:
            path.write_bytes(original)
            marker.write_bytes(marker_bytes)

    marker.write_text(json.dumps({**receipt, "csv_parts": receipt["csv_parts"] + 1}), encoding="utf-8")
    try:
        assert "coverage does not match" in cli_call(cli, "verify-bundle", root, success=False)
    finally:
        marker.write_bytes(marker_bytes)
    assert cli_call(cli, "verify-bundle", root)["receipt"] == receipt


def verify_bundle_comparison_rejects_changed_bytes(cli, root, files):
    report = Path(files[0]["resolved_path"])
    part = Path(next(entry for entry in files if entry["trial"] == 1 and entry["csv_part"] == 1)["resolved_path"])
    report_bytes = report.read_bytes()
    csv_bytes = part.read_bytes()
    header, row, remaining = csv_bytes.split(b"\n", 2)
    values = row.split(b",")
    values[5] = str(int(values[5]) + 1).encode()
    changed_csv = b"\n".join([header, b",".join(values), remaining])
    failed_export = root.parent / "changed-bundle-result.json"
    for path, original, changed, message in (
        (report, report_bytes, report_bytes + b"\n", "trial 1 report changed"),
        (part, csv_bytes, changed_csv, "trial 1 CSV part 1 changed"),
    ):
        path.write_bytes(changed)
        try:
            assert message in cli_call(cli, "compare-runs", "--bundle", root,
                                       "--out", failed_export, success=False)
            assert not failed_export.exists()
        finally:
            path.write_bytes(original)


def verify_trial_set_comparison(cli, destination, reports, bases):
    reports = [path.resolve() for path in reports]
    bases = [path.resolve() for path in bases]
    direct = cli_call(cli, "compare-runs", *reports, "--csv", bases[0], "--csv", bases[1])
    set_path = destination / "cli-trial-set.json"
    rows = [{"report": path.name, "csv": base.name} for path, base in zip(reports, bases)]
    rows[1]["report"] = str(reports[1])
    manifest = {"schema": 1, "audit_csv": True, "trials": rows}
    set_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    before = set_path.read_bytes()
    result_path = destination / "exported-set-comparison.json"
    from_set = cli_call(cli, "compare-runs", "--trial-set", set_path, "--out", result_path)
    result_bytes = result_path.read_bytes()
    assert json.loads(result_bytes) == from_set and result_bytes.endswith(b"\n")
    assert from_set == direct
    assert len(from_set["csv_audits"]) == 2
    assert set_path.read_bytes() == before
    assert "already exists" in cli_call(cli, "compare-runs", "--trial-set", set_path,
                                        "--out", result_path, success=False)
    assert "already exists" in cli_call(cli, "compare-runs", "--trial-set", set_path,
                                        "--out", set_path, success=False)
    assert result_path.read_bytes() == result_bytes and set_path.read_bytes() == before
    wrong_ext = destination / "no-export.txt"
    assert "must end in .json" in cli_call(cli, "compare-runs", "--trial-set", set_path,
                                            "--out", wrong_ext, success=False)
    assert not wrong_ext.exists()
    direct_path = destination / "exported-direct-comparison.json"
    assert cli_call(cli, "compare-runs", *reports, "--csv", bases[0], "--csv", bases[1],
                    "--out", direct_path) == json.loads(direct_path.read_bytes()) == from_set
    verify_comparison_file_hashes(cli, destination, result_path)
    verify_comparison_bundle(cli, destination, result_path)
    assert "cannot be used with" in cli_call(cli, "compare-runs", *reports, "--trial-set", set_path, success=False)
    assert "cannot be used with" in cli_call(cli, "compare-runs", "--trial-set", set_path, "--csv", bases[0], success=False)

    draft = destination / "cli-incomplete-trial-set.json"
    manifest["trials"][1]["csv"] = ""
    draft.write_text(json.dumps(manifest), encoding="utf-8")
    failed_output = destination / "failed-comparison.json"
    assert "missing at row 2" in cli_call(cli, "compare-runs", "--trial-set", draft,
                                           "--out", failed_output, success=False)
    assert not failed_output.exists()
    manifest["audit_csv"] = False
    counters = destination / "cli-counter-trial-set.json"
    counters.write_text(json.dumps(manifest), encoding="utf-8-sig")
    counter_result = destination / "counter-comparison.json"
    assert cli_call(cli, "compare-runs", "--trial-set", counters, "--out", counter_result) == cli_call(cli, "compare-runs", *reports)
    counter_check = cli_call(cli, "check-comparison", counter_result)
    assert counter_check["all_match"] and not counter_check["csv_hashes_recorded"]
    assert len(counter_check["files"]) == 2 and all(e["csv_part"] is None for e in counter_check["files"])
    verify_comparison_bundle(cli, destination, counter_result)
    manifest["trials"][0]["report"] = ""
    draft.write_text(json.dumps(manifest), encoding="utf-8")
    assert "report path for row 1" in cli_call(cli, "compare-runs", "--trial-set", draft, success=False)


def verify_comparison(cli, destination):
    profile = ROOT / "samples/synthetic.json"
    paths, trials = [], []
    for index, scheduler in enumerate(["deadline", "relative"] * 3):
        base = destination / f"trial-{index}.csv"
        path = destination / f"trial-{index}.json"
        report = cli_call(cli, "run", profile, "--scheduler", scheduler, "--seconds", 1, "--csv", base,
                          "--report", path)
        assert json.loads(path.read_text(encoding="utf-8")) == report
        assert not path.read_bytes().startswith(b"\xef\xbb\xbf")
        verify_csv(report, base)
        ctx = report["context"]
        assert ctx["schema"] == 1 and ctx["frontend"] == "cli" and ctx["csv_enabled"] is True
        assert ctx["source"] == {"kind": "synthetic", "faults": False}
        assert ctx["duration_limit_us"] == 1_000_000
        assert report["cyclic_elapsed_us"] >= 1_000_000 - ctx["profile"]["requested_cycle_us"]
        raw_profile = json.dumps(ctx["profile"], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        assert ctx["profile_sha256"] == hashlib.sha256(raw_profile).hexdigest()
        common = dict(ctx["profile"]); common["scheduler"] = "deadline"
        assert ctx["comparison_sha256"] == hashlib.sha256(
            json.dumps(common, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
        paths.append(path); trials.append(report)
    result = cli_call(cli, "compare-runs", *paths)
    assert len(result["trials"]) == 6 and [g["trials"] for g in result["schedules"]] == [3, 3]
    assert result["source"] == {"kind": "synthetic", "faults": False}
    assert "scheduler" not in result["common_profile_settings"]
    for index, row in enumerate(result["trials"]):
        original = trials[index]
        assert row["sha256"] == hashlib.sha256(paths[index].read_bytes()).hexdigest()
        assert row["send_spacing"] == original["send_spacing"]
        assert row["receive_spacing"] == original["receive_spacing"]
        assert row["valid_receive_spacing"] == original["valid_receive_spacing"]
        assert row["capture"] == original["capture"] and row["cyclic_elapsed_us"] == original["cyclic_elapsed_us"]
    for group in result["schedules"]:
        p99 = sorted(r["receive_spacing"]["p99_us"] for r in trials if r["scheduler"] == group["scheduler"])
        assert group["receive_p99_us"] == {"min": p99[0], "median": p99[1], "max": p99[2]}
        assert group["valid_receive_trials"] == 3
        assert group["valid_receive_p99_us"] == group["receive_p99_us"]  # These trials have no invalid replies.
    assert any("Offline fixture" in w for w in result["warnings"])
    assert any("CSV bytes" in w for w in result["warnings"])
    assert not any("fewer than three" in w for w in result["warnings"])
    (destination / "comparison.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    legacy = json.loads(paths[0].read_bytes())
    legacy.pop("valid_receive_spacing")
    legacy_path = destination / "legacy-valid-spacing.json"
    legacy_path.write_text(json.dumps(legacy), encoding="utf-8")
    historical = cli_call(cli, "compare-runs", legacy_path, paths[1], paths[2])
    assert historical["trials"][0]["valid_receive_spacing"] is None
    assert historical["schedules"][0]["valid_receive_trials"] == 1
    assert historical["schedules"][0]["valid_receive_p99_us"] is None
    assert any("no valid-input spacing metadata" in w for w in historical["warnings"])
    for name in ["count", "percentiles", "duration", "all-replies"]:
        changed = json.loads(paths[0].read_bytes())
        spacing = changed["valid_receive_spacing"]
        if name == "count": spacing["count"] -= 1
        elif name == "percentiles": spacing["p99_us"] = 0
        elif name == "duration": spacing["longest_gap_us"] = changed["cyclic_elapsed_us"] + 1
        else: spacing["longest_gap_us"] += 1
        invalid = destination / f"bad-valid-spacing-{name}.json"
        invalid.write_text(json.dumps(changed), encoding="utf-8")
        assert "valid-input spacing" in cli_call(cli, "compare-runs", invalid, paths[1], success=False)
    for index, path in enumerate(paths):
        audit_capture(cli, path, destination / f"trial-{index}.csv", trials[index])
    audited = cli_call(cli, "compare-runs", paths[0], paths[1],
        "--csv", destination / "trial-0.csv", "--csv", destination / "trial-1.csv")
    assert len(audited["csv_audits"]) == 2 and all(r["rows"] > 0 for r in audited["csv_audits"])
    assert not any("CSV bytes and field values are not inspected" in w for w in audited["warnings"])
    assert "one --csv base per report" in cli_call(cli, "compare-runs", paths[0], paths[1],
        "--csv", destination / "trial-0.csv", success=False)
    (destination / "audited-comparison.json").write_text(json.dumps(audited, indent=2), encoding="utf-8")
    verify_trial_set_comparison(cli, destination, paths[:2],
                                [destination / f"trial-{index}.csv" for index in range(2)])
    assert "duplicate report" in cli_call(cli, "compare-runs", paths[0], paths[0], success=False)
    assert "capture-start order" in cli_call(cli, "compare-runs", paths[1], paths[0], success=False)
    assert "both deadline and relative" in cli_call(cli, "compare-runs", paths[0], paths[2], success=False)
    before = paths[0].read_bytes()
    base = destination / "report-collision.csv"
    assert "reserve new report" in cli_call(cli, "run", profile, "--seconds", 1, "--csv", base,
        "--report", paths[0], success=False)
    assert paths[0].read_bytes() == before and not list(destination.glob("report-collision*.csv"))
    bom = destination / "utf8-bom.json"
    bom.write_bytes(b"\xef\xbb\xbf" + paths[1].read_bytes())
    assert len(cli_call(cli, "compare-runs", paths[0], bom)["trials"]) == 2
    for mutation, expected in [("legacy", "no versioned run context"), ("profile", "hash mismatch"),
            ("frontend", "configuration differs"), ("faults", "configuration differs"),
            ("cancelled", "cancelled"), ("counter", "capture counters"), ("csv", "CSV logging"),
            ("spacing", "spacing measurements"), ("replay", "playback timing"), ("schema", "unsupported run-context")]:
        changed = json.loads(json.dumps(trials[1]))
        if mutation == "legacy": changed.pop("context")
        elif mutation == "profile": changed["context"]["profile"]["tx"][0]["name"] += " changed"
        elif mutation == "frontend": changed["context"]["frontend"] = "gui"
        elif mutation == "faults": changed["context"]["source"]["faults"] = True
        elif mutation == "cancelled": changed["cancelled"] = True
        elif mutation == "counter": changed["capture"]["written"] -= 1
        elif mutation == "csv": changed["context"]["csv_enabled"] = False
        elif mutation == "spacing": changed["receive_spacing"]["count"] -= 1
        elif mutation == "schema": changed["context"]["schema"] = 2
        else: changed["context"]["source"] = {"kind": "replay", "fixture": "unused.json"}
        path = destination / f"bad-{mutation}.json"
        path.write_text(json.dumps(changed), encoding="utf-8")
        assert expected in cli_call(cli, "compare-runs", paths[0], path, success=False), mutation

    # Exercise actual DC startup twice: measured offsets may vary, settings must agree.
    dc_paths = []
    for index, scheduler in enumerate(["deadline", "relative"]):
        base = destination / f"dc-{scheduler}.csv"
        report = cli_call(cli, "run", ROOT / "samples/virtual-dc.json", "--backend", "virtual",
            "--virtual-model", "coe-dc", "--scheduler", scheduler, "--seconds", 1, "--csv", base)
        verify_csv(report, base, virtual=True)
        assert report["stopped_al"] == [1, 0]
        path = destination / f"dc-{index}.json"
        path.write_text(json.dumps(report), encoding="utf-8"); dc_paths.append(path)
    dc = cli_call(cli, "compare-runs", *dc_paths)
    assert dc["source"] == {"kind": "virtual", "model": "CoeDc", "fault": "None"}
    assert "system_time_offset_ns" not in dc["synchronization_settings"]["dc"]
    assert dc["synchronization_settings"]["dc"]["activation"]["value"] == 0
    assert "configuration differs" in cli_call(cli, "compare-runs", paths[0], dc_paths[0], success=False)
    changed = json.loads(dc_paths[1].read_text(encoding="utf-8"))
    changed["pdo_verification"]["readback"]["tx"]["sync_managers"][0]["pdos"][0]["entries"][0] ^= 1
    altered_pdo = destination / "different-device-pdo.json"
    altered_pdo.write_text(json.dumps(changed), encoding="utf-8")
    assert "PDO assignment readback" in cli_call(cli, "compare-runs", dc_paths[0], altered_pdo, success=False)
    oversized = destination / "oversized-report.json"
    with oversized.open("wb") as stream: stream.truncate(16 * 1024 * 1024 + 1)
    assert "exceeds 16 MiB" in cli_call(cli, "compare-runs", paths[0], oversized, success=False)
    (destination / "dc-comparison.json").write_text(json.dumps(dc, indent=2), encoding="utf-8")


def verify_capture_audit(cli, destination, comparison):
    original = json.loads((comparison / "trial-0.json").read_text(encoding="utf-8"))
    _, entries = rows(comparison / "trial-0.csv")
    names = list(entries[0])
    clone = lambda value: json.loads(json.dumps(value))

    def fixture(name, records=None, change=None, eol="\n", bom=False):
        folder = destination / name; folder.mkdir()
        report = clone(original)
        report["context"]["profile"]["rotate_rows"] = 0
        if records is None: records = clone(entries)
        report["capture"].update(parts=1, written=len(records), selected=len(records), overruns=0)
        report["error"] = "Authored offline CSV audit fixture; not a measured fault"
        if change: change(report)
        ctx = report["context"]
        ctx["profile_sha256"] = hashlib.sha256(json.dumps(ctx["profile"], ensure_ascii=False,
            separators=(",", ":")).encode("utf-8")).hexdigest()
        common = dict(ctx["profile"]); common["scheduler"] = "deadline"
        ctx["comparison_sha256"] = hashlib.sha256(json.dumps(common, ensure_ascii=False,
            separators=(",", ":")).encode("utf-8")).hexdigest()
        path = folder / "report.json"; path.write_text(json.dumps(report), encoding="utf-8")
        base = folder / "capture.csv"
        with base.open("w", encoding="utf-8-sig" if bom else "utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=names, lineterminator=eol)
            writer.writeheader(); writer.writerows(records)
        return path, base, report

    gap_rows = clone(entries)
    removed = {0, len(gap_rows)//2, len(gap_rows)-1}
    gap_rows = [row for i,row in enumerate(gap_rows) if i not in removed]
    def losses(r): r["capture"].update(selected=len(entries),overruns=3)
    path, base, r = fixture("queue-gaps", gap_rows, losses)
    audit = audit_capture(cli,path,base,r)
    assert [audit[k] for k in ["leading_index_gap","interior_index_gaps","trailing_index_gap"]] == [1,1,1]
    assert audit["logger_overruns"] == 3 and any("run failed" in w for w in audit["warnings"])

    path, base, r = fixture("crlf-bom", eol="\r\n", bom=True)
    audit = audit_capture(cli,path,base,r)
    assert audit["parts"][0]["eol"] == "CRLF" and audit["parts"][0]["utf8_bom"] is True
    extra = base.with_name("capture.0002.csv"); extra.write_bytes(b"preserve unrelated later file\n")
    assert audit_capture(cli,path,base,r)["rows"] == len(entries)
    assert extra.read_bytes() == b"preserve unrelated later file\n"

    def invalid_input(r):
        r.update(valid=0,replies=r["cycles"],timeouts=0,wkc_mismatches=r["cycles"],state_mismatches=0)
    path, base, r = fixture("zero-valid", [], invalid_input)
    assert audit_capture(cli,path,base,r)["rows"] == 0
    path, base, r = fixture("cancelled", change=lambda r:r.update(cancelled=True))
    assert audit_capture(cli,path,base,r)["run_cancelled"] is True

    repeated = clone(entries[:2])
    for name in names[5:]: repeated[1][name] = repeated[0][name]
    as_change = lambda r: r["context"]["profile"].update(mode="change")
    path, base, r = fixture("change-repeat", repeated, as_change)
    assert "repeats identical" in cli_call(cli,"verify-capture",path,base,success=False)
    for row in repeated: row["Scaled counter"] = "NaN"
    path, base, r = fixture("change-nan", repeated, as_change)
    audit = audit_capture(cli,path,base,r)
    assert audit["non_finite_values"] == 2 and audit["ambiguous_nan_repeats"] == 1

    for case, expected in [("generation","generation"),("utc","UTC anchor"),("sample","out of order"),
            ("elapsed","out of order"),("cycle","outside report bounds"),("unsigned","field width"),
            ("boolean","true or false"),("float","canonical f32"),("header","header differs"),
            ("newline","final newline"),("mixed-eol","mixed CSV"),("quotes","quoting"),
            ("blank","blank CSV"),("oversized","exceeds 1 MiB"),("incomplete","capture is incomplete")]:
        records = clone(entries)
        if case == "generation": records[0]["connection_generation"] = "999"
        elif case == "utc": records[0]["capture_start_utc"] = "2025-01-01T00:00:00Z"
        elif case == "sample": records[1]["sample_index"] = records[0]["sample_index"]
        elif case == "elapsed": records[1]["elapsed_us"] = "0"
        elif case == "cycle": records[0]["cycle_index"] = str(original["cycles"]+original["missed_deadlines"]+1)
        elif case == "unsigned": records[0]["Counter"] = "65536"
        elif case == "boolean": records[0]["Sensor active"] = "TRUE"
        elif case == "float": records[0]["Scaled counter"] = "1e999"
        path, base, r = fixture(case, records)
        data = base.read_bytes()
        if case == "header": base.write_bytes(data.replace(b"Counter",b"Different",1))
        elif case == "newline": base.write_bytes(data[:-1])
        elif case == "mixed-eol": base.write_bytes(data.replace(b"\n",b"\r\n",1))
        elif case == "quotes": base.write_bytes(data.replace(b"capture_start_utc",b'"capture_start_utc"',1))
        elif case == "blank": base.write_bytes(data+b"\n")
        elif case == "oversized": base.write_bytes(b"A"*(1024*1024+1))
        elif case == "incomplete":
            r["capture"]["written"] -= 1; path.write_text(json.dumps(r),encoding="utf-8")
        error = cli_call(cli,"verify-capture",path,base,success=False)
        assert expected in error,(case,error)

    # Metadata ordering persists across rotation boundaries and comparison reads actual CSV bytes.
    report_path = comparison / "trial-0.json"
    corrupt = destination / "rotated"; corrupt.mkdir()
    rotated_base = corrupt / "capture.csv"
    sources = sorted(comparison.glob("trial-0.*.csv"))
    for index, source in enumerate(sources,1):
        target = corrupt / f"capture.{index:04}.csv"
        target.write_bytes(source.read_bytes())
    second = corrupt / "capture.0002.csv"
    assert second.exists()
    with second.open(encoding="utf-8",newline="") as stream: records = list(csv.DictReader(stream))
    records[0]["sample_index"] = "1"
    with second.open("w",encoding="utf-8",newline="") as stream:
        writer=csv.DictWriter(stream,fieldnames=names,lineterminator="\n"); writer.writeheader(); writer.writerows(records)
    assert "out of order" in cli_call(cli,"verify-capture",report_path,rotated_base,success=False)
    assert "out of order" in cli_call(cli,"compare-runs",report_path,comparison/"trial-1.json",
        "--csv",rotated_base,"--csv",comparison/"trial-1.csv",success=False)

    # Exercise native writer quoting and multiple decoded kinds, including signed/endian and raw fields.
    profile = clone(original["context"]["profile"])
    profile["tx"] = [
        {"name":'Counter, "µs"',"bit":0,"width":16},
        {"name":"Signed swapped","bit":0,"width":16,"kind":"signed","swap_bytes_in_words":True},
        {"name":"Double","bit":0,"width":64,"kind":"f64"},
        {"name":"Payload","bit":0,"width":64,"kind":"raw"}]
    typed_profile=destination/"typed.json"; typed_profile.write_text(json.dumps(profile),encoding="utf-8")
    base=destination/"typed.csv"; path=destination/"typed-report.json"
    r=cli_call(cli,"run",typed_profile,"--seconds",1,"--csv",base,"--report",path)
    receipt=audit_capture(cli,path,base,r)
    assert receipt["fields"] == [f["name"] for f in profile["tx"]]
    (destination/"typed-audit.json").write_text(json.dumps(receipt,indent=2),encoding="utf-8")


def verify_discovery(cli, destination):
    reports = {}
    for case in ["normal","port-errors","counters-unavailable","information-unavailable",
                 "core-wkc","core-timeout","diagnostics-timeout"]:
        failed = case in ["core-wkc","core-timeout"]
        report = cli_call(cli,"scan-virtual","--case",case,success=not failed)
        audit = report["audit"]
        assert "device_audits" not in report
        assert audit["register_writes"] == audit["logical_writes"] == audit["physical_output_writes"] == 0
        assert audit["sii_reads"] == audit["coe_uploads"] == audit["coe_downloads"] == audit["op_requests"] == 0
        assert audit["state_requests"] == []
        if failed:
            assert report["devices"] == [] and report["error"]
            assert "Working Counters" in report["error"] if case=="core-wkc" else "no matching core" in report["error"]
        else:
            assert report["error"] is None and len(report["devices"]) == 1
            device = report["devices"][0]; diag = device["diagnostics"]; raw = diag["snapshot"]
            assert device["identity"] is None and device["name"] is None
            assert raw["source"] == "virtual_esc" and raw["position"] == 0
            assert raw["dl_status"] == diag["data_link"]["raw"]
            assert [p["physical_link"] for p in diag["data_link"]["ports"]] == device["link_ports"]
            absent_counters = case in ["counters-unavailable","diagnostics-timeout"]
            absent_information = case in ["information-unavailable","diagnostics-timeout"]
            assert (diag["counters"] is None) == absent_counters
            assert (diag["information"] is None) == absent_information
            if absent_counters: assert raw["counters"]["unavailable"] and raw["counters"]["value"] is None
            if absent_information: assert raw["information"]["unavailable"] and raw["information"]["value"] is None
            if case == "port-errors":
                assert diag["al"]["state"] == "SAFEOP" and diag["al"]["error"] is True
                assert diag["al"]["code"] == 0x1d and "Output" in diag["al"]["description"]
                assert diag["counters"]["pdi_error_code"] == 0x1234
                assert diag["counters"]["at_byte_maximum"] == ["port1.invalid_frames","port3.lost_links"]
                assert [(p["physical_link"],p["loop_closed"],p["signal_detected"]) for p in diag["data_link"]["ports"]] == [
                    (True,False,True),(True,True,True),(False,True,False),(True,False,True)]
                assert audit["final_al_status"] == 0x14 and audit["final_al_code"] == 0x1d
            else: assert audit["final_al_status"] == 1 and audit["final_al_code"] == 0
            snapshot = destination / (case+"-snapshot.json")
            snapshot.write_text(json.dumps(raw),encoding="utf-8")
            assert cli_call(cli,"decode-esc",snapshot) == diag
        reports[case] = report
    chain_cases = ["two-devices", "second-device-diagnostics-timeout", "second-device-core-timeout"]
    for case in chain_cases:
        core_timeout = case == "second-device-core-timeout"
        diagnostics_timeout = case == "second-device-diagnostics-timeout"
        report = cli_call(cli, "scan-virtual", "--case", case, success=not core_timeout)
        audits = report["device_audits"]
        assert len(audits) == 2 and report["audit"] == audits[0]
        downstream_drops = int(core_timeout or diagnostics_timeout)
        assert [audit["dropped_replies"] for audit in audits] == [0, downstream_drops]
        for audit in audits:
            assert all(audit[field] == 0 for field in [
                "register_writes", "logical_writes", "logical_reads", "physical_output_writes",
                "sii_reads", "coe_uploads", "coe_downloads", "op_requests",
            ])
            assert audit["state_requests"] == []
        if core_timeout:
            assert report["devices"] == [] and "bus position 1" in report["error"]
        else:
            assert report["error"] is None
            assert [
                (device["position"], device["station_address"], device["alias"],
                 device["link_ports"], device["al_status"])
                for device in report["devices"]
            ] == [
                (0, 0x1000, 0x42, [True, True, False, False], 1),
                (1, 0x1001, 0x43, [True, False, False, False], 2),
            ]
            for position, device in enumerate(report["devices"]):
                assert device["identity"] is None and device["name"] is None
                diag = device["diagnostics"]
                raw = diag["snapshot"]
                assert raw["source"] == "virtual_esc" and raw["position"] == position
                ports = diag["data_link"]["ports"]
                assert [port["signal_detected"] for port in ports] == device["link_ports"]
                assert [not port["loop_closed"] for port in ports] == device["link_ports"]
                if position == 1 and diagnostics_timeout:
                    for name in ["information", "counters"]:
                        assert diag[name] is None
                        assert raw[name]["value"] is None and "within 30 ms" in raw[name]["unavailable"]
                else:
                    assert diag["counters"]["ports"][0]["invalid_frames"] == position * 7
                    assert diag["information"]["controller_type"] == 0x11 + position
                    implemented = [
                        kind != "Not implemented" for kind in diag["information"]["port_types"]
                    ]
                    assert implemented == device["link_ports"]
        reports[case] = report
    for model in ["sii","coe-dc","coe-normal","coe-segmented"]:
        report = cli_call(cli,"scan-virtual","--model",model)
        assert report["audit"]["register_writes"] == 0
        info=report["devices"][0]["diagnostics"]["information"]
        assert info["fmmus"] == 2 and info["sync_managers"] == (2 if model=="sii" else 4)
        assert info["feature_bits"] == (0x10c if model=="coe-dc" else 0)
    raw = reports["port-errors"]["devices"][0]["diagnostics"]["snapshot"]
    for change in ["schema","non-utc","both","missing","short-array","byte-range","unknown"]:
        altered=json.loads(json.dumps(raw))
        if change=="schema": altered["schema"]=2
        elif change=="non-utc": altered["started_utc"]="2026-01-01T00:00:00+01:00"
        elif change=="both": altered["counters"]["unavailable"]="contradictory"
        elif change=="missing": altered["counters"]={"value":None,"unavailable":None}
        elif change=="short-array": altered["counters"]["value"].pop()
        elif change=="byte-range": altered["information"]["value"][0]=256
        else: altered["unexpected"]=1
        path=destination/("invalid-"+change+".json");path.write_text(json.dumps(altered),encoding="utf-8")
        assert cli_call(cli,"decode-esc",path,success=False)
    bom=destination/"bom.json";bom.write_bytes(b"\xef\xbb\xbf"+json.dumps(raw).encode("utf-8"))
    assert cli_call(cli,"decode-esc",bom)["snapshot"] == raw
    large=destination/"large.json";large.write_bytes(b" "*(64*1024+1))
    assert "exceeds 64 KiB" in cli_call(cli,"decode-esc",large,success=False)
    sample=cli_call(cli,"decode-esc",ROOT/"samples/esc-diagnostics.json")
    assert sample["snapshot"]["source"] == "authored" and sample["counters"]["pdi_error_code"] == 0x1234
    (destination/"scans.json").write_text(json.dumps(reports,indent=2),encoding="utf-8")


def verify_input_group(cli, destination):
    manifest = ROOT / "samples/input-group.json"
    payload = "2a 00 01 00 00 00 80 3f 12 34 00 00 00 00 00 40"
    plan = cli_call(cli, "inspect-input-group", manifest)
    assert (plan["schema"], plan["source"], plan["logical_start"]) == (1, "offline_profiles", 0)
    assert (plan["input_bytes"], plan["expected_wkc"], plan["actual_wkc"]) == (16, 2, None)
    assert "frame" not in plan and "fmmu" not in plan and all("al" not in device for device in plan["devices"])
    for index, device in enumerate(plan["devices"]):
        assert (device["position"], device["offset"], device["tx_bytes"]) == (index, index * 8, 8)
        assert device["input"] is None
        assert device["identity"]["product"] == index + 1
        profile = manifest.parent / device["profile"]
        assert device["profile_sha256"] == hashlib.sha256(profile.read_bytes()).hexdigest()
    out = destination / "decoded.json"
    decoded = cli_call(cli, "inspect-input-group", manifest, "--hex", payload, "--wkc", 2, "--out", out)
    assert decoded == json.loads(out.read_bytes()) and decoded["actual_wkc"] == 2
    expected = [("2a0001000000803f", ["42", "true", "1"]), ("1234000000000040", ["13330", "false", "2"])]
    for device, (raw, values) in zip(decoded["devices"], expected, strict=True):
        assert device["input"]["raw_hex"] == raw
        single = cli_call(cli, "decode", manifest.parent / device["profile"], raw)
        assert device["input"]["fields"] == single
        assert [f["value"] for f in single] == values

    saved = out.read_bytes()
    assert "existing paths are preserved" in cli_call(cli, "inspect-input-group", manifest, "--out", out, success=False)
    assert out.read_bytes() == saved
    invalid = destination / "no-invalid-output.json"
    for wkc in (1, 3):
        assert "payload decoding withheld" in cli_call(
            cli, "inspect-input-group", manifest, "--hex", payload, "--wkc", wkc, "--out", invalid,
            success=False,
        )
        assert not invalid.exists()
    assert "expected 16 group input bytes" in cli_call(
        cli, "inspect-input-group", manifest, "--hex", "00", "--wkc", 2, success=False,
    )
    for option, value, required in [("--hex", payload, "--wkc"), ("--wkc", 2, "--hex")]:
        assert required in cli_call(cli, "inspect-input-group", manifest, option, value, success=False)

    first, second = json.loads(manifest.read_bytes())["devices"]
    first["profile"] = str((manifest.parent / first["profile"]).resolve())
    second["profile"] = str((manifest.parent / second["profile"]).resolve())
    def write_manifest(name, devices, schema=1):
        path = destination / name
        path.write_text(json.dumps({"schema": schema, "devices": devices}), encoding="utf-8")
        return path

    middle = {"position": 1, "profile": "zero-input.json", "identity": second["identity"]}
    zero = destination / middle["profile"]
    zero.write_bytes(b"\xef\xbb\xbf" + json.dumps({"expected_identity": middle["identity"]}).encode("utf-8"))
    with_zero = write_manifest("zero-middle.json", [first, middle, {**second, "position": 2}])
    witness = cli_call(cli, "inspect-input-group", with_zero, "--hex", payload, "--wkc", 2)
    assert witness["expected_wkc"] == 2 and witness["input_bytes"] == 16
    assert [d["offset"] for d in witness["devices"]] == [0, None, 8]
    assert witness["devices"][1]["input"] is None
    assert witness["devices"][1]["profile_sha256"] == hashlib.sha256(zero.read_bytes()).hexdigest()

    big = destination / "full-input.json"
    big.write_text(json.dumps({"expected_identity": first["identity"], "tx_bytes": 1024}), encoding="utf-8")
    full = {**first, "profile": big.name}
    assert cli_call(cli, "inspect-input-group", write_manifest("max.json", [full, middle]))["input_bytes"] == 1024
    for name, devices, schema, message in [
        ("schema", [first], 2, "unsupported input group schema"),
        ("order", [second, first], 1, "expected position 0"),
        ("identity", [first, {**second, "profile": first["profile"]}], 1, "position 1 profile must carry"),
        ("empty", [{**middle, "position": 0}], 1, "at least one nonempty TxPDO image"),
        ("oversize", [full, second], 1, "group input exceeds 1024 bytes"),
        ("count", [{**first, "position": index} for index in range(17)], 1, "device positions"),
    ]:
        invalid_manifest = write_manifest(name + ".json", devices, schema)
        assert message in cli_call(cli, "inspect-input-group", invalid_manifest, success=False)
    (destination / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")


def verify_input_group_frame(cli, destination):
    manifest = ROOT / "samples/input-group.json"
    sample = ROOT / "samples/input-group-frame.json"
    reference = json.loads(sample.read_bytes())
    reply = bytes.fromhex(reference["reply_hex"])
    result = cli_call(cli, "inspect-input-group", manifest, "--frame", sample)
    assert (result["input_bytes"], result["expected_wkc"], result["actual_wkc"]) == (16, 2, 2)
    assert result["frame"] == {
        "index": 42, "reply_sha256": hashlib.sha256(reply).hexdigest(),
        "lrd_wkc_matches": True, "valid": True,
    }
    legacy = cli_call(cli, "inspect-input-group", manifest, "--hex", reply[26:42].hex(), "--wkc", 2)
    for device, previous, station in zip(result["devices"], legacy["devices"], reference["stations"], strict=True):
        assert device["input"] == previous["input"]
        assert device["al"] == {
            "station_address": station, "expected_wkc": 1, "actual_wkc": 1, "clean_safeop": True,
            "status": {"raw": 4, "state": "SAFEOP", "error": False, "uninterpreted_flags": 0,
                       "code": 0, "description": "No reported AL error"},
        }

    def case(name, packet=reply, **changes):
        path = destination / f"{name}.json"
        path.write_text(json.dumps({**reference, "reply_hex": packet.hex(), **changes}), encoding="utf-8")
        return path

    for name, offset, replacement in [
        ("error-flag", 72, 0x14), ("al-code", 76, 0x1e), ("preop", 72, 2), ("op", 72, 8),
        ("missing-al", 78, 0), ("ambiguous-al", 78, 2), ("partial-lrd", 42, 1),
    ]:
        altered = bytearray(reply)
        altered[offset] = replacement
        saved = case(name, altered)
        receipt = destination / f"{name}-receipt.json"
        report = cli_call(cli, "inspect-input-group", manifest, "--frame", saved, "--out", receipt)
        assert json.loads(receipt.read_bytes()) == report
        assert report["frame"]["valid"] is False and all(d["input"] is None for d in report["devices"])
        assert report["frame"]["lrd_wkc_matches"] == (name != "partial-lrd")
        al = report["devices"][1]["al"]
        if name in ("missing-al", "ambiguous-al"):
            assert al["actual_wkc"] == replacement and al["status"] is None
        elif offset == 72:
            assert al["status"]["raw"] == replacement and not al["clean_safeop"]
        elif offset == 76:
            assert al["status"]["code"] == replacement and not al["clean_safeop"]
        else:
            assert al["clean_safeop"] and report["actual_wkc"] == 1

    flagged = bytearray(reply)
    flagged[72] = 0x24
    special = cli_call(cli, "inspect-input-group", manifest, "--frame", case("upper-flag", flagged))
    assert special["frame"]["valid"] and special["devices"][1]["al"]["status"]["uninterpreted_flags"] == 0x20
    for name, offset, replacement in [
        ("request-source", 6, 0x10), ("wrong-index", 63, 43), ("wrong-station", 64, 2),
        ("wrong-command", 62, 5), ("wrong-more-flag", 69, 0x80),
    ]:
        altered = bytearray(reply)
        altered[offset] = replacement
        failed = cli_call(cli, "inspect-input-group", manifest, "--frame", case(name, altered), success=False)
        assert "does not match" in failed
    for name, path, expected_error in [
        ("truncated", case("truncated", reply[:-1]), "does not match"),
        ("reordered", case("reordered", stations=[4097, 4096]), "does not match"),
        ("duplicate", case("duplicate", stations=[4096, 4096]), "duplicate station"),
        ("missing", case("missing", stations=[4096]), "one station address per position"),
        ("zero", case("zero", stations=[4096, 0]), "must be nonzero"),
        ("version", case("version", schema=2), "unsupported group frame schema"),
        ("hex", case("bad-hex", reply_hex="00z"), "hex byte pairs"),
        ("length", case("oversized", reply + b"\0" * 1514), "frame exceeds 1514 bytes"),
    ]:
        out = destination / f"{name}-no-output.json"
        assert expected_error in cli_call(cli, "inspect-input-group", manifest, "--frame", path, "--out", out,
                                          success=False)
        assert not out.exists()
    assert "cannot be used" in cli_call(cli, "inspect-input-group", manifest, "--frame", sample,
                                       "--hex", reply[26:42].hex(), "--wkc", 2, success=False)

    # A zero-input position still needs its own AL reply. Fill all 16 positions and
    # the 1024-byte LRD limit to exercise the complete datagram chain.
    authored_identity = {"vendor": 1, "product": 1, "revision": 1}
    full = destination / "full.json"
    full.write_text(json.dumps({"expected_identity": authored_identity, "tx_bytes": 1024}), encoding="utf-8")
    zero = destination / "zero.json"
    zero.write_text(json.dumps({"expected_identity": authored_identity}), encoding="utf-8")
    group_path = destination / "max-group.json"
    group_path.write_text(json.dumps({"schema": 1, "devices": [
        {"position": i, "profile": full.name if i == 0 else zero.name, "identity": authored_identity}
        for i in range(16)
    ]}), encoding="utf-8")
    stations = list(range(4096, 4112))
    body = struct.pack("<BBIHH", 0x0a, 42, 0, 0x8400, 0) + bytes(1024) + struct.pack("<H", 1)
    for i, station in enumerate(stations):
        flags = 0x8006 if i < 15 else 6
        body += struct.pack("<BBHHHHHHHH", 4, 42, station, 0x130, flags, 0, 4, 0, 0, 1)
    packet = reply[:14] + struct.pack("<H", 0x1000 | len(body)) + body
    max_sample = case("max-frame", packet, stations=stations)
    full_group = cli_call(cli, "inspect-input-group", group_path, "--frame", max_sample)
    assert full_group["frame"]["valid"] and full_group["expected_wkc"] == 1
    assert full_group["devices"][0]["input"]["raw_hex"] == "00" * 1024
    assert all(d["input"] is None and d["al"]["clean_safeop"] for d in full_group["devices"][1:])
    no_last_al = case("max-missing-last", packet[:-2] + bytes(2), stations=stations)
    partial = cli_call(cli, "inspect-input-group", group_path, "--frame", no_last_al)
    assert partial["frame"]["lrd_wkc_matches"] and not partial["frame"]["valid"]
    assert partial["devices"][-1]["al"]["status"] is None
    assert all(d["input"] is None for d in partial["devices"])
    (destination / "healthy-receipt.json").write_text(json.dumps(result, indent=2), encoding="utf-8")


def verify_input_group_fmmu(cli, destination):
    manifest = ROOT / "samples/input-group.json"
    saved_frame = ROOT / "samples/input-group-frame.json"
    sample = ROOT / "samples/input-group-fmmu.json"
    frame_args = ("--frame", saved_frame)
    standalone = cli_call(cli, "inspect-input-group", manifest, "--fmmu", sample)
    review = standalone["fmmu"]
    assert review["source_sha256"] == hashlib.sha256(sample.read_bytes()).hexdigest()
    assert review["valid"] and review["layout_matches"] and review["stations_match"] is None
    assert standalone["actual_wkc"] is None and "frame" not in standalone
    assert all(d["input"] is None for d in standalone["devices"])
    first, second = review["devices"]
    assert [d["station_address"] for d in (first, second)] == [4096, 4097]
    assert not first["issues"] and not second["issues"]
    assert first["slots"][0]["mapping"]["physical_start"] == 0x1200
    assert first["slots"][1]["mapping"]["write_enabled"] and not first["slots"][1]["mapping"]["read_enabled"]
    assert [s["mapping"]["logical_start"] for s in second["slots"]] == [18, 12, 8]
    checked = cli_call(cli, "inspect-input-group", manifest, "--fmmu", sample, *frame_args)
    previous = cli_call(cli, "inspect-input-group", manifest, *frame_args)
    assert "fmmu" not in previous
    assert checked["frame"] == previous["frame"] and checked["devices"] == previous["devices"]
    assert checked["fmmu"]["valid"] and checked["fmmu"]["stations_match"]
    assert all(device["station_matches"] for device in checked["fmmu"]["devices"])
    (destination / "healthy-receipt.json").write_text(json.dumps(checked, indent=2), encoding="utf-8")

    for name, expected in [
        ("wrong-range", "outside planned input"), ("overlap", "overlaps"), ("gap", "unmapped logical input bytes"),
        ("unaligned", "not byte aligned"), ("zero-length", "zero length"), ("physical-overflow", "exceeds the physical"),
        ("logical-overflow", "exceeds the logical"), ("unknown-count", "FMMU count WKC"),
        ("over-limit-count", "count 17 exceeds 16"), ("missing-slot", "ESC reports 3 slots"),
        ("bad-slot-wkc", "FMMU 0 WKC 2"), ("wrong-station", None),
    ]:
        evidence = json.loads(sample.read_bytes())
        downstream = evidence["devices"][1]
        mapped = downstream["slots"][2]["value"]
        if name == "wrong-range":
            mapped[0] = 7
        elif name == "overlap":
            mapped[4] = 5
        elif name == "gap":
            mapped[12] = 0
        elif name == "unaligned":
            mapped[10] = 1
        elif name == "zero-length":
            mapped[4] = 0
        elif name == "physical-overflow":
            mapped[8:10] = [255, 255]
        elif name == "logical-overflow":
            mapped[:4] = [255] * 4
        elif name == "unknown-count":
            downstream["count"]["wkc"] = 0
        elif name == "over-limit-count":
            downstream["count"]["value"] = 17
        elif name == "missing-slot":
            downstream["slots"].pop(0)
        elif name == "bad-slot-wkc":
            downstream["slots"][0]["wkc"] = 2
        else:
            downstream["station_address"] = 4100
        path = destination / f"{name}.json"
        path.write_text(json.dumps(evidence), encoding="utf-8")
        out = destination / f"{name}-receipt.json"
        report = cli_call(cli, "inspect-input-group", manifest, "--fmmu", path, *frame_args, "--out", out)
        assert report == json.loads(out.read_bytes())
        audit = report["fmmu"]
        assert report["frame"]["valid"] and not audit["valid"]
        assert all(device["input"] is None for device in report["devices"])
        assert audit["layout_matches"] == (name == "wrong-station")
        assert audit["stations_match"] == (name != "wrong-station")
        if expected:
            assert any(expected in issue for issue in audit["devices"][1]["issues"]), audit
        if name == "bad-slot-wkc":
            assert audit["devices"][1]["slots"][0]["mapping"] is None
        if name == "wrong-station":
            assert not audit["devices"][1]["station_matches"]

    for name, expected in [
        ("wrong-schema", "unsupported group FMMU schema"),
        ("duplicate-station", "duplicate station address"),
        ("oversize-record", "parse "),
        ("oversize-slot-list", "more than 16 FMMU slots"),
        ("missing-device", "one station address per position"),
    ]:
        evidence = json.loads(sample.read_bytes())
        downstream = evidence["devices"][1]
        if name == "wrong-schema":
            evidence["schema"] = 2
        elif name == "duplicate-station":
            downstream["station_address"] = 4096
        elif name == "oversize-record":
            downstream["slots"][0]["value"].append(0)
        elif name == "oversize-slot-list":
            downstream["slots"] = [downstream["slots"][0]] * 17
        else:
            evidence["devices"].pop()
        path = destination / f"{name}.json"
        path.write_text(json.dumps(evidence), encoding="utf-8")
        out = destination / f"{name}-no-output.json"
        assert expected in cli_call(cli, "inspect-input-group", manifest, "--fmmu", path, "--out", out, success=False)
        assert not out.exists()
    assert "cannot be used" in cli_call(cli, "inspect-input-group", manifest, "--fmmu", sample,
                                       "--hex", "00", "--wkc", 2, success=False)

    zero = destination / "zero-input.json"
    plan = json.loads(manifest.read_bytes())
    for device in plan["devices"]:
        device["profile"] = str((manifest.parent / device["profile"]).resolve())
    identity = plan["devices"][1]["identity"]
    zero.write_text(json.dumps({"expected_identity": identity}), encoding="utf-8")
    plan["devices"].append({"position": 2, "profile": zero.name, "identity": identity})
    zero_plan = destination / "zero-plan.json"
    zero_plan.write_text(json.dumps(plan), encoding="utf-8")
    evidence = json.loads(sample.read_bytes())
    zero_device = {"station_address": 4098, "count": {"wkc": 1, "value": 0}, "slots": []}
    evidence["devices"].append(zero_device)
    zero_snapshot = destination / "zero-snapshot.json"
    zero_snapshot.write_text(json.dumps(evidence), encoding="utf-8")
    assert cli_call(cli, "inspect-input-group", zero_plan, "--fmmu", zero_snapshot)["fmmu"]["valid"]
    zero_device["count"]["value"] = 1
    zero_device["slots"].append(evidence["devices"][0]["slots"][0])
    zero_snapshot.write_text(json.dumps(evidence), encoding="utf-8")
    zero_report = cli_call(cli, "inspect-input-group", zero_plan, "--fmmu", zero_snapshot)["fmmu"]
    assert not zero_report["valid"] and "no planned input" in zero_report["devices"][2]["issues"][0]

    dirty = json.loads(saved_frame.read_bytes())
    raw = bytearray.fromhex(dirty["reply_hex"])
    raw[76] = 0x1e
    dirty["reply_hex"] = raw.hex()
    dirty_frame = destination / "bad-al-frame.json"
    dirty_frame.write_text(json.dumps(dirty), encoding="utf-8")
    dirty_report = cli_call(cli, "inspect-input-group", manifest, "--fmmu", sample, "--frame", dirty_frame)
    assert dirty_report["fmmu"]["valid"] and not dirty_report["frame"]["valid"]
    assert all(device["input"] is None for device in dirty_report["devices"])


def verify_input_group_sync_managers(cli, destination):
    manifest = ROOT / "samples/input-group.json"
    frame = ROOT / "samples/input-group-frame.json"
    fmmu = ROOT / "samples/input-group-fmmu.json"
    sample = ROOT / "samples/input-group-sync-managers.json"

    def inspect(sync=sample, mapped=fmmu, *args, **kwargs):
        return cli_call(cli, "inspect-input-group", manifest, "--fmmu", mapped,
                        "--sync-managers", sync, *args, **kwargs)

    def save(name, value):
        path = destination / (name + ".json")
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    previous = cli_call(cli, "inspect-input-group", manifest, "--fmmu", fmmu, "--frame", frame)
    assert "sync_managers" not in previous
    standalone = inspect()
    assert standalone["sync_managers"]["valid"] and standalone["fmmu"]["valid"]
    assert "frame" not in standalone and all(d["input"] is None for d in standalone["devices"])
    checked = inspect(sample, fmmu, "--frame", frame, "--out", destination / "healthy-receipt.json")
    assert checked == json.loads((destination / "healthy-receipt.json").read_bytes())
    assert checked["devices"] == previous["devices"] and checked["frame"] == previous["frame"]
    report = checked["sync_managers"]
    assert report["valid"] and report["source_sha256"] == hashlib.sha256(sample.read_bytes()).hexdigest()
    for index, device in enumerate(report["devices"]):
        assert device["station_address"] == 4096 + index and device["fmmu_station_matches"]
        assert device["fmmu_physical_ranges"] == device["input_buffer_ranges"] == [
            {"start": 0x1200, "end": 0x1208}
        ]
        aliases = [slot["covering_fmmu_slots"] for slot in device["slots"]]
        assert aliases == ([[], [], [], [0]] if index == 0 else [[], [1, 2]])

    def reject(path, text, mapping=fmmu, frame_path=frame, fmmu_valid=True):
        review = inspect(path, mapping, "--frame", frame_path)
        assert review["frame"]["valid"] and review["fmmu"]["valid"] == fmmu_valid
        assert not review["sync_managers"]["valid"]
        assert all(d["input"] is None for d in review["devices"])
        downstream = review["sync_managers"]["devices"][1]
        assert any(text in issue for issue in downstream["issues"]), downstream
        return downstream

    for name, slot, offset, values, issue in [
        ("short-input", 1, 2, [7], "coverage differs"),
        ("disabled", 1, 6, [0], "coverage differs"),
        ("pdi-disabled", 1, 7, [1], "deactivated by its PDI"),
        ("mailbox", 1, 4, [2], "coverage differs"),
        ("wrong-direction", 1, 4, [4], "coverage differs"),
        ("reserved-mode", 1, 4, [3], "coverage differs"),
        ("register-space", 1, 0, [0, 1], "invalid physical range"),
        ("overflow", 1, 0, [255, 255], "invalid physical range"),
        ("overlaps-output", 0, 0, [1, 18], "overlaps enabled SM0"),
    ]:
        evidence = json.loads(sample.read_bytes())
        raw = evidence["devices"][1]["slots"][slot]["value"]
        raw[offset:offset + len(values)] = values
        reject(save(name, evidence), issue)

    for name, field, changes, issue in [
        ("count-wkc", "count", {"wkc": 0}, "count WKC 0"),
        ("missing-slot", "count", {"value": 3}, "reports 3 SyncManager slots"),
        ("count-limit", "count", {"value": 17}, "count 17 exceeds 16"),
        ("ambiguous-slot", "slot", {"wkc": 2}, "SM1 WKC 2"),
        ("station", "station", {"station_address": 4112}, "station address differs"),
    ]:
        evidence = json.loads(sample.read_bytes())
        device = evidence["devices"][1]
        target = {"count": device["count"], "slot": device["slots"][1], "station": device}[field]
        target.update(changes)
        downstream = reject(save(name, evidence), issue)
        if name == "ambiguous-slot":
            assert downstream["slots"][1]["channel"] is None
        if name == "station":
            assert not downstream["fmmu_station_matches"]

    for name, offset, value, expected in [
        ("wrong-fmmu-target", 8, 8, "coverage differs"),
        ("physical-alias", 8, 4, "overlap in physical memory"),
        ("bad-logical-range", 0, 7, "logical layout check did not pass"),
    ]:
        evidence = json.loads(fmmu.read_bytes())
        evidence["devices"][1]["slots"][2]["value"][offset] = value
        reject(sample, expected, save(name, evidence), fmmu_valid=(offset != 0))

    mapping = json.loads(fmmu.read_bytes())
    mapping["devices"][1]["slots"][1]["value"][8:10] = [0, 19]
    sync = json.loads(sample.read_bytes())
    device = sync["devices"][1]
    device["count"]["value"] = 3
    device["slots"][1]["value"][2] = 4
    device["slots"].append({"wkc": 1, "value": [0, 19, 4, 0, 0, 0, 1, 0]})
    split = inspect(save("two-input-buffers", sync), save("split-fmmus", mapping), "--frame", frame)
    assert split["sync_managers"]["valid"] and split["devices"] == previous["devices"]
    downstream = split["sync_managers"]["devices"][1]
    assert downstream["input_buffer_ranges"] == [
        {"start": 0x1200, "end": 0x1204}, {"start": 0x1300, "end": 0x1304}
    ]
    assert [s["covering_fmmu_slots"] for s in downstream["slots"]] == [[], [2], [1]]
    second_fmmu = mapping["devices"][1]
    coalesced = second_fmmu["slots"].pop()
    coalesced["value"][4] = 8
    second_fmmu["slots"][1] = coalesced
    second_fmmu["count"]["value"] = 2
    reject(destination / "two-input-buffers.json", "coverage differs", save("coalesced-over-gap", mapping))

    malformed = json.loads(sample.read_bytes())
    malformed["devices"][1]["slots"][1]["value"].append(0)
    no_output = destination / "unusable-export.json"
    assert "parse " in inspect(save("bad-register", malformed), fmmu, "--out", no_output, success=False)
    assert not no_output.exists()
    assert "--fmmu" in cli_call(cli, "inspect-input-group", manifest, "--sync-managers", sample, success=False)


def verify_input_group_pdo(cli, destination):
    manifest = ROOT / "samples/input-group.json"
    frame = ROOT / "samples/input-group-frame.json"
    fmmu = ROOT / "samples/input-group-fmmu.json"
    sm = ROOT / "samples/input-group-sync-managers.json"
    sample = ROOT / "samples/input-group-pdo.json"

    def save(name, obj):
        path = destination / (name + ".json")
        path.write_text(json.dumps(obj), encoding="utf-8")
        return path

    def inspect(snapshot=sample, *args, mapping=fmmu, slots=sm, plan=manifest, **kwargs):
        return cli_call(cli, "inspect-input-group", plan, "--fmmu", mapping, "--sync-managers", slots,
                        "--pdo", snapshot, *args, **kwargs)

    baseline = cli_call(cli, "inspect-input-group", manifest, "--fmmu", fmmu, "--sync-managers", sm, "--frame", frame)
    assert "pdo" not in baseline
    standalone = inspect()
    assert standalone["pdo"]["valid"] and "frame" not in standalone
    assert all(d["input"] is None for d in standalone["devices"])
    receipt = destination / "healthy-receipt.json"
    checked = inspect(sample, "--frame", frame, "--out", receipt)
    assert checked == json.loads(receipt.read_bytes())
    assert checked["devices"] == baseline["devices"] and checked["frame"] == baseline["frame"]
    report = checked["pdo"]
    assert report["valid"] and report["source_sha256"] == hashlib.sha256(sample.read_bytes()).hexdigest()
    for position, (device, source, channel) in enumerate(zip(report["devices"], ("coe", "sii"), (3, 1), strict=True)):
        assert device["readback"]["mapping_source"] == source and device["station_address"] == 4096 + position
        assert device["tx"]["image_bytes"] == 8 and not device["issues"]
        assert [field["state"] for field in device["tx"]["fields"]] == ["matched"] * 3
        assert device["placements"] == [{
            "sync_manager": channel, "logical_start": 8 * position, "bytes": 8,
            "physical_range": {"start": 0x1200, "end": 0x1208}, "matches": True,
        }]
        rows = manifest.parent / baseline["devices"][position]["profile"]
        single = save(f"single-{position}", {"tx": device["readback"], "rx": None})
        assert device["tx"] == cli_call(cli, "verify-pdo", rows, single)["tx"]

    def reject(snapshot, text, **options):
        failed = inspect(snapshot, "--frame", frame, **options)
        assert failed["frame"]["valid"] and failed["fmmu"]["valid"] and failed["sync_managers"]["valid"]
        assert not failed["pdo"]["valid"] and all(d["input"] is None for d in failed["devices"])
        device = failed["pdo"]["devices"][1]
        assert any(text in reason for reason in device["issues"] + device["tx"]["errors"]), device
        return device

    for name, issue in [
        ("reordered", "no device entry"), ("wrong-revision", "identity differs"),
        ("wrong-station", "station address differs"), ("unavailable", "layout is unavailable"),
        ("esi", "supply CoE or SII"), ("wrong-sm", "SM0 TxPDO bytes"),
        ("rx-index", "outside 0x1a00"), ("wrong-sm-length", "register length 7"),
        ("inconsistent-readback", "both a TxPDO layout and an unavailable reason"),
    ]:
        evidence = json.loads(sample.read_bytes())
        device = evidence["devices"][1]
        channel = device["tx"]["sync_managers"][0]
        pdo = channel["pdos"][0]
        if name == "reordered":
            pdo["entries"][0], pdo["entries"][3] = pdo["entries"][3], pdo["entries"][0]
        elif name == "wrong-revision":
            device["identity"]["revision"] += 1
        elif name == "wrong-station":
            device["station_address"] = 4099
        elif name == "unavailable":
            device["tx"] = None
            device["tx_unavailable"] = "no saved read"
        elif name == "esi":
            device["tx"]["mapping_source"] = "esi"
        elif name == "wrong-sm":
            channel["index"] = 0
        elif name == "rx-index":
            pdo["index"] = 0x1600
        elif name == "wrong-sm-length":
            channel["configured_bytes"] = 7
        else:
            device["tx_unavailable"] = "contradictory evidence"
        result = reject(save(name, evidence), issue)
        if name == "reordered":
            assert result["tx"]["image_bytes"] == 8
        if name == "unavailable":
            assert result["tx"]["unavailable"] == "no saved read"

    prepared_plan = json.loads(manifest.read_bytes())
    for device in prepared_plan["devices"]:
        device["profile"] = str((manifest.parent / device["profile"]).resolve())
    downstream = json.loads(Path(prepared_plan["devices"][1]["profile"]).read_bytes())
    downstream["tx"][2]["pdo_index"] = 6657
    for key in ["pdo_index", "object_index", "subindex"]:
        downstream["tx"][0].pop(key)
    prepared_plan["devices"][1]["profile"] = save("split-profile", downstream).name
    plan = save("split-plan", prepared_plan)
    evidence = json.loads(sample.read_bytes())
    channel = evidence["devices"][1]["tx"]["sync_managers"][0]
    entries = channel["pdos"][0]["entries"]
    float_entry = entries.pop()
    channel["configured_bytes"] = 4
    evidence["devices"][1]["tx"]["sync_managers"].append({
        "index": 2, "configured_bytes": 4, "pdos": [{"index": 6657, "entries": [float_entry]}],
    })
    split_snapshot = save("split-pdo", evidence)
    mapping = json.loads(fmmu.read_bytes())
    mapping["devices"][1]["slots"][1]["value"][8:10] = [0, 19]
    slots = json.loads(sm.read_bytes())
    slots["devices"][1]["count"]["value"] = 3
    slots["devices"][1]["slots"][1]["value"][2] = 4
    slots["devices"][1]["slots"].append({"wkc": 1, "value": [0, 19, 4, 0, 0, 0, 1, 0]})
    split_slots = save("split-sm", slots)
    good = inspect(split_snapshot, "--frame", frame, mapping=save("split-fmmu", mapping), slots=split_slots, plan=plan)
    assert good["pdo"]["valid"]
    assert [d["input"] for d in good["devices"]] == [d["input"] for d in baseline["devices"]]
    result = good["pdo"]["devices"][1]
    assert [d["logical_start"] for d in result["placements"]] == [8, 12]
    assert [field["state"] for field in result["tx"]["fields"]] == ["manual", "matched", "matched"]
    mapping["devices"][1]["slots"][1]["value"][9] = 18
    mapping["devices"][1]["slots"][2]["value"][9] = 19
    swapped = reject(split_snapshot, "SM1 TxPDO bytes", mapping=save("swapped-fmmu", mapping), slots=split_slots, plan=plan)
    assert not swapped["tx"]["errors"] and not any(p["matches"] for p in swapped["placements"])

    evidence = json.loads(sample.read_bytes())
    del evidence["devices"][1]["tx"]["mapping_source"]
    out = destination / "malformed-export.json"
    assert "mapping_source" in inspect(save("missing-source", evidence), "--out", out, success=False)
    assert not out.exists()
    assert "--sync-managers" in cli_call(cli, "inspect-input-group", manifest, "--pdo", sample, success=False)


def verify_group_dc(cli, destination):
    manifest = ROOT / "samples/input-group-dc.json"
    period = 700_000

    def rehearse(*args, plan=manifest, success=True):
        return cli_call(cli, "rehearse-group-dc", plan, *args, success=success)

    def audit(report, logical_reads):
        assert len(report["wire_audit"]) == 2
        for esc in report["wire_audit"]:
            assert esc["model"] == "coe_dc"
            assert esc["dc_clock_distribution"] == len(report["cycles"])
            assert esc["logical_reads"] == logical_reads
            assert esc["final_al_status"] == 4 and esc["final_al_code"] == 0
            assert not esc["state_requests"] and not esc.get("dc_program_writes")
            for key in ("register_writes", "op_requests", "logical_writes", "physical_output_writes",
                        "sync_manager_writes", "fmmu_writes", "coe_downloads"):
                assert esc[key] == 0, key

    out = destination / "normal.json"
    normal = rehearse("--period-ns", period, "--out", out)
    assert json.loads(out.read_bytes()) == normal
    assert normal["schema"] == 1 and normal["source"] == "virtual_group_dc_rehearsal"
    assert normal["configured_sync0"] == [
        {"station": station, "activation": 3, "period_ns": period}
        for station in (4096, 4097)
    ]
    assert normal["plan"]["fmmu"]["valid"] and normal["plan"]["sync_managers"]["valid"]
    assert normal["plan"]["topology"]["valid"] and normal["plan"]["topology"]["unchanged"]
    assert normal["period_ns"] == period and normal["difference_limit_ns"] == 500
    assert normal["scenario"] == "normal"
    assert normal["clock_rejections"] == 0 and normal["valid_input_cycles"] == 4
    for i, cycle in enumerate(normal["cycles"], 1):
        assert cycle["cycle_index"] == i
        clock = cycle["clock"]
        ref = 1_000_000_000 + i * period
        assert clock["valid"] and not clock["issues"]
        assert clock["frmw_payload_ns"] == ref
        assert clock["expected_distribution_wkc"] == clock["actual_distribution_wkc"] == 2
        assert clock["reference"] == {"station": 4096, "wkc": 1, "time_ns": ref}
        assert clock["follower"] == {"station": 4097, "wkc": 1, "time_ns": ref + 250}
        assert clock["difference"] == {"wkc": 1, "raw": 0x800000FA, "received_minus_local_ns": -250}
        assert clock["raw_follower_minus_reference_ns"] == 250
        assert cycle["input"]["frame"]["valid"] and cycle["input"]["actual_wkc"] == 2
        assert [d["input"]["raw_hex"][:4] for d in cycle["input"]["devices"]] == ["0000", "0100"]
    audit(normal, 4)
    before = out.read_bytes()
    assert "exists" in rehearse("--out", out, success=False).lower()
    assert out.read_bytes() == before

    for scenario, issues in (
        ("follower-wkc", ["distribution_wkc", "follower_time_not_new"]),
        ("follower-stale", ["follower_time_not_new"]),
        ("follower-offset", ["difference_outside_limit"]),
        ("difference-read-wkc", ["difference_wkc"]),
        ("reference-regression", ["reference_time_not_new", "follower_time_not_new"]),
    ):
        report = rehearse("--period-ns", period, "--scenario", scenario,
                          "--out", destination / f"{scenario}.json")
        assert report["scenario"] == scenario
        assert report["clock_rejections"] == 1 and report["valid_input_cycles"] == 3
        assert [c["clock"]["valid"] for c in report["cycles"]] == [True, False, True, True]
        assert [c["input"] is not None for c in report["cycles"]] == [True, False, True, True]
        clock = report["cycles"][1]["clock"]
        assert clock["issues"] == issues
        assert clock["actual_distribution_wkc"] == (1 if scenario == "follower-wkc" else 2)
        if scenario in ("follower-wkc", "follower-stale"):
            assert clock["follower"] == report["cycles"][0]["clock"]["follower"]
            assert clock["difference"]["received_minus_local_ns"] == -250
        if scenario == "follower-offset":
            assert clock["difference"] == {"wkc": 1, "raw": 2500, "received_minus_local_ns": 2500}
            assert clock["raw_follower_minus_reference_ns"] == -2500
        if scenario == "difference-read-wkc":
            assert clock["difference"] == {"wkc": 0, "raw": None, "received_minus_local_ns": None}
        if scenario == "reference-regression":
            assert clock["frmw_payload_ns"] == report["cycles"][0]["clock"]["frmw_payload_ns"] - 1
        audit(report, 3)

    strict = rehearse("--difference-limit-ns", 249)
    assert strict["clock_rejections"] == 4 and strict["valid_input_cycles"] == 0
    assert all(c["clock"]["issues"] == ["difference_outside_limit"] and c["input"] is None
               for c in strict["cycles"])
    audit(strict, 0)
    assert rehearse("--difference-limit-ns", 250, "--cycles", 64)["valid_input_cycles"] == 64
    assert rehearse("--difference-limit-ns", 2500, "--scenario", "follower-offset")["valid_input_cycles"] == 4
    invalid = destination / "invalid.json"
    assert "positive" in rehearse("--period-ns", 0, "--out", invalid, success=False)
    assert "64 cycles" in rehearse("--cycles", 65, "--out", invalid, success=False)
    assert "two authored CoE/DC" in rehearse("--out", invalid, plan=ROOT / "samples/input-group.json", success=False)
    assert not invalid.exists()


def verify_three_station_group_dc(cli, destination):
    sample = ROOT / "samples"
    manifest = sample / "input-group-dc-three.json"
    period = 700_000

    def rehearse(*args, **kwargs):
        return cli_call(cli, "rehearse-group-dc", manifest, "--period-ns", period, *args, **kwargs)

    normal = rehearse("--out", destination / "normal.json")
    assert normal["clock_rejections"] == 0 and normal["valid_input_cycles"] == 4
    assert normal["configured_sync0"] == [
        {"station": station, "activation": 3, "period_ns": period}
        for station in (4096, 4097, 4098)
    ]
    assert [(d["offset"], d["tx_bytes"]) for d in normal["plan"]["devices"]] == [(0, 8), (None, 0), (8, 8)]
    assert normal["plan"]["topology"]["before_mapping"]["count_wkc"] == 3
    for cycle_index, cycle in enumerate(normal["cycles"], 1):
        clock = cycle["clock"]
        assert clock["valid"] and not clock["issues"]
        assert clock["actual_distribution_wkc"] == clock["expected_distribution_wkc"] == 3
        reference = 1_000_000_000 + cycle_index * period
        assert clock["reference"]["time_ns"] == reference
        assert clock["follower"] == {"station": 4097, "wkc": 1, "time_ns": reference + 250}
        assert clock["difference"]["received_minus_local_ns"] == -250
        [last] = clock["additional_followers"]
        assert last["follower"] == {"station": 4098, "wkc": 1, "time_ns": reference - 350}
        assert last["difference"] == {"wkc": 1, "raw": 350, "received_minus_local_ns": 350}
        assert last["raw_follower_minus_reference_ns"] == -350 and not last["issues"]
        entry = cycle["input"]
        assert entry["actual_wkc"] == entry["expected_wkc"] == 2
        assert entry["devices"][1]["input"] is None and entry["devices"][1]["al"]["clean_safeop"]

    for scenario, actual_wkc, main_issue, last_issue in (
        ("middle-follower-stale", 3, "follower_time_not_new", None),
        ("follower-stale", 3, "additional_follower_rejected", "follower_time_not_new"),
        ("follower-wkc", 2, "distribution_wkc", "follower_time_not_new"),
        ("follower-offset", 3, "additional_follower_rejected", "difference_outside_limit"),
        ("difference-read-wkc", 3, "additional_follower_rejected", "difference_wkc"),
        ("reference-regression", 3, "reference_time_not_new", "follower_time_not_new"),
    ):
        result = rehearse("--scenario", scenario, "--out", destination / f"{scenario}.json")
        assert [c["clock"]["valid"] for c in result["cycles"]] == [True, False, True, True]
        rejected = result["cycles"][1]
        clock = rejected["clock"]
        assert rejected["input"] is None and clock["actual_distribution_wkc"] == actual_wkc
        assert main_issue in clock["issues"]
        [last] = clock["additional_followers"]
        assert last["issues"] == ([last_issue] if last_issue else [])
        if scenario == "middle-follower-stale":
            first = result["cycles"][0]["clock"]
            assert clock["follower"]["time_ns"] == first["follower"]["time_ns"]
            assert last["follower"]["time_ns"] > first["additional_followers"][0]["follower"]["time_ns"]
        assert len(result["wire_audit"]) == 3
        for position in result["wire_audit"]:
            assert position["logical_reads"] == 3 and position["dc_clock_distribution"] == 4
            assert all(position[field] == 0 for field in ("register_writes", "logical_writes", "op_requests", "physical_output_writes"))
    all_rejected = rehearse("--difference-limit-ns", 300)
    assert all_rejected["clock_rejections"] == 4 and all_rejected["valid_input_cycles"] == 0
    assert all(c["clock"]["issues"] == ["additional_follower_rejected"] for c in all_rejected["cycles"])
    assert rehearse("--difference-limit-ns", 350)["valid_input_cycles"] == 4
    assert "three-station DC fixture" in cli_call(cli, "rehearse-group-dc", sample / "input-group-dc.json",
                                                "--scenario", "middle-follower-stale", success=False)

    fixture = destination / "dc-three-frames.json"
    saved = cli_call(cli, "generate-group-dc-replay", manifest, "--period-ns", period, "--cycles", 8,
                     "--scenario", "middle-follower-stale", "--out", fixture)
    assert saved["schema"] == 4 and saved["stations"] == [4096, 4097, 4098]
    assert len(saved["setup_topology"][0]["mapping_replies"]) == 24
    assert saved["cycles"][1]["elapsed_us"] is None and not saved["cycles"][1]["received_hex"]
    for cycle in saved["cycles"]:
        frames = cycle["clock_frames"]
        frmw = bytes.fromhex(frames["distribution_hex"])
        assert frmw[16] == 14 and struct.unpack_from("<H", frmw, 34)[0] == 3
        raw = bytes.fromhex(frames["readback_hex"])
        for offset, (station, register, width) in zip(
            (16, 36, 56, 72, 92), ((4096, 0x0910, 8), (4097, 0x0910, 8), (4097, 0x092C, 4),
                                  (4098, 0x0910, 8), (4098, 0x092C, 4)), strict=True,
        ):
            assert raw[offset] == 4
            address, register_word, control = struct.unpack_from("<HHH", raw, offset + 2)
            assert (address, register_word, control & 0x7FF) == (station, register, width)
    log = destination / "three-clock.csv"
    receipt = destination / "three-clock-replay.json"
    report = cli_call(cli, "replay-input-group", manifest, fixture, "--csv", log, "--rotate-rows", 2, "--out", receipt)
    assert report["counts"]["clock_rejections"] == 1 and report["counts"]["valid"] == 7
    _, logged = rows(log)
    assert [int(row["cycle_index"]) for row in logged] == [1, 3, 4, 5, 6, 7, 8]
    assert all("Position 0 Counter" in row and "Position 2 Counter" in row and
               not any(field.startswith("Position 1 ") for field in row) for row in logged)
    audited = cli_call(cli, "verify-group-replay", manifest, fixture, receipt, log)
    assert audited["verified_rows"] == 7 and audited["verified_mapping_generations"] == 1
    bundle = destination / "clock-bundle"
    cli_call(cli, "bundle-group-replay", manifest, fixture, receipt, log, "--out", bundle)
    moved = bundle.rename(destination / "moved-clock-bundle")
    assert cli_call(cli, "verify-group-bundle", moved)["audit"]["verified_rows"] == 7

    for name, offset, replacement, message in (
        ("changed-third-difference", 102, struct.pack("<I", 2500), "clock-rejected replay cycle 1 cannot carry"),
        ("changed-third-address", 94, struct.pack("<H", 4097), "does not match the expected clock readback"),
    ):
        altered = json.loads(fixture.read_bytes())
        frames = altered["cycles"][0]["clock_frames"]
        raw = bytearray.fromhex(frames["readback_hex"])
        raw[offset:offset + len(replacement)] = replacement
        frames["readback_hex"] = raw.hex()
        invalid = destination / f"{name}.json"
        invalid.write_text(json.dumps(altered), encoding="utf-8")
        blocked = destination / "blocked.csv"
        assert message in cli_call(cli, "replay-input-group", manifest, invalid, "--csv", blocked, success=False)
        assert not blocked.exists()


def verify_clock_and_topology(cli, destination):
    manifest = ROOT / "samples/input-group-dc-three.json"
    arguments = ("--scenario", "topology-change", "--period-ns", 700_000)
    direct = cli_call(cli, "rehearse-group-dc", manifest, *arguments, "--out", destination / "direct.json")
    assert direct["clock_rejections"] == 1 and direct["valid_input_cycles"] == 2
    assert len(direct["cycles"]) == 8
    for station in direct["wire_audit"]:
        assert station["logical_reads"] == 7 and station["dc_clock_distribution"] == 8
        assert station["register_writes"] == station["logical_writes"] == station["physical_output_writes"] == 0
        assert not station["state_requests"]

    fixture = destination / "clock-topology.json"
    saved = cli_call(cli, "generate-group-dc-replay", manifest, *arguments, "--out", fixture)
    assert saved["schema"] == 5 and "virtual_scenario" not in saved
    assert saved["virtual_dc"]["scenario"] == "topology-change"
    assert len(saved["setup_topology"][0]["mapping_replies"]) == 24
    assert not saved["cycles"][1]["received_hex"] and saved["cycles"][1]["elapsed_us"] is None
    base = destination / "qualified.csv"
    receipt = destination / "replay.json"
    report = cli_call(cli, "replay-input-group", manifest, fixture, "--csv", base, "--rotate-rows", 1, "--out", receipt)
    assert report["counts"] == {
        "cycles": 8, "matched_replies": 7, "valid": 2, "unmatched_cycles": 0, "clock_rejections": 1,
        "topology_rejections": 2, "topology_hold_rejections": 3, "wkc_mismatches": 0, "invalid_al": 0, "ignored_frames": 0,
    }
    for ordinal, (raw_cycle, cycle, rehearsal) in enumerate(zip(saved["cycles"], report["cycles"], direct["cycles"], strict=True), 1):
        assert cycle["clock"] == rehearsal["clock"]
        assert cycle["clock"]["actual_distribution_wkc"] == 3
        assert cycle["valid"] == (ordinal in (1, 3))
        if ordinal == 2:
            assert cycle["clock"]["issues"] == ["follower_time_not_new"] and rehearsal["input"] is None
            assert "cyclic_topology" not in cycle and "cyclic_topology" not in rehearsal
            continue
        topology = cycle["cyclic_topology"]
        assert cycle["clock"]["valid"] and topology == rehearsal["cyclic_topology"]
        assert topology["matches_setup"] == (ordinal not in (4, 5))
        assert topology["held_for_setup"] == (ordinal >= 6)
        assert cycle["actual_wkc"] == 2 and all(al["clean_safeop"] for al in cycle["al"])
        input_report = rehearsal["input"]
        assert input_report["frame"]["valid"] == cycle["valid"]
        assert all(d["input"] is None for d in input_report["devices"]) == (not cycle["valid"])
        [raw] = [bytes.fromhex(text) for text in raw_cycle["received_hex"]]
        assert len(raw) == 160
        for offset, cmd in ((16, 10), (44, 4), (62, 4), (80, 4), (98, 7), (112, 1), (128, 1), (144, 1)):
            assert raw[offset:offset + 2] == bytes([cmd, cycle["index"]])
        assert struct.unpack_from("<H", raw, 42)[0] == 2
        assert struct.unpack_from("<H", raw, 110)[0] == topology["count_wkc"] == 3
        assert [struct.unpack_from("<H", raw, i)[0] for i in (122, 138, 154)] == (
            [4096, 4098, 4097] if ordinal in (4, 5) else [4096, 4097, 4098]
        )
    parts, data = rows(base)
    assert len(parts) == 2 and [int(row["cycle_index"]) for row in data] == [1, 3]
    audit = cli_call(cli, "verify-group-replay", manifest, fixture, receipt, base)
    assert audit["complete"] and audit["verified_rows"] == 2
    assert audit["verified_topology_generations"] == audit["verified_mapping_generations"] == 1
    bundle = destination / "clock-topology-bundle"
    cli_call(cli, "bundle-group-replay", manifest, fixture, receipt, base, "--out", bundle)
    moved = bundle.rename(destination / "moved-clock-topology-bundle")
    assert cli_call(cli, "verify-group-bundle", moved)["audit"]["verified_rows"] == 2

    def rejected(name, mutate, message):
        changed = json.loads(fixture.read_bytes())
        mutate(changed)
        path = destination / f"{name}.json"
        path.write_text(json.dumps(changed), encoding="utf-8")
        blocked = destination / f"{name}.csv"
        assert message in cli_call(cli, "replay-input-group", manifest, path, "--csv", blocked, success=False)
        assert not blocked.exists()

    rejected("downgraded", lambda data: data.update(schema=4), "requires a monitored group replay fixture")
    rejected("setup-absent", lambda data: data.pop("setup_topology"), "requires setup topology probes")
    rejected("second-generation", lambda data: data["cycles"][-1].update(connection_generation=2), "missing setup topology")
    rejected("timestamp-on-stale", lambda data: data["cycles"][1].update(elapsed_us=700), "clock-rejected replay cycle 2")
    assert "three-station DC fixture" in cli_call(cli, "rehearse-group-dc", ROOT / "samples/input-group-dc.json", *arguments, success=False)
    assert "at least 6 cycles" in cli_call(cli, "rehearse-group-dc", manifest, *arguments, "--cycles", 5, success=False)


def verify_clock_reconnect(cli, destination):
    sample = ROOT / "samples"
    manifest = sample / "input-group-dc-three.json"
    args = ("--scenario", "topology-reconnect", "--period-ns", 700_000)
    direct = cli_call(cli, "rehearse-group-dc", manifest, *args, "--out", destination / "direct.json")
    assert direct["clock_rejections"] == 2 and direct["valid_input_cycles"] == 5
    assert direct["configured_sync0"] == direct["reconnected_setup"]["configured_sync0"]
    for setup, expected in ((direct, 8), (direct["reconnected_setup"], 4)):
        assert len(setup["wire_audit"]) == 3
        for esc in setup["wire_audit"]:
            assert esc["dc_clock_distribution"] == expected and esc["logical_reads"] == expected - 1
            assert esc["register_writes"] == esc["logical_writes"] == esc["physical_output_writes"] == 0
            assert not esc["state_requests"]

    fixture = destination / "reconnect-frames.json"
    saved = cli_call(cli, "generate-group-dc-replay", manifest, *args, "--out", fixture)
    assert saved["schema"] == 6 and len(saved["cycles"]) == 12
    clock_policy = saved["virtual_dc"]
    assert clock_policy["scenario"] == "topology-reconnect" and "sync0_hex" not in clock_policy
    for generation, setup, sync0 in zip((1, 2), saved["setup_topology"], clock_policy["sync0_by_generation"], strict=True):
        assert generation == setup["connection_generation"] == sync0["connection_generation"]
        assert setup["before_mapping"]["index"] == (0 if generation == 1 else 56)
        assert len(setup["mapping_replies"]) == 24
        raw_sync0 = bytes.fromhex(sync0["reply_hex"])
        assert raw_sync0[17] == setup["after_mapping"]["index"] + 1
        first_cycle = saved["cycles"][0 if generation == 1 else 8]
        assert first_cycle["index"] == raw_sync0[17] + 3
        assert bytes.fromhex(first_cycle["clock_frames"]["distribution_hex"])[17] == raw_sync0[17] + 1
        assert bytes.fromhex(first_cycle["clock_frames"]["readback_hex"])[17] == raw_sync0[17] + 2

    csv_base = destination / "capture.csv"
    receipt = destination / "replay.json"
    report = cli_call(cli, "replay-input-group", manifest, fixture, "--csv", csv_base, "--rotate-rows", 2, "--out", receipt)
    assert report["counts"] == {
        "cycles": 12, "matched_replies": 10, "valid": 5, "unmatched_cycles": 0,
        "clock_rejections": 2, "topology_rejections": 2, "topology_hold_rejections": 3,
        "wkc_mismatches": 0, "invalid_al": 0, "ignored_frames": 0,
    }
    setups = report["setup_topology"]
    assert [setup["connection_generation"] for setup in setups] == [1, 2]
    assert setups[0]["configured_sync0"] == setups[1]["configured_sync0"] == direct["configured_sync0"]
    for recorded, read, rehearsal in zip(saved["cycles"], report["cycles"], direct["cycles"], strict=True):
        assert recorded["connection_generation"] == read["connection_generation"] == rehearsal["connection_generation"]
        assert recorded["cycle_index"] == read["cycle_index"] == rehearsal["cycle_index"]
        assert read["clock"] == rehearsal["clock"]
        assert read.get("cyclic_topology") == rehearsal.get("cyclic_topology")
    before, first, recovered = report["cycles"][7:10]
    assert before["cyclic_topology"]["held_for_setup"]
    assert first["connection_generation"] == 2 and first["cycle_index"] == 1
    assert first["clock"]["actual_distribution_wkc"] == 2 and first["clock"]["issues"] == ["distribution_wkc"]
    assert first["elapsed_us"] is None and first["actual_wkc"] is None
    assert "cyclic_topology" not in first and not saved["cycles"][8]["received_hex"]
    assert recovered["valid"] and recovered["clock"]["valid"]
    assert recovered["clock"]["reference"]["time_ns"] < before["clock"]["reference"]["time_ns"]
    assert recovered["cyclic_topology"]["matches_setup"] and not recovered["cyclic_topology"]["held_for_setup"]
    assert report["valid_receive_spacing"]["count"] == 3 and report["valid_receive_spacing"]["longest_gap_us"] == 1400

    parts, logged = rows(csv_base)
    assert len(parts) == 3
    assert [tuple(int(row[key]) for key in ("connection_generation", "cycle_index", "elapsed_us")) for row in logged] == [
        (1, 1, 0), (1, 3, 1400), (2, 2, 6300), (2, 3, 7000), (2, 4, 7700),
    ]
    on_change = destination / "on-change.csv"
    on_change_receipt = destination / "on-change.json"
    cli_call(cli, "replay-input-group", manifest, fixture, "--csv", on_change, "--on-change", "--out", on_change_receipt)
    with on_change.open(encoding="utf-8", newline="") as stream:
        changed_rows = list(csv.DictReader(stream, strict=True))
    assert [(row["connection_generation"], row["cycle_index"]) for row in changed_rows] == [("1", "1"), ("2", "2")]
    assert all(changed_rows[0][key] == changed_rows[1][key] for key in changed_rows[0] if key.startswith("Position "))
    assert cli_call(cli, "verify-group-replay", manifest, fixture, on_change_receipt, on_change)["verified_rows"] == 2
    checked = cli_call(cli, "verify-group-replay", manifest, fixture, receipt, csv_base)
    assert checked["complete"] and checked["verified_rows"] == 5
    assert checked["verified_clock_setup_generations"] == checked["verified_mapping_generations"] == checked["verified_topology_generations"] == 2
    bundle = destination / "reconnect-bundle"
    cli_call(cli, "bundle-group-replay", manifest, fixture, receipt, csv_base, "--out", bundle)
    verified = cli_call(cli, "verify-group-bundle", bundle.rename(destination / "moved-reconnect-bundle"))["audit"]
    assert verified["verified_rows"] == 5 and verified["verified_clock_setup_generations"] == 2

    def rejected(name, mutate, message):
        changed = json.loads(fixture.read_bytes())
        mutate(changed)
        path = destination / f"{name}.json"
        path.write_text(json.dumps(changed), encoding="utf-8")
        blocked = destination / f"{name}.csv"
        error = cli_call(cli, "replay-input-group", manifest, path, "--csv", blocked, success=False)
        assert message in error, (name, error)
        assert not blocked.exists()

    rejected("old-schema", lambda d: d.update(schema=5), "requires a schema 6")
    rejected("setup-missing", lambda d: d["setup_topology"].pop(), "missing setup topology for generation 2")
    rejected("sync0-missing", lambda d: d["virtual_dc"].pop("sync0_by_generation"), "requires the SYNC0 evidence")
    rejected("sync0-wrong-generation", lambda d: d["virtual_dc"]["sync0_by_generation"][1].update(connection_generation=1),
             "setup evidence does not match generation 2")
    rejected("old-sync0", lambda d: d["virtual_dc"]["sync0_by_generation"][1].update(
        reply_hex=d["virtual_dc"]["sync0_by_generation"][0]["reply_hex"]), "SYNC0 setup for generation 2")
    rejected("old-clock-reply", lambda d: d["cycles"][8].update(clock_frames=d["cycles"][0]["clock_frames"]), "DC replay cycle 9")
    rejected("restarted-elapsed", lambda d: d["cycles"][9].update(elapsed_us=700), "differs from the authored SYNC0 schedule")
    rejected("stale-input", lambda d: d["cycles"][8].update(elapsed_us=5600), "clock-rejected replay cycle 9")
    assert "at least 10 cycles" in cli_call(cli, "rehearse-group-dc", manifest, *args, "--cycles", 9, success=False)
    assert "three-station DC fixture" in cli_call(cli, "rehearse-group-dc", sample / "input-group-dc.json", *args, success=False)


def verify_group_dc_replay(cli, destination):
    manifest = ROOT / "samples/input-group-dc.json"
    fixture = destination / "stale.json"
    authored = cli_call(cli, "generate-group-dc-replay", manifest, "--period-ns", 700_000,
                        "--cycles", 8, "--scenario", "follower-stale", "--out", fixture)
    assert json.loads(fixture.read_bytes()) == authored and authored["schema"] == 4
    policy = authored["virtual_dc"]
    assert (policy["scenario"], policy["period_ns"], policy["difference_limit_ns"]) == ("follower-stale", 700_000, 500)
    assert bytes.fromhex(policy["sync0_hex"])[12:14] == b"\x88\xa4"
    rejected = authored["cycles"][1]
    assert rejected["elapsed_us"] is None and not rejected["received_hex"]
    assert all(set(c["clock_frames"]) == {"distribution_hex", "readback_hex"} for c in authored["cycles"])
    before = fixture.read_bytes()
    assert "exists" in cli_call(cli, "generate-group-dc-replay", manifest, "--out", fixture, success=False)
    assert fixture.read_bytes() == before

    def run(base, receipt, source=fixture, *args, success=True):
        return cli_call(cli, "replay-input-group", manifest, source, "--csv", base, "--out", receipt,
                        *args, success=success)

    def audit(base, receipt, source=fixture, *, success=True):
        return cli_call(cli, "verify-group-replay", manifest, source, receipt, base, success=success)

    base = destination / "every.csv"
    receipt = destination / "every.json"
    report = run(base, receipt, fixture, "--rotate-rows", 2)
    assert report["virtual_dc"] == policy
    assert len(report["setup_topology"]) == 1
    assert report["setup_topology"][0]["valid"]
    assert report["setup_topology"][0]["mapping"]["fmmu"]["valid"]
    assert report["setup_topology"][0]["mapping"]["sync_managers"]["valid"]
    assert len(authored["setup_topology"][0]["mapping_replies"]) == 16
    assert report["fixture_sha256"] == hashlib.sha256(before).hexdigest()
    assert report["counts"]["valid"] == report["counts"]["matched_replies"] == 7
    assert report["counts"]["unmatched_cycles"] == 0 and report["counts"]["clock_rejections"] == 1
    assert report["counts"]["wkc_mismatches"] == 0 and report["counts"]["invalid_al"] == 0
    bad = report["cycles"][1]
    assert bad["clock"]["actual_distribution_wkc"] == 2 and bad["clock"]["issues"] == ["follower_time_not_new"]
    assert not bad["valid"] and bad["actual_wkc"] is None
    assert report["valid_receive_spacing"] == report["receive_spacing"] == {
        "count": 6, "p50_us": 700, "p95_us": 1400, "p99_us": 1400, "longest_gap_us": 1400,
    }
    parts, actual = rows(base)
    expected = [1, 3, 4, 5, 6, 7, 8]
    assert len(parts) == 4
    for sample, (row, cycle) in enumerate(zip(actual, expected, strict=True), 1):
        assert row["capture_start_utc"] == authored["capture_start_utc"]
        keys = ["sample_index", "connection_generation", "cycle_index", "elapsed_us"]
        assert [int(row[key]) for key in keys] == [sample, 1, cycle, (cycle - 1) * 700]
        step = (sample - 1) // 4
        for position in (0, 1):
            value = step + position
            assert row[f"Position {position} Counter"] == str(value)
            assert row[f"Position {position} Sensor active"] == ("true" if value % 2 else "false")
            assert float(row[f"Position {position} Scaled counter"]) == value / 4
    checked = audit(base, receipt)
    assert checked["complete"] and checked["expected_rows"] == checked["verified_rows"] == 7

    change_base = destination / "change.csv"
    change_receipt = destination / "change.json"
    change = run(change_base, change_receipt, fixture, "--on-change")
    assert change["valid_receive_spacing"] == report["valid_receive_spacing"]
    with change_base.open(encoding="utf-8", newline="") as stream:
        changed = list(csv.DictReader(stream, strict=True))
    assert [int(row["cycle_index"]) for row in changed] == [1, 6]
    assert audit(change_base, change_receipt)["verified_rows"] == 2

    bundle = destination / "saved-group"
    cli_call(cli, "bundle-group-replay", manifest, fixture, receipt, base, "--out", bundle)
    relocated = bundle.with_name("relocated-group")
    bundle.rename(relocated)
    bundled = cli_call(cli, "verify-group-bundle", relocated)
    assert bundled["audit"]["verified_rows"] == 7
    assert bundled["audit"]["verified_topology_generations"] == 1
    assert bundled["audit"]["verified_mapping_generations"] == 1

    empty = destination / "no-accepted-cycles.json"
    cli_call(cli, "generate-group-dc-replay", manifest, "--difference-limit-ns", 249,
             "--cycles", 1, "--out", empty)
    empty_base = destination / "empty.csv"
    empty_receipt = destination / "empty.json"
    empty_report = run(empty_base, empty_receipt, empty)
    assert empty_report["counts"]["clock_rejections"] == 1 and empty_report["counts"]["unmatched_cycles"] == 0
    assert audit(empty_base, empty_receipt, empty)["verified_rows"] == 0

    def edit_source(name, mutate):
        data = json.loads(before)
        mutate(data)
        path = destination / f"{name}.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def no_pdo_reply(data):
        data["cycles"][2]["received_hex"] = []
        data["cycles"][2]["elapsed_us"] = None

    missing = edit_source("unanswered-input", no_pdo_reply)
    missing_base = destination / "missing.csv"
    missing_receipt = destination / "missing-receipt.json"
    result = run(missing_base, missing_receipt, missing)
    assert result["counts"]["unmatched_cycles"] == 1 and result["counts"]["clock_rejections"] == 1
    assert result["cycles"][2]["clock"]["valid"] and result["cycles"][2]["actual_wkc"] is None
    assert audit(missing_base, missing_receipt, missing)["verified_rows"] == 6

    def wrong_index(data):
        cycle = data["cycles"][2]
        raw = bytearray.fromhex(cycle["clock_frames"]["readback_hex"])
        raw[17] ^= 1
        cycle["clock_frames"]["readback_hex"] = raw.hex()

    for name, mutate, message in [
        ("wrong-readback", wrong_index, "does not match the expected clock readback"),
        ("clock-omitted", lambda d: d["cycles"][1].pop("clock_frames"), "missing DC frames"),
        ("clock-downgrade", lambda d: d.update(schema=1), "unsupported group replay schema"),
        ("clock-setup-mismatch", lambda d: d["virtual_dc"].update(period_ns=500_000), "authored schedule"),
        ("clock-rejection-with-pdo", lambda d: d["cycles"][1].update(received_hex=d["cycles"][2]["received_hex"]),
         "clock-rejected replay cycle 2"),
        ("shifted-clock", lambda d: d["cycles"][2].update(elapsed_us=1401), "authored SYNC0 schedule"),
    ]:
        invalid = edit_source(name, mutate)
        unavailable = destination / "unavailable.csv"
        absent_receipt = destination / "unavailable.json"
        assert message in run(unavailable, absent_receipt, invalid, success=False)
        assert not unavailable.exists() and not absent_receipt.exists()

    amended = destination / "amended-receipt.json"
    report["cycles"][1]["clock"]["valid"] = True
    amended.write_text(json.dumps(report), encoding="utf-8")
    assert "differs from the rebuilt" in audit(base, amended, success=False)
    assert "fixture SHA-256 differs" in audit(base, receipt, missing, success=False)

    def legacy_dc(data):
        data["schema"] = 2
        del data["setup_topology"]

    legacy = edit_source("legacy-dc", legacy_dc)
    legacy_base = destination / "legacy.csv"
    legacy_receipt = destination / "legacy-receipt.json"
    result = run(legacy_base, legacy_receipt, legacy)
    assert result["counts"]["valid"] == 7 and result["counts"]["clock_rejections"] == 1
    assert "setup_topology" not in result
    legacy_audit = audit(legacy_base, legacy_receipt, legacy)
    assert "verified_topology_generations" not in legacy_audit
    assert "verified_mapping_generations" not in legacy_audit


def verify_input_group_replay(cli, destination):
    manifest = ROOT / "samples/input-group.json"
    fixture = ROOT / "samples/input-group-replay.json"
    options = ("--fmmu", ROOT / "samples/input-group-fmmu.json",
               "--sync-managers", ROOT / "samples/input-group-sync-managers.json",
               "--pdo", ROOT / "samples/input-group-pdo.json")
    authored = json.loads(fixture.read_bytes())
    metadata = ["capture_start_utc", "elapsed_us", "sample_index", "connection_generation", "cycle_index"]
    selected_fields = ["Counter", "Sensor active", "Scaled counter"]
    columns = metadata + [
        f"Position {position} {field}" for position in range(2) for field in selected_fields
    ]

    def replay(base, *args, source=fixture, plan=manifest, success=True):
        return cli_call(cli, "replay-input-group", plan, source, "--csv", base, *args, success=success)

    def audit(base, receipt, *args, source=fixture, plan=manifest, success=True):
        return cli_call(cli, "verify-group-replay", plan, source, receipt, base, *args, success=success)

    def csv_records(base):
        parts = sorted(base.parent.glob(f"{base.stem}.*.csv"))
        if not parts:
            parts = [base]
        observations = []
        for part in parts:
            with part.open(encoding="utf-8", newline="") as stream:
                reader = csv.DictReader(stream, strict=True)
                assert reader.fieldnames == columns
                for row in reader:
                    assert set(row) == set(columns) and all(v is not None for v in row.values())
                    observations.append(row)
        return parts, observations

    def check_rows(observations, expected):
        assert len(observations) == len(expected)
        for index, (row, (generation, cycle, elapsed, downstream)) in enumerate(zip(observations, expected, strict=True), 1):
            assert row["capture_start_utc"] == authored["capture_start_utc"]
            assert [int(row[key]) for key in metadata[1:]] == [elapsed, index, generation, cycle]
            assert [row[key] for key in columns[5:]] == ["42", "true", "1", str(downstream), "false", "2"]

    for mode, extra, expected, expected_parts in [
        ("every", [], [(7, 1, 100, 13330), (7, 2, 1100, 13330), (7, 5, 4100, 13330),
                       (7, 6, 5100, 13331), (8, 1, 10000, 13331), (8, 3, 12000, 13331)], 3),
        ("change", ["--on-change"], [(7, 1, 100, 13330), (7, 6, 5100, 13331), (8, 1, 10000, 13331)], 2),
    ]:
        base = destination / f"{mode}.csv"
        out = destination / f"{mode}.json"
        result = replay(base, *options, *extra, "--rotate-rows", 2, "--out", out)
        assert result == json.loads(out.read_bytes())
        assert result["mode"] == mode and result["source"] == "offline_group_replay" and result["error"] is None
        assert result["fixture_sha256"] == hashlib.sha256(fixture.read_bytes()).hexdigest()
        assert result["plan"]["fmmu"]["valid"] and result["plan"]["sync_managers"]["valid"] and result["plan"]["pdo"]["valid"]
        assert result["counts"] == {
            "cycles": 9, "matched_replies": 8, "valid": 6, "unmatched_cycles": 1,
            "wkc_mismatches": 1, "invalid_al": 2, "ignored_frames": 2,
        }
        assert result["capture"] == {
            "selected": len(expected), "written": len(expected), "overruns": 0,
            "utc_start": authored["capture_start_utc"], "parts": expected_parts,
        }
        assert result["receive_spacing"] == {
            "count": 6, "p50_us": 1000, "p95_us": 2000, "p99_us": 2000, "longest_gap_us": 2000,
        }
        assert result["valid_receive_spacing"] == {
            "count": 4, "p50_us": 1000, "p95_us": 3000, "p99_us": 3000, "longest_gap_us": 3000,
        }
        assert [c["valid"] for c in result["cycles"]] == [True, True, False, False, True, True, True, False, True]
        assert [c["index"] for c in result["cycles"][:3]] == [254, 255, 0]
        assert result["cycles"][2]["actual_wkc"] == 1 and result["cycles"][2]["al"][1]["status"]["code"] == 0x1e
        assert result["cycles"][3]["actual_wkc"] is None and result["cycles"][3]["elapsed_us"] is None
        assert result["cycles"][7]["actual_wkc"] == 2 and result["cycles"][7]["al"][1]["actual_wkc"] == 0
        parts, observations = csv_records(base)
        assert len(parts) == expected_parts and not base.exists()
        check_rows(observations, expected)
        audit_path = destination / f"{mode}-audit.json"
        checked = audit(base, out, *options, "--out", audit_path)
        assert checked == json.loads(audit_path.read_bytes())
        assert checked["complete"] and checked["mode"] == mode
        assert checked["verified_rows"] == checked["expected_rows"] == len(expected)
        assert checked["receipt_sha256"] == hashlib.sha256(out.read_bytes()).hexdigest()
        assert checked["fixture_sha256"] == result["fixture_sha256"]
        for index, (entry, part) in enumerate(zip(checked["parts"], parts, strict=True)):
            data = part.read_bytes()
            assert entry["sha256"] == hashlib.sha256(data).hexdigest()
            assert entry["bytes"] == len(data) and entry["rows"] == min(2, len(expected) - 2 * index)
        assert "exists" in audit(base, out, *options, "--out", audit_path, success=False)
        assert checked == json.loads(audit_path.read_bytes())

    plan = json.loads(manifest.read_bytes())
    for device in plan["devices"]:
        device["profile"] = str((manifest.parent / device["profile"]).resolve())
    second = json.loads(Path(plan["devices"][1]["profile"]).read_bytes())
    second["tx"][0]["log"] = False
    modified = destination / "unselected.json"
    modified.write_text(json.dumps(second), encoding="utf-8")
    plan["devices"][1]["profile"] = modified.name
    custom = destination / "plan.json"
    custom.write_text(json.dumps(plan), encoding="utf-8")
    masked_base = destination / "masked.csv"
    masked = replay(masked_base, "--on-change", plan=custom)
    assert masked["capture"]["written"] == 2 and masked["counts"]["valid"] == 6
    with masked_base.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, strict=True)
        assert reader.fieldnames == [name for name in columns if name != "Position 1 Counter"]
        assert [(r["connection_generation"], r["cycle_index"]) for r in reader] == [("7", "1"), ("8", "1")]

    collision = destination / "collision.0002.csv"
    collision.write_bytes(b"must preserve this part\n")
    incomplete_base = destination / "collision.csv"
    incomplete_receipt = destination / "collision.json"
    partial = replay(incomplete_base, "--rotate-rows", 2, "--out", incomplete_receipt, success=False)
    assert collision.read_bytes() == b"must preserve this part\n"
    assert partial["capture"]["written"] == 2 and partial["capture"]["selected"] == 6
    assert "CSV replay incomplete" in partial["error"]
    reopened = audit(incomplete_base, incomplete_receipt)
    assert not reopened["complete"] and reopened["capture_error"] == partial["error"]
    assert (reopened["verified_rows"], reopened["expected_rows"], len(reopened["parts"])) == (2, 6, 1)
    assert collision.read_bytes() == b"must preserve this part\n"
    assert "already exists" in replay(destination / "no-csv.csv", "--out", destination / "every.json", success=False)
    assert not (destination / "no-csv.csv").exists()

    for name, issue in [
        ("repeated-cycle", "increasing generation/cycle order"), ("regression", "receive time regresses"),
        ("missing-time", "needs elapsed_us"), ("unmatched-time", "needs elapsed_us"),
        ("trailing-candidate", "final candidate"), ("local-clock", "must use UTC"),
    ]:
        altered = json.loads(fixture.read_bytes())
        if name == "repeated-cycle":
            altered["cycles"][-1]["cycle_index"] = 2
        elif name == "regression":
            altered["cycles"][-1]["elapsed_us"] = 50
        elif name == "missing-time":
            altered["cycles"][-1]["elapsed_us"] = None
        elif name == "unmatched-time":
            altered["cycles"][3]["elapsed_us"] = 3100
        elif name == "trailing-candidate":
            altered["cycles"][-1]["received_hex"].extend(authored["cycles"][0]["received_hex"])
        else:
            altered["capture_start_utc"] = "2026-11-20T07:00:00-05:00"
        path = destination / f"{name}.json"
        path.write_text(json.dumps(altered), encoding="utf-8")
        csv_path = destination / f"{name}.csv"
        assert issue in replay(csv_path, source=path, success=False)
        assert not csv_path.exists()

    wrong = json.loads((ROOT / "samples/input-group-pdo.json").read_bytes())
    wrong["devices"][1]["identity"]["revision"] = 2
    wrong_path = destination / "wrong-pdo.json"
    wrong_path.write_text(json.dumps(wrong), encoding="utf-8")
    blocked = destination / "no-mapping.csv"
    assert "saved mapping evidence failed" in replay(blocked, *options[:-1], wrong_path, success=False)
    assert not blocked.exists()

    only_unmatched = destination / "only-unmatched.json"
    only_unmatched.write_text(json.dumps({**authored, "cycles": [authored["cycles"][3]]}), encoding="utf-8")
    empty_base = destination / "header-only.csv"
    empty_receipt = destination / "header-only-receipt.json"
    no_data = replay(empty_base, "--out", empty_receipt, source=only_unmatched)
    assert no_data["counts"]["unmatched_cycles"] == 1 and no_data["capture"]["written"] == 0
    assert no_data["valid_receive_spacing"]["count"] == 0 and no_data["valid_receive_spacing"]["p99_us"] is None
    assert csv_records(empty_base) == ([empty_base], [])
    zero_audit = audit(empty_base, empty_receipt, source=only_unmatched)
    assert zero_audit["complete"] and zero_audit["verified_rows"] == zero_audit["expected_rows"] == 0

    receipt = destination / "every.json"
    base = destination / "every.csv"
    parts, _ = csv_records(base)
    for name, column, replacement, reason in [
        ("wrong-field", 5, "43", "differs from recorded input"),
        ("wrong-time", 1, "101", "elapsed_us differs from replay"),
        ("wrong-cycle", 4, "3", "cycle_index differs from replay"),
        ("wrong-generation", 3, "8", "connection_generation differs from replay"),
    ]:
        altered_base = destination / f"{name}.csv"
        for index, part in enumerate(parts, 1):
            copied = destination / f"{name}.{index:04}.csv"
            if index != 1:
                shutil.copyfile(part, copied)
                continue
            with part.open("r", encoding="utf-8", newline="") as stream:
                rows = list(csv.reader(stream, strict=True))
            rows[1][column] = replacement
            with copied.open("w", encoding="utf-8", newline="") as stream:
                csv.writer(stream, lineterminator="\n").writerows(rows)
        out = destination / f"{name}-audit.json"
        assert reason in audit(altered_base, receipt, *options, "--out", out, success=False)
        assert not out.exists()

    for index, part in enumerate(parts, 1):
        torn = destination / f"torn.{index:04}.csv"
        torn.write_bytes(part.read_bytes()[:-1] if index == len(parts) else part.read_bytes())
    assert "missing its final newline" in audit(destination / "torn.csv", receipt, *options, success=False)
    assert "rebuilt cycles" in audit(base, receipt, success=False)  # Earlier receipt retained all three evidence files.
    changed_fixture = destination / "changed-source.json"
    changed_fixture.write_bytes(fixture.read_bytes() + b"\n")
    assert "fixture SHA-256 differs" in audit(base, receipt, *options, source=changed_fixture, success=False)
    tampered_receipt = destination / "tampered-receipt.json"
    edited = json.loads(receipt.read_bytes())
    edited["cycles"][2]["valid"] = True
    tampered_receipt.write_text(json.dumps(edited), encoding="utf-8")
    assert "rebuilt cycles" in audit(base, tampered_receipt, *options, success=False)
    changed_plan = destination / "modified-plan"
    changed_plan.mkdir()
    copied_manifest = changed_plan / manifest.name
    shutil.copyfile(manifest, copied_manifest)
    for position, device in enumerate(json.loads(manifest.read_bytes())["devices"]):
        data = (manifest.parent / device["profile"]).read_bytes()
        (changed_plan / device["profile"]).write_bytes(data + (b"\n" if position == 1 else b""))
    assert "profile/mapping evidence" in audit(base, receipt, *options, plan=copied_manifest, success=False)
    shutil.copyfile(parts[0], destination / "missing.0001.csv")
    assert "missing.0002.csv" in audit(destination / "missing.csv", receipt, *options, success=False)

    nan_fixture = destination / "nan-bits.json"
    nanos = json.loads(fixture.read_bytes())
    nanos["cycles"] = nanos["cycles"][:2]
    for index, cycle in enumerate(nanos["cycles"], 1):
        packet = bytearray.fromhex(cycle["received_hex"][-1])
        packet[30:34] = struct.pack("<I", 0x7fc00000 + index)
        cycle["received_hex"][-1] = packet.hex()
    nan_fixture.write_text(json.dumps(nanos), encoding="utf-8")
    nan_base = destination / "nan.csv"
    nan_receipt = destination / "nan-receipt.json"
    assert replay(nan_base, "--on-change", "--out", nan_receipt, source=nan_fixture)["capture"]["written"] == 2
    _, nan_rows = csv_records(nan_base)
    assert [row["Position 0 Scaled counter"] for row in nan_rows] == ["NaN", "NaN"]
    assert audit(nan_base, nan_receipt, source=nan_fixture)["complete"]


def verify_dc_rehearsal(cli, destination):
    profile = ROOT / "samples/virtual-dc.json"
    period = 700_000
    delay = 2_000_123
    reference_at_setup = 1_000_000_000
    start_register = (reference_at_setup + delay) // period * period
    expected_options = ["--period-ns", period, "--start-delay-ns", delay, "--cycles", 5]

    for scenario, activation, disable, count, reads, error in [
        ("normal", 3, 0, 5, 5, None),
        ("activation-mismatch", 1, 0, 0, 0, "activation readback differs"),
        ("reference-wkc", 3, 0, 2, 1, "reference clock exchange 2"),
        ("input-wkc", 3, 0, 2, 2, "input exchange 2 lacked WKC 1"),
        ("disable-rejected", 3, 3, 5, 5, "deactivation was not confirmed"),
    ]:
        target = destination / f"{scenario}.json"
        report = cli_call(cli, "rehearse-dc", profile, *expected_options, "--scenario", scenario,
                          "--out", target, success=error is None)
        assert report == json.loads(target.read_bytes())
        assert report["schema"] == 1 and report["scope"] == "virtual_sync0_rehearsal"
        assert report["scenario"] == scenario and report["requested_cycles"] == 5
        assert report["timing_source"] == "authored_reference_clock_unpaced_host"
        assert report["host_requested_cycle_us"] == 1000
        assert report["stopped_al"] == [1, 0]
        assert report["device"]["identity"] == json.loads(profile.read_bytes())["expected_identity"]
        assert report["device"]["al_status"] == 4
        trial = report["trial"]
        assert trial["period_ns"] == period and trial["start_delay_ns"] == delay
        assert trial["sync1_delay_ns"] is None and trial["timing_origin"] == {"kind": "manual"}
        assert trial["start_register_ns"] == {"value": start_register, "unavailable": None}
        assert trial["reference_before_cycles_ns"]["value"] == reference_at_setup
        assert trial["activation_after_disable"] == {"value": disable, "unavailable": None}
        dc = report["synchronization"]["dc"]
        assert dc["requested_sync"] == "virtual SYNC0"
        assert dc["activation"]["value"] == activation and dc["assign_activate"]["value"] == activation << 8
        assert dc["sync0_cycle_ns"]["value"] == period and dc["sync1_cycle_ns"]["value"] == 0
        assert dc["cyclic_clock_distribution"] == (count > 0)
        wire = report["wire"]
        assert wire["dc_enable_requests"] == 1 and wire["dc_clock_distribution"] == count
        expected_writes = [(0x0981, 0, 1), (0x0990, start_register, 8), (0x09A0, period, 4),
                           (0x09A4, 0, 4), (0x0981, 3, 1), (0x0981, 0, 1)]
        assert wire["dc_program_writes"] == [
            {"register": offset, "payload": list(value.to_bytes(width, "little")), "wkc": 1}
            for offset, value, width in expected_writes
        ]
        assert wire["logical_reads"] == reads and wire["state_requests"] == [1, 2, 4, 1]
        assert wire["logical_writes"] == wire["physical_output_writes"] == wire["op_requests"] == 0
        assert len(report["cycles"]) == count
        valid_reads = reads - int(scenario == "input-wkc")
        for index, exchange in enumerate(report["cycles"][:valid_reads], 1):
            assert exchange["index"] == index and exchange["reference_ns"] == reference_at_setup + index * period
            assert exchange["reference_wkc"] == exchange["expected_reference_wkc"] == exchange["input_wkc"] == 1
            assert exchange["al"]["raw"] == 4
            assert len(exchange["tx_hex"]) == 16
        if scenario == "reference-wkc":
            failed = report["cycles"][1]
            assert failed["reference_wkc"] == 0 and failed["reference_ns"] is None
            assert failed["input_wkc"] is None and failed["tx_hex"] is None
        if scenario == "input-wkc":
            failed = report["cycles"][1]
            assert failed["reference_ns"] == reference_at_setup + 2 * period
            assert failed["reference_wkc"] == 1 and failed["input_wkc"] == 0
            assert failed["al"]["raw"] == 4 and failed["tx_hex"] is None
        if error is None:
            assert report["error"] is None
            assert [x["tx_hex"][:4] for x in report["cycles"]] == ["0000"] * 4 + ["0100"]
        else:
            assert error in report["error"]
        assert report["setup_failure_al"] == ([4, 0] if scenario == "activation-mismatch" else None)

    stale = cli_call(cli, "rehearse-dc", profile, "--period-ns", period, "--start-delay-ns", 0, success=False)
    assert "future aligned time" in stale["error"] and stale["trial"]["activation_after_disable"]["value"] == 0
    assert stale["stopped_al"] == [1, 0] and not stale["cycles"]
    assert stale["wire"]["dc_enable_requests"] == 0
    existing = destination / "normal.json"
    contents = existing.read_bytes()
    assert "exists" in cli_call(cli, "rehearse-dc", profile, *expected_options, "--out", existing, success=False)
    assert contents == existing.read_bytes()
    refused = destination / "refused.json"
    wrong = cli_call(cli, "rehearse-dc", ROOT / "samples/virtual.json", *expected_options, "--out", refused, success=False)
    assert "authored CoE/DC identity" in wrong and not refused.exists()
    for key, value, reason in [
        ("--period-ns", 0, "period must be positive"), ("--cycles", 65, "1–64 cycles"),
    ]:
        options = expected_options.copy()
        options[options.index(key) + 1] = value
        assert reason in cli_call(cli, "rehearse-dc", profile, *options, "--out", refused, success=False)
        assert not refused.exists()


def verify_dc_esi_modes(cli, destination):
    sample = ROOT / "samples"
    raw_profile = sample / "virtual-dc.json"
    delay = 2_000_123
    base = ["--start-delay-ns", delay, "--cycles", 2]
    xml = sample / "sync-rehearsal.esi.xml"

    def step(report, period, sync1):
        activation = 3 if sync1 is None else 7
        assert report["trial"]["period_ns"] == period and report["trial"]["sync1_delay_ns"] == sync1
        assert report["stopped_al"] == [1, 0] and report["trial"]["activation_after_disable"]["value"] == 0
        dc = report["synchronization"]["dc"]
        assert dc["assign_activate"]["value"] == (activation << 8)
        assert dc["activation"]["value"] == activation
        assert dc["sync0_cycle_ns"]["value"] == period and dc["sync1_cycle_ns"]["value"] == (sync1 or 0)
        assert [cycle["reference_ns"] for cycle in report["cycles"]] == [1_000_000_000 + i * period for i in (1, 2)]
        trace = report["wire"]["dc_program_writes"]
        assert [(x["register"], len(x["payload"]), x["wkc"]) for x in trace] == (
            [(0x0981, 1, 1), (0x0990, 8, 1), (0x09A0, 4, 1),
             (0x09A4, 4, 1), (0x0981, 1, 1), (0x0981, 1, 1)]
        )
        assert int.from_bytes(bytes(trace[3]["payload"]), "little") == (sync1 or 0)
        assert trace[4]["payload"] == [activation] and trace[5]["payload"] == [0]
        assert report["wire"]["logical_writes"] == report["wire"]["physical_output_writes"] == report["wire"]["op_requests"] == 0

    for explicit in (0, 200_000):
        report = cli_call(cli, "rehearse-dc", raw_profile, "--period-ns", 700_000,
                          "--sync1-delay-ns", explicit, *base, "--out", destination / f"manual-{explicit}.json")
        assert report["scope"] == "virtual_sync01_rehearsal"
        assert report["trial"]["timing_origin"] == {"kind": "manual"}
        step(report, 700_000, explicit)

    for index, name, period, sync1 in [(0, "Sync01-Factors", 500_000, 500_000), (1, "Fixed-Sync0", 700_000, None)]:
        profile = destination / f"mode-{index}.json"
        cli_call(cli, "esi-import", xml, "--device", 0, "--dc-mode", index,
                 "--sync-unit-cycle-ns", 1_000_000, "--out", profile)
        source = profile.read_bytes()
        report = cli_call(cli, "rehearse-dc", profile, "--from-esi", *base, "--out", destination / f"mode-{index}-run.json")
        assert report["trial"]["timing_origin"] == {
            "kind": "staged_esi", "file_name": xml.name, "sha256": hashlib.sha256(xml.read_bytes()).hexdigest(),
            "mode_index": index, "mode_name": name, "sync_unit_cycle_ns": 1_000_000,
        }
        assert report["host_requested_cycle_us"] == 1000
        assert profile.read_bytes() == source
        step(report, period, sync1)

    failure = cli_call(cli, "rehearse-dc", raw_profile, "--period-ns", 700_000,
                       "--sync1-delay-ns", 200_000, *base, "--scenario", "cycle-write-wkc", success=False)
    assert "program SYNC1 delay register" in failure["error"]
    assert failure["stopped_al"] == [1, 0] and failure["setup_failure_al"] == [2, 0]
    assert failure["trial"]["activation_after_disable"]["value"] == 0 and not failure["cycles"]
    assert failure["wire"]["dc_enable_requests"] == failure["wire"]["dc_clock_distribution"] == 0
    trace = failure["wire"]["dc_program_writes"]
    assert [(entry["register"], entry["wkc"]) for entry in trace] == (
        [(0x0981, 1), (0x0990, 1), (0x09A0, 1), (0x09A4, 0), (0x0981, 1)]
    )

    refused = destination / "refused.json"
    missing = cli_call(cli, "rehearse-dc", raw_profile, "--from-esi", *base, "--out", refused, success=False)
    assert "requires a staged ESI DC mode" in missing and not refused.exists()
    assert "cannot be used" in cli_call(cli, "rehearse-dc", raw_profile, "--period-ns", 700_000,
                                      "--from-esi", *base, success=False)
    for filename, index, marker in [
        ("sync-rehearsal.esi.xml", 0, "SYNC0 cycle unresolved"),
        ("sync-modes.esi.xml", 2, "resolved zero SYNC shifts"),
        ("sync-modes.esi.xml", 0, "AssignActivate 0x0300 or 0x0700"),
    ]:
        profile = destination / f"unsupported-{filename}-{index}.json"
        cli_call(cli, "esi-import", sample / filename, "--device", 0, "--dc-mode", index, "--out", profile)
        error = cli_call(cli, "rehearse-dc", profile, "--from-esi", *base, "--out", refused, success=False)
        assert marker in error and not refused.exists()


def verify_output_plan(cli, destination):
    sample = ROOT / "samples"
    model_profiles = {
        "coe": "virtual.json", "sii": "virtual-sii.json", "coe_dc": "virtual-dc.json",
        "coe_normal": "virtual-normal.json", "coe_segmented": "virtual-segmented.json",
    }
    for model, filename in model_profiles.items():
        profile = json.loads((sample / filename).read_bytes())
        profile["nic"] = r"\Device\NPF_{11111111-1111-1111-1111-111111111111}"
        profile["staged_rx_hex"] = "3412"
        profile_path = destination / f"{model}-profile.json"
        profile_path.write_text(json.dumps(profile), encoding="utf-8")
        plan_path = destination / f"{model}-plan.json"
        options = ["--safe-hex", "00 00", "--watchdog-us", 10000, "--max-op-us", 1000,
                   "--stop-observation", "Observe independent output indicator at zero", "--serial", 1]
        review = cli_call(cli, "plan-output", profile_path, *options, "--out", plan_path)
        assert review == json.loads(plan_path.read_bytes())
        proposal = review["proposal"]
        digest = review["plan_sha256"]
        assert digest == hashlib.sha256(json.dumps(proposal, separators=(",", ":")).encode()).hexdigest()
        assert proposal["scope"] == "offline_one_shot_output_plan" and proposal["rx_bytes"] == 2
        assert proposal["nic"] == profile["nic"] and proposal["expected_identity"] == profile["expected_identity"]
        assert proposal["staged_rx_hex"] == "3412"
        assert proposal["stop"]["safe_rx_hex"] == "0000" and proposal["stop"]["expected_serial"] == 1
        assert proposal["fields"][0]["safe"] == "0" and proposal["fields"][0]["staged"] == "4660"
        assert cli_call(cli, "verify-output-plan", profile_path, plan_path, "--sha256", digest) == review
        report = cli_call(cli, "rehearse-output", profile_path, "--plan", plan_path, "--plan-sha256", digest)
        assert report["plan_sha256"] == digest and report["safe_rx_hex"] == "0000"
        assert report["profile_sha256"] == proposal["profile_sha256"]
        assert report["device"]["identity"] == proposal["expected_identity"]
        assert report["device"]["serial"] == 1 and report["wire"]["model"] == model
        assert report["pdo_verification"]["readback"]["rx"]["mapping_source"] == ("sii" if model == "sii" else "coe")
        assert report["pdo_verification"]["rx"]["entries"][0]["sync_manager"] == (0 if model == "sii" else 2)
        assert report["sequence"]["safe_stop"]["actual_wkc"] == 1
        assert report["sequence"]["init"]["raw"] == 1 and report["error"] is None
        assert report["wire"]["logical_writes"] == 3 and report["wire"]["dc_enable_requests"] == 0
        assert report["modeled_outputs"]["applied_in_order"] == [[0, 0], [52, 18], [0, 0]]
        assert report["modeled_outputs"]["last_applied"] == [0, 0]
        assert not report["modeled_outputs"]["outputs_active"]
        if model == "sii":
            assert report["wire"]["coe_uploads"] == 0 and report["wire"]["sii_reads"] > 0
        if model in ("coe_normal", "coe_segmented"):
            assert report["wire"]["coe_" + model.removeprefix("coe_") + "_uploads"] > 0
        if model != "coe":
            continue

        before = plan_path.read_bytes()
        assert "exists" in cli_call(cli, "plan-output", profile_path, *options, "--out", plan_path, success=False)
        assert plan_path.read_bytes() == before
        for scenario, op_writes, applied, steps, code in [
            ("write-reply-lost", 1, [[0, 0], [52, 18]], ("output",), "OP output write outcome unknown"),
            ("safe-stop-reply-lost", 2, [[0, 0], [52, 18], [0, 0]], ("safe_stop",), "safe-image write outcome unknown"),
        ]:
            fault = cli_call(cli, "rehearse-output", profile_path, "--plan", plan_path,
                             "--plan-sha256", digest, "--scenario", scenario, success=False)
            assert code in fault["error"] and fault["wire"]["logical_writes"] == op_writes + 1
            assert fault["modeled_outputs"]["applied_in_order"] == applied
            for step in steps:
                assert fault["sequence"][step]["actual_wkc"] is None
            assert ("safe_stop" in fault["sequence"]) == (op_writes == 2)
            assert fault["sequence"]["init"]["raw"] == 1 and not fault["modeled_outputs"]["outputs_active"]

        changed = destination / "changed-profile.json"
        for key, value in [("nic", "another NIC"), ("staged_rx_hex", "AABB"), ("name", "edited mapping")]:
            changed.write_text(json.dumps(dict(profile, **{key: value})), encoding="utf-8")
            assert "differs" in cli_call(cli, "verify-output-plan", changed, plan_path, "--sha256", digest, success=False)
        tampered = destination / "tampered-plan.json"
        edited = json.loads(before)
        edited["proposal"]["stop"]["safe_rx_hex"] = "FF00"
        tampered.write_text(json.dumps(edited), encoding="utf-8")
        assert "differs" in cli_call(cli, "verify-output-plan", profile_path, tampered, "--sha256", digest, success=False)
        assert "differs" in cli_call(cli, "verify-output-plan", profile_path, plan_path, "--sha256", "0" * 64, success=False)
        refused = destination / "refused.json"
        cli_call(cli, "rehearse-output", changed, "--plan", plan_path, "--plan-sha256", digest,
                 "--out", refused, success=False)
        assert not refused.exists()
        cli_call(cli, "rehearse-output", profile_path, "--plan", plan_path, success=False)
        mismatched = destination / "serial-plan.json"
        other_serial = cli_call(cli, "plan-output", profile_path, *options[:-1], 2, "--out", mismatched)
        rejected = cli_call(cli, "rehearse-output", profile_path, "--plan", mismatched, "--plan-sha256",
                            other_serial["plan_sha256"], success=False)
        assert "serial differs" in rejected["error"] and rejected["wire"]["logical_writes"] == 0
        assert rejected["wire"]["op_requests"] == 0 and rejected["sequence"]["init"]["raw"] == 1


def verify_output_timing(cli, destination):
    profile = json.loads((ROOT / "samples/virtual.json").read_bytes())
    profile.update(nic=r"\Device\NPF_{11111111-1111-1111-1111-111111111111}", staged_rx_hex="3412")
    profile_path = destination / "profile.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")

    def run(name, max_op, watchdog=100, scenario="normal", success=False):
        plan = destination / f"{name}-plan.json"
        review = cli_call(cli, "plan-output", profile_path, "--safe-hex", "0000", "--max-op-us",
                          max_op, "--watchdog-us", watchdog, "--stop-observation", "Observe safe state",
                          "--out", plan)
        out = destination / f"{name}.json"
        attempted = cli_call(cli, "rehearse-output", profile_path, "--scenario", scenario, "--plan",
                             plan, "--plan-sha256", review["plan_sha256"], "--out", out, success=success)
        assert attempted == json.loads(out.read_bytes())
        timing = attempted["timing"]
        assert timing["clock"] == "modeled_frame_dispatch" and timing["frame_step_us"] == 10
        assert timing["max_op_us"] == max_op and timing["watchdog_us"] == watchdog
        assert attempted["sequence"]["init"]["raw"] == 1
        assert not attempted["modeled_outputs"]["outputs_active"]
        return attempted

    normal = run("normal", 70, success=True)
    assert normal["timing"]["init_request_elapsed_us"] == 60
    assert normal["timing"]["init_confirmed_elapsed_us"] == 70
    assert normal["timing"]["init_within_limit"] is True
    assert normal["sequence"]["op_watchdog"] == {"wkc": 1, "raw": 1}
    assert normal["sequence"]["before_safe_restore"]["watchdog"] == {"wkc": 1, "raw": 1}
    assert normal["modeled_outputs"]["applied_in_order"] == [[0, 0], [52, 18], [0, 0]]

    for limit, blocked, init_sent, init_seen, applied in [
        (30, "staged_write", 30, 40, [[0, 0]]),
        (50, "safe_restore", 40, 50, [[0, 0], [52, 18]]),
        (65, None, 60, 70, [[0, 0], [52, 18], [0, 0]]),
    ]:
        report = run(f"limit-{limit}", limit)
        timing = report["timing"]
        assert timing["blocked_write"] == blocked
        assert timing["blocked_dispatch_elapsed_us"] == (limit if blocked else None)
        assert timing["init_request_elapsed_us"] == init_sent and timing["init_confirmed_elapsed_us"] == init_seen
        assert timing["init_within_limit"] == (init_seen <= limit)
        assert (f"blocks {blocked}" if blocked else "INIT confirmed at 70 us") in report["error"]
        assert report["modeled_outputs"]["applied_in_order"] == applied
        assert report["wire"]["logical_writes"] == len(applied)
        assert report["modeled_outputs"]["watchdog_expired_at_us"] is None

    for scenario, al_raw, code in [("watchdog-expires", 0x14, 0x1b), ("watchdog-expires-in-op", 8, 0)]:
        lost = run(scenario, 1000, scenario=scenario)
        observed = lost["sequence"]["before_safe_restore"]
        assert observed["al"]["raw"] == al_raw and observed["al"]["code"] == code
        assert observed["watchdog"] == {"wkc": 1, "raw": 0}
        assert "safe_stop" not in lost["sequence"]
        assert lost["wire"]["logical_writes"] == 2 and lost["wire"]["op_requests"] == 1
        assert lost["modeled_outputs"]["watchdog_expired_at_us"] == 150
        assert lost["timing"]["init_within_limit"] is True

    gap = run("expires-during-staged-dispatch", 1000, watchdog=30)
    assert gap["sequence"]["op_watchdog"] == {"wkc": 1, "raw": 1}
    assert gap["sequence"]["output"]["actual_wkc"] == 0
    assert gap["modeled_outputs"]["applied_in_order"] == [[0, 0]]
    assert gap["modeled_outputs"]["watchdog_expired_at_us"] == 50
    assert gap["wire"]["logical_writes"] == 2 and gap["timing"]["init_within_limit"] is True

    largest_limit = (1 << 64) - 1
    long_pause = run("long-pause", largest_limit, watchdog=largest_limit, scenario="watchdog-expires")
    assert long_pause["timing"]["blocked_write"] == "safe_restore"
    assert long_pause["timing"]["init_within_limit"] is False
    assert long_pause["modeled_outputs"]["watchdog_expired_at_us"] == largest_limit + 50
    assert long_pause["wire"]["logical_writes"] == 2

    unreadable = run("watchdog-unavailable", 1000, scenario="watchdog-unavailable")
    assert unreadable["sequence"]["op"]["raw"] == 8
    assert unreadable["sequence"]["op_watchdog"] == {"wkc": 0, "raw": None}
    assert unreadable["sequence"]["output"] is None and unreadable["wire"]["logical_writes"] == 1
    assert "did not return WKC 1" in unreadable["error"]
    error = cli_call(cli, "rehearse-output", profile_path, "--scenario", "watchdog-expires", success=False)
    assert "requires a verified output plan" in error


def verify_output_rehearsal(cli, destination):
    sample = ROOT / "samples" / "virtual.json"
    source_bytes = sample.read_bytes()
    staged = destination / "staged.json"
    preview = cli_call(cli, "stage-rx", sample, "--set", "0=4660", "--out", staged)
    assert preview["after_hex"] == "3412"
    output = staged.read_bytes()
    supported = {
        "normal": (True, 2, 1, 1, 1, 1, 0, None),
        "preload-wkc": (False, 1, 0, 0, 0, None, 0, "SAFEOP preload WKC 0"),
        "op-reject": (False, 1, 1, 1, 1, None, 0, "OP confirmation failed"),
        "write-reply-lost": (False, 2, 1, 1, 1, None, 1, "output write outcome unknown"),
        "init-reject": (False, 2, 1, 1, 1, 1, 0, "INIT confirmation failed"),
    }
    for name, (ok, attempted, preloaded, op_requests, preload_wkc, output_wkc, dropped, failure) in supported.items():
        receipt = destination / f"{name}.json"
        report = cli_call(cli, "rehearse-output", staged, "--scenario", name, "--out", receipt, success=ok)
        assert report == json.loads(receipt.read_bytes())
        assert report["schema"] == 1 and report["scope"] == "virtual_rxpdo_rehearsal"
        assert report["scenario"] == name and report["staged_rx_hex"] == "3412"
        assert len(report["profile_sha256"]) == 64
        assert report["device"]["identity"] == json.loads(source_bytes)["expected_identity"]
        assert report["pdo_verification"]["rx"]["fields"][0]["state"] == "matched"
        sequence = report["sequence"]
        assert sequence["safeop"]["raw"] == 4 and sequence["safeop"]["code"] == 0
        assert sequence["preload"] == {"expected_wkc": 1, "actual_wkc": preload_wkc}
        if op_requests:
            assert sequence["op_request"] == {"expected_wkc": 1, "actual_wkc": 1}
            assert sequence["op"]["raw"] == (0x14 if name == "op-reject" else 8)
            assert sequence["op"]["code"] == (0x19 if name == "op-reject" else 0)
        else:
            assert sequence["op_request"] is None and sequence["op"] is None
        if attempted == 2:
            assert sequence["output"] == {"expected_wkc": 1, "actual_wkc": output_wkc}
        else:
            assert sequence["output"] is None
        assert sequence["init_request"] == {"expected_wkc": 1, "actual_wkc": 1}
        assert sequence["init"]["raw"] == (8 if name == "init-reject" else 1)
        wire = report["wire"]
        assert wire["logical_writes"] == attempted and wire["op_requests"] == op_requests
        assert wire["physical_output_writes"] == 0 and wire["coe_downloads"] == 0
        assert wire["dropped_replies"] == dropped
        assert wire["state_requests"] == ([1, 2, 4, 8, 1] if op_requests else [1, 2, 4, 1])
        model = report["modeled_outputs"]
        assert model["preload_writes"] == preloaded and model["op_writes"] == int(attempted == 2)
        assert model["last_applied"] == ([52, 18] if attempted == 2 else None)
        assert model["outputs_active"] == (name == "init-reject")
        if failure is None:
            assert report["error"] is None
        else:
            assert failure in report["error"]
    existing = destination / "normal.json"
    saved = existing.read_bytes()
    assert "exists" in cli_call(cli, "rehearse-output", staged, "--out", existing, success=False)
    assert saved == existing.read_bytes()
    blank = destination / "blank.json"
    profile = json.loads(output)
    profile["staged_rx_hex"] = ""
    blank.write_text(json.dumps(profile), encoding="utf-8")
    missing = cli_call(cli, "rehearse-output", blank, "--out", destination / "absent.json", success=False)
    assert "stage an explicit two-byte" in missing and not (destination / "absent.json").exists()
    manual = destination / "manual.json"
    profile["staged_rx_hex"] = "3412"
    for reference in ("pdo_index", "object_index", "subindex"):
        profile["rx"][0].pop(reference)
    manual.write_text(json.dumps(profile), encoding="utf-8")
    refused = cli_call(cli, "rehearse-output", manual, success=False)
    assert "fully matched RxPDO" in refused["error"]
    assert refused["wire"]["logical_writes"] == refused["wire"]["op_requests"] == 0
    assert refused["sequence"]["init"]["raw"] == 1
    assert source_bytes == sample.read_bytes() and output == staged.read_bytes()


def verify_virtual_group_pdo_readback(cli, destination):
    sample = ROOT / "samples"
    manifest = sample / "input-group.json"

    def readback(plan=manifest, *args, **kwargs):
        return cli_call(cli, "inspect-virtual-group-mapping", plan, "--read-pdos", *args, **kwargs)

    def save(name, data):
        path = destination / f"{name}.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    clean = readback(manifest, "--out", destination / "readback.json")
    basic = cli_call(cli, "inspect-virtual-group-mapping", manifest)
    assert clean["valid"] and clean["source"] == "virtual_group_pdo_reads"
    assert "pdo_exchanges" not in basic and "pdo_snapshot" not in basic
    for view in ("fmmu_snapshot", "sync_manager_snapshot", "mapping_replies"):
        assert clean[view] == basic[view]
    assert clean["inspection"]["pdo"]["valid"]
    snapshot = clean["pdo_snapshot"]
    assert snapshot["schema"] == 1
    for position, captured in enumerate(snapshot["devices"]):
        assert captured["station_address"] == 0x1000 + position
        assert captured["identity"] == {"vendor": 16715776, "product": position + 1, "revision": 1}
        assert captured["tx_unavailable"] is None
        assert captured["tx"]["mapping_source"] == ("coe", "sii")[position]
        [channel] = captured["tx"]["sync_managers"]
        assert channel["index"] == (3, 1)[position] and channel["configured_bytes"] == 8
        assert channel["pdos"] == [{"index": 0x1a00, "entries": [0x60000110, 0x60000201, 15, 0x60000320]}]

    next_index = clean["inspection"]["topology"]["after_mapping"]["index"] + 1
    coe_objects = []
    sii_words = {4096: [], 4097: []}
    for sequence, frame in enumerate(clean["pdo_exchanges"], next_index):
        request = bytes.fromhex(frame["request_hex"])
        reply = bytes.fromhex(frame["reply_hex"])
        assert request[12:14] == reply[12:14] == b"\x88\xa4"
        assert request[16:24] == reply[16:24] and reply[17] == sequence % 256
        command, _, station, register, length = struct.unpack_from("<BBHHH", request, 16)
        end = 26 + (length & 0x7ff)
        assert struct.unpack_from("<H", reply, end)[0] == 1
        if command == 5 and register == 0x0502:
            assert request[26:28] == b"\x00\x01" and end == 32
            assert request[30:32] == b"\x00\x00"
            sii_words[station].append(struct.unpack_from("<H", request, 28)[0])
        elif command == 5:
            assert station == 4096 and register == 0x1000 and request[34] == 0x40
            coe_objects.append((*struct.unpack_from("<HB", request, 35), request[31] >> 4))
        else:
            assert command == 4
    assert coe_objects == [(0x1c13, 0, 1), (0x1c13, 1, 2)] + [(0x1a00, sub, sub + 3) for sub in range(5)]
    assert sii_words[4096] == [8, 10, 12] and sii_words[4097][:4] == [8, 10, 12, 0x40]
    assert clean["wire_audit"][0]["coe_uploads"] == 7
    assert clean["wire_audit"][1]["coe_uploads"] == 0
    for audit in clean["wire_audit"]:
        assert all(audit[key] == 0 for key in ("coe_downloads", "sync_manager_writes", "fmmu_writes",
                                               "logical_reads", "logical_writes", "physical_output_writes"))
        assert not audit["state_requests"]

    fmmu = save("fmmu", clean["fmmu_snapshot"])
    sm = save("sync-managers", clean["sync_manager_snapshot"])
    pdo = save("pdo", snapshot)
    evidence = ("--fmmu", fmmu, "--sync-managers", sm, "--pdo", pdo)
    frame = ("--frame", sample / "input-group-frame.json")
    checked = cli_call(cli, "inspect-input-group", manifest, *evidence, *frame)
    assert checked["frame"]["valid"] and checked["pdo"]["valid"] and all(d["input"] for d in checked["devices"])
    fixture = destination / "frames.json"
    cli_call(cli, "generate-group-replay", manifest, "--out", fixture)
    csv_base = destination / "valid.csv"
    receipt = destination / "replay.json"
    report = cli_call(cli, "replay-input-group", manifest, fixture, "--csv", csv_base, "--out", receipt, *evidence)
    assert report["counts"]["valid"] == 12
    assert cli_call(cli, "verify-group-replay", manifest, fixture, receipt, csv_base, *evidence)["verified_rows"] == 12

    for position, scenario in enumerate(("coe-pdo-order", "sii-pdo-order")):
        fault = readback(manifest, "--scenario", scenario, "--out", destination / f"{scenario}-report.json")
        assert not fault["valid"] and not fault["inspection"]["pdo"]["valid"]
        assert all(fault["inspection"][key]["valid"] for key in ("topology", "fmmu", "sync_managers"))
        dev = fault["inspection"]["pdo"]["devices"][position]
        assert dev["tx"]["image_bytes"] == 8 and "no device entry" in " ".join(dev["tx"]["errors"])
        assert [entry["tx"]["errors"] == [] for entry in fault["inspection"]["pdo"]["devices"]] == [position != 0, position != 1]
        bad_pdo = save(scenario, fault["pdo_snapshot"])
        rejected = cli_call(cli, "inspect-input-group", manifest, *evidence[:-1], bad_pdo, *frame)
        assert rejected["frame"]["valid"] and not rejected["pdo"]["valid"]
        assert all(d["input"] is None for d in rejected["devices"])
        blocked = destination / f"{scenario}.csv"
        assert "saved mapping evidence failed" in cli_call(
            cli, "replay-input-group", manifest, fixture, "--csv", blocked, *evidence[:-1], bad_pdo, success=False
        )
        assert not blocked.exists()
        assert "require --read-pdos" in cli_call(cli, "inspect-virtual-group-mapping", manifest, "--scenario", scenario, success=False)

    invalid_topology = readback(manifest, "--scenario", "swap-during-readback")
    assert not invalid_topology["valid"] and "pdo_exchanges" not in invalid_topology
    assert all(audit["coe_uploads"] == audit["sii_reads"] == 0 for audit in invalid_topology["wire_audit"])
    three = readback(sample / "input-group-three.json")
    assert three["valid"] and three["inspection"]["expected_wkc"] == 2
    assert [d["tx"]["image_bytes"] for d in three["inspection"]["pdo"]["devices"]] == [8, 0, 8]
    assert three["pdo_snapshot"]["devices"][1]["tx"] == {"mapping_source": "sii", "sync_managers": []}


def verify_group_pdo_against_recorded_setup(cli, destination):
    sample = ROOT / "samples"
    manifest = sample / "input-group.json"
    fixture = destination / "frames.json"
    receipt = destination / "replay.json"
    base = destination / "capture.csv"
    readback = destination / "pdo-readback.json"

    def save(name, value):
        path = destination / f"{name}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    exported = cli_call(cli, "inspect-virtual-group-mapping", manifest, "--read-pdos", "--out", readback)
    capture = cli_call(cli, "generate-group-replay", manifest, "--out", fixture)
    report = cli_call(cli, "replay-input-group", manifest, fixture, "--pdo", readback, "--csv", base,
                      "--rotate-rows", 4, "--out", receipt)
    assert report["counts"]["valid"] == 12 and report["verified_pdo_generations"] == 2
    proof = report["plan"]["pdo"]
    assert proof["valid"] and proof["source_sha256"] == hashlib.sha256(readback.read_bytes()).hexdigest()
    assert "fmmu" not in report["plan"] and "sync_managers" not in report["plan"]
    assert all(g["mapping"]["fmmu"]["valid"] for g in report["setup_topology"])
    assert [d["readback"]["mapping_source"] for d in proof["devices"]] == ["coe", "sii"]
    audited = cli_call(cli, "verify-group-replay", manifest, fixture, receipt, base, "--pdo", readback)
    assert audited["verified_rows"] == 12 and audited["verified_pdo_generations"] == 2
    assert "differs from the rebuilt" in cli_call(cli, "verify-group-replay", manifest, fixture, receipt, base, success=False)
    altered_receipt = json.loads(receipt.read_bytes())
    altered_receipt["verified_pdo_generations"] = 1
    assert "differs from the rebuilt" in cli_call(
        cli, "verify-group-replay", manifest, fixture, save("changed-count", altered_receipt), base,
        "--pdo", readback, success=False,
    )
    bundle = destination / "bundle"
    cli_call(cli, "bundle-group-replay", manifest, fixture, receipt, base, "--pdo", readback, "--out", bundle)
    moved = bundle.rename(destination / "moved-bundle")
    assert (moved / "pdo.json").read_bytes() == readback.read_bytes()
    assert not (moved / "fmmu.json").exists() and not (moved / "sync-managers.json").exists()
    reopened = cli_call(cli, "verify-group-bundle", moved)["audit"]
    assert reopened["verified_pdo_generations"] == 2 and reopened["verified_rows"] == 12
    altered_file = moved / "pdo.json"
    original = altered_file.read_bytes()
    changed = original.replace(b'"scenario": "clean"', b'"scenario": "other"', 1)
    assert changed != original and len(changed) == len(original)
    altered_file.write_bytes(changed)
    assert "differs from the rebuilt" in cli_call(cli, "verify-group-bundle", moved, success=False)
    altered_file.write_bytes(original)

    def blocked(name, evidence, source=fixture, message=""):
        path = destination / f"{name}.csv"
        result = cli_call(cli, "replay-input-group", manifest, source, "--pdo", evidence, "--csv", path, success=False)
        assert message in result, result
        assert not path.exists()

    fault = destination / "faulty-readback.json"
    cli_call(cli, "inspect-virtual-group-mapping", manifest, "--read-pdos", "--scenario", "coe-pdo-order", "--out", fault)
    blocked("fault", fault, message="TxPDO verification failed for generation 1")
    unrecorded = dict(capture, schema=3)
    unrecorded["setup_topology"] = [
        {key: value for key, value in generation.items() if key != "mapping_replies"}
        for generation in capture["setup_topology"]
    ]
    blocked("no-maps", readback, save("schema-three", unrecorded), "requires recorded FMMU and SyncManager replies")
    blocked("legacy", readback, sample / "input-group-replay.json", "requires recorded FMMU and SyncManager replies")
    blocked("wrong-source", save("wrong-source", dict(exported, source="unrecognized")),
            message="expected a schema 1 virtual group PDO readback report")
    blocked("no-snapshot", save("no-snapshot", dict(exported, pdo_snapshot=None)), message="has no PDO snapshot")

    # Shift the input to SM2 in generation 2 without changing its physical coverage.
    changed = json.loads(fixture.read_bytes())
    replies = changed["setup_topology"][1]["mapping_replies"]
    slots = {}
    for index, encoded in enumerate(replies):
        raw = bytearray.fromhex(encoded)
        address = struct.unpack_from("<HH", raw, 18)
        if address in ((0x1000, 0x0810), (0x1000, 0x0818)):
            slots[address[1]] = index, raw
    assert set(slots) == {0x0810, 0x0818}
    lower_index, lower = slots[0x0810]
    upper_index, upper = slots[0x0818]
    lower[26:34], upper[26:34] = upper[26:34], lower[26:34]
    replies[lower_index], replies[upper_index] = lower.hex(), upper.hex()
    shifted = save("second-generation-slot", changed)
    geometry = cli_call(cli, "replay-input-group", manifest, shifted, "--csv", destination / "geometry.csv")
    assert geometry["counts"]["valid"] == 12
    assert all(g["mapping"]["sync_managers"]["valid"] for g in geometry["setup_topology"])
    blocked("shifted-slot", readback, shifted, "TxPDO verification failed for generation 2")

    monitored = destination / "monitored.json"
    cli_call(cli, "generate-group-replay", manifest, "--scenario", "topology-change", "--out", monitored)
    snapshot = save("standalone-pdo", exported["pdo_snapshot"])
    monitored_report = cli_call(cli, "replay-input-group", manifest, monitored, "--pdo", snapshot,
                                "--csv", destination / "monitored.csv")
    assert monitored_report["verified_pdo_generations"] == 2 and monitored_report["counts"]["valid"] == 6

    dc_manifest = sample / "input-group-dc-three.json"
    dc_fixture = destination / "reconnect.json"
    cli_call(cli, "generate-group-dc-replay", dc_manifest, "--scenario", "topology-reconnect", "--out", dc_fixture)
    coe_layout = exported["pdo_snapshot"]["devices"][0]["tx"]
    identity = {"vendor": 16715776, "product": 3, "revision": 1}
    dc_pdo = save("reconnect-pdo", {"schema": 1, "devices": [
        {"station_address": 4096 + index, "identity": identity,
         "tx": coe_layout if index != 1 else {"mapping_source": "coe", "sync_managers": []}}
        for index in range(3)
    ]})
    dc_report = cli_call(cli, "replay-input-group", dc_manifest, dc_fixture, "--pdo", dc_pdo,
                         "--csv", destination / "reconnect.csv")
    assert dc_report["verified_pdo_generations"] == 2 and dc_report["counts"]["valid"] == 5


def verify_virtual_group_mapping(cli, destination):
    sample = ROOT / "samples"
    manifest = sample / "input-group.json"
    def observe(snapshot, count, stations, aliases, wkcs):
        assert snapshot["count_wkc"] == count
        assert [row["expected_station_address"] for row in snapshot["positions"]] == [0x1000, 0x1001]
        for position, (row, station, alias, wkc) in enumerate(zip(snapshot["positions"], stations, aliases, wkcs, strict=True)):
            assert row["position"] == position and row["wkc"] == wkc
            assert (row["station_address"], row["configured_alias"]) == (station, alias)
        raw = bytes.fromhex(snapshot["reply_hex"])
        assert raw[12:14] == b"\x88\xa4" and len(raw) == 62
        assert raw[16:18] == bytes([7, snapshot["index"]])
        assert struct.unpack_from("<H", raw, 28)[0] == count
        for position, (offset, wkc) in enumerate(zip((30, 46), wkcs, strict=True)):
            assert raw[offset:offset + 2] == bytes([1, snapshot["index"]])
            address, register = struct.unpack_from("<HH", raw, offset + 2)
            assert address == (count - position) % 65536 and register == 0x0010
            got_station, got_alias, got_wkc = struct.unpack_from("<HHH", raw, offset + 10)
            assert got_wkc == wkc
            if wkc == 1:
                assert got_station == stations[position] and got_alias == aliases[position]

    clean = (2, (0x1000, 0x1001), (0x42, 0x43), (1, 1))
    swapped = (2, (0x1001, 0x1000), (0x43, 0x42), (1, 1))
    extra = (3, *clean[1:])
    duplicate = (2, (0x1000, 0x1000), (0x42, 0x43), (1, 1))
    position_wkc = (2, (0x1000, None), (0x42, None), (1, 2))
    for scenario, before, after, expected_valid, geometry_valid in [
        ("swapped-stations", swapped, swapped, (False, False), True),
        ("swap-during-readback", clean, swapped, (True, False), True),
        ("extra-station", extra, extra, (False, False), True),
        ("duplicate-station", duplicate, duplicate, (False, False), False),
        ("position-wkc", position_wkc, position_wkc, (False, False), True),
    ]:
        result = cli_call(cli, "inspect-virtual-group-mapping", manifest, "--scenario", scenario,
                          "--out", destination / f"{scenario}.json")
        assert not result["valid"] and result["scenario"] == scenario
        inspection = result["inspection"]
        assert inspection["fmmu"]["valid"] == inspection["sync_managers"]["valid"] == geometry_valid
        topology = inspection["topology"]
        assert topology["expected_count"] == 2 and not topology["valid"]
        assert topology["unchanged"] == (before == after)
        for key, expected, valid in zip(("before_mapping", "after_mapping"), (before, after), expected_valid, strict=True):
            assert topology[key]["valid"] == valid
            observe(topology[key], *expected)
        assert topology["before_mapping"]["index"] == 0
        assert topology["after_mapping"]["index"] > topology["before_mapping"]["index"]
        assert len(result["wire_audit"]) == after[0]
        for record in result["wire_audit"]:
            assert not record["state_requests"]
            assert all(record[key] == 0 for key in (
                "logical_reads", "register_writes", "logical_writes", "physical_output_writes", "op_requests",
            ))

    for scenario, fmmu_issue, sm_issue, count, wkc, datagrams in [
        ("clean", None, None, 2, 1, 14),
        ("logical-shift", "outside planned input", "FMMU logical layout", 2, 1, 14),
        ("physical-shift", None, "physical coverage differs", 2, 1, 14),
        ("station-missing", "count WKC 0", "count WKC 0", 0, 0, 10),
        ("excess-channels", "exceeds 16", "exceeds 16", 255, 1, 10),
    ]:
        receipt = destination / f"{scenario}.json"
        args = ["--scenario", scenario] if scenario != "clean" else []
        result = cli_call(cli, "inspect-virtual-group-mapping", manifest, *args, "--out", receipt)
        assert result == json.loads(receipt.read_bytes())
        assert result["schema"] == 1 and result["source"] == "virtual_group_register_reads"
        assert result["scenario"] == scenario and result["valid"] == (scenario == "clean")
        checks = result["inspection"]
        topology = checks["topology"]
        assert topology["unchanged"] and topology["expected_count"] == 2
        assert topology["valid"] == (scenario != "station-missing")
        observations = clean if scenario != "station-missing" else (2, (0x1000, 0x1002), (0x42, 0x43), (1, 1))
        for key in ("before_mapping", "after_mapping"):
            assert topology[key]["valid"] == topology["valid"]
            observe(topology[key], *observations)
        for review, issue in [(checks["fmmu"], fmmu_issue), (checks["sync_managers"], sm_issue)]:
            assert review["valid"] == (issue is None)
            assert not review["devices"][0]["issues"]
            actual_issues = review["devices"][1]["issues"]
            if issue is None:
                assert not actual_issues
            else:
                assert any(issue in item for item in actual_issues), actual_issues
        assert checks["fmmu"]["stations_match"] and all(device["input"] is None for device in checks["devices"])
        assert [record["model"] for record in result["wire_audit"]] == ["coe", "sii"]
        for record in result["wire_audit"]:
            assert record["datagrams"] == datagrams + 6
            assert not record["state_requests"]
            assert all(record[key] == 0 for key in (
                "logical_reads", "register_writes", "logical_writes", "physical_output_writes",
                "coe_uploads", "coe_downloads", "sii_reads", "op_requests",
            ))
        saved = []
        for kind, review_key, upstream_count in [
            ("fmmu", "fmmu", 2), ("sync_manager", "sync_managers", 4),
        ]:
            snapshot = result[f"{kind}_snapshot"]
            stations = snapshot["devices"]
            assert [row["station_address"] for row in stations] == [0x1000, 0x1001]
            assert stations[0]["count"] == {"wkc": 1, "value": upstream_count}
            assert stations[1]["count"] == {"wkc": wkc, "value": count}
            assert len(stations[1]["slots"]) == (count if wkc == 1 and count <= 16 else 0)
            payload = json.dumps(snapshot, separators=(",", ":")).encode()
            assert checks[review_key]["source_sha256"] == hashlib.sha256(payload).hexdigest()
            path = destination / f"{scenario}-{kind}.json"
            path.write_bytes(payload)
            saved.append(path)
        paired = cli_call(cli, "inspect-input-group", manifest, "--fmmu", saved[0],
                          "--sync-managers", saved[1], "--frame", sample / "input-group-frame.json")
        assert paired["fmmu"] == checks["fmmu"]
        assert paired["sync_managers"] == checks["sync_managers"]
        assert paired["frame"]["valid"] and paired["actual_wkc"] == 2
        assert all((device["input"] is not None) == result["valid"] for device in paired["devices"])
    original = (destination / "clean.json").read_bytes()
    assert "exists" in cli_call(cli, "inspect-virtual-group-mapping", manifest,
                                "--out", destination / "clean.json", success=False)
    assert (destination / "clean.json").read_bytes() == original


def verify_replay_setup_topology(cli, destination):
    manifest = ROOT / "samples/input-group.json"
    fixture = destination / "topology.json"
    captured = cli_call(cli, "generate-group-replay", manifest, "--out", fixture)
    probes = captured["setup_topology"]
    assert captured["schema"] == 4 and [p["connection_generation"] for p in probes] == [1, 2]
    assert [p["before_mapping"]["index"] for p in probes] == [0, 32]
    expected_registers = []
    for station, sm_count in ((4096, 4), (4097, 2)):
        expected_registers += [(station, 0x0004, 1), (station, 0x0600, 16),
                               (station, 0x0610, 16), (station, 0x0005, 1)]
        expected_registers += [(station, 0x0800 + slot * 8, 8) for slot in range(sm_count)]
    for record in probes:
        start = record["before_mapping"]["index"] + 1
        assert record["after_mapping"]["index"] == start + len(expected_registers)
        for i, (text, (station, reg, width)) in enumerate(zip(record["mapping_replies"], expected_registers, strict=True), start):
            raw = bytes.fromhex(text)
            assert raw[12:14] == b"\x88\xa4" and raw[16:18] == bytes([4, i])
            assert struct.unpack_from("<HHH", raw, 18) == (station, reg, width)
            assert struct.unpack_from("<H", raw, 26 + width)[0] == 1
    base = destination / "clean.csv"
    receipt = destination / "verified.json"
    replay = cli_call(cli, "replay-input-group", manifest, fixture, "--csv", base, "--out", receipt)
    assert replay["counts"]["valid"] == 12 and replay["capture"]["written"] == 12
    for saved, report in zip(probes, replay["setup_topology"], strict=True):
        assert report["valid"] and report["unchanged"] and report["expected_count"] == 2
        assert report["connection_generation"] == saved["connection_generation"]
        for phase in ("before_mapping", "after_mapping"):
            for key in ("index", "reply_hex"):
                assert report[phase][key] == saved[phase][key]
            assert report[phase]["count_wkc"] == 2
            assert [p["station_address"] for p in report[phase]["positions"]] == [0x1000, 0x1001]
    audit = cli_call(cli, "verify-group-replay", manifest, fixture, receipt, base)
    assert audit["verified_topology_generations"] == audit["verified_mapping_generations"] == 2
    assert audit["verified_rows"] == 12
    for entry in replay["setup_topology"]:
        assert entry["mapping"]["fmmu"]["valid"] and entry["mapping"]["sync_managers"]["valid"]

    def change_reply(data, *, offset, value):
        reply = data["setup_topology"][1]["after_mapping"]
        raw = bytearray.fromhex(reply["reply_hex"])
        struct.pack_into("<H", raw, offset, value)
        reply["reply_hex"] = raw.hex()

    def duplicate_probe(data):
        probes = data["setup_topology"][1]
        probes["after_mapping"] = probes["before_mapping"].copy()

    def reverse_probes(data):
        probes = data["setup_topology"][1]
        probes["before_mapping"], probes["after_mapping"] = probes["after_mapping"], probes["before_mapping"]

    def reversed_stations(data):
        change_reply(data, offset=40, value=0x1001)
        change_reply(data, offset=56, value=0x1000)

    def mutate_mapping(data, ordinal, offset, value):
        replies = data["setup_topology"][1]["mapping_replies"]
        raw = bytearray.fromhex(replies[ordinal])
        raw[offset] = value
        replies[ordinal] = raw.hex()

    def swap_mapping_frames(data):
        replies = data["setup_topology"][1]["mapping_replies"]
        replies[1], replies[2] = replies[2], replies[1]

    for name, mutate, message in [
        ("missing-probes", lambda d: d.pop("setup_topology"), "requires setup topology"),
        ("missing-generation", lambda d: d["setup_topology"].pop(), "missing setup topology for generation 2"),
        ("wrong-generation", lambda d: d["setup_topology"].reverse(), "do not match generation 1"),
        ("extra-generation", lambda d: d["setup_topology"].append(probes[1]), "unmatched setup topology"),
        ("reused-probe", duplicate_probe, "datagram indexes must increase"),
        ("reversed-probes", reverse_probes, "datagram indexes must increase"),
        ("wrong-count", lambda d: change_reply(d, offset=28, value=3), "fail count, station order or stability"),
        ("reversed-stations", reversed_stations, "fail count, station order or stability"),
        ("unstable-alias", lambda d: change_reply(d, offset=58, value=0x44), "fail count, station order or stability"),
        ("wrong-position", lambda d: change_reply(d, offset=48, value=66), "auto-increment address differs"),
        ("mapping-absent", lambda d: d["setup_topology"][1].pop("mapping_replies"), "missing setup mapping replies"),
        ("mapping-short", lambda d: d["setup_topology"][1]["mapping_replies"].pop(), "mapping reply count differs"),
        ("mapping-reordered", swap_mapping_frames, "reply does not match register"),
        ("mapping-wrong-station", lambda d: mutate_mapping(d, 1, 18, 17), "reply does not match register"),
        ("mapping-count-wkc", lambda d: mutate_mapping(d, 0, 27, 0), "reply does not match register"),
        ("mapping-slot-wkc", lambda d: mutate_mapping(d, 1, 42, 2), "recorded FMMU or SyncManager mapping failed"),
        ("mapping-logical-shift", lambda d: mutate_mapping(d, 1, 26, 1), "recorded FMMU or SyncManager mapping failed"),
        ("mapping-sm-disabled", lambda d: mutate_mapping(d, 7, 32, 0), "recorded FMMU or SyncManager mapping failed"),
        ("mapping-schema-downgrade", lambda d: d.update(schema=3), "schema 3 cannot include mapping replies"),
    ]:
        data = json.loads(fixture.read_bytes())
        mutate(data)
        invalid = destination / f"{name}.json"
        invalid.write_text(json.dumps(data), encoding="utf-8")
        assert data["cycles"] == captured["cycles"]
        blocked_csv = destination / "blocked.csv"
        blocked_receipt = destination / "blocked-receipt.json"
        failure = cli_call(cli, "replay-input-group", manifest, invalid, "--csv", blocked_csv,
                           "--out", blocked_receipt, success=False)
        assert message in failure
        assert not blocked_csv.exists() and not blocked_receipt.exists()

    conflicting = ROOT / "samples/input-group-fmmu.json"
    failure = cli_call(cli, "replay-input-group", manifest, fixture, "--csv", blocked_csv,
                       "--fmmu", conflicting, success=False)
    assert "saved FMMU snapshot differs from recorded setup mapping" in failure
    assert not blocked_csv.exists()

    register_report = cli_call(cli, "inspect-virtual-group-mapping", manifest)
    matching_fmmu = destination / "matching-fmmu.json"
    matching_fmmu.write_text(json.dumps(register_report["fmmu_snapshot"]), encoding="utf-8")
    conflicting_sm = destination / "conflicting-sm.json"
    sm = register_report["sync_manager_snapshot"]
    sm["devices"][0]["slots"][3]["value"][5] ^= 1
    conflicting_sm.write_text(json.dumps(sm), encoding="utf-8")
    failure = cli_call(cli, "replay-input-group", manifest, fixture, "--csv", blocked_csv,
                       "--fmmu", matching_fmmu, "--sync-managers", conflicting_sm, success=False)
    assert "saved SyncManager snapshot differs from recorded setup mapping" in failure
    assert not blocked_csv.exists()

    legacy = destination / "legacy-topology.json"
    old = json.loads(fixture.read_bytes())
    old["schema"] = 3
    for pair in old["setup_topology"]:
        del pair["mapping_replies"]
    legacy.write_text(json.dumps(old), encoding="utf-8")
    legacy_csv = destination / "legacy-topology.csv"
    legacy_receipt = destination / "legacy-topology-replay.json"
    cli_call(cli, "replay-input-group", manifest, legacy, "--csv", legacy_csv, "--out", legacy_receipt,
             "--fmmu", conflicting)
    legacy_audit = cli_call(cli, "verify-group-replay", manifest, legacy, legacy_receipt, legacy_csv,
                            "--fmmu", conflicting)
    assert legacy_audit["verified_rows"] == 12 and legacy_audit["verified_topology_generations"] == 2
    assert "verified_mapping_generations" not in legacy_audit

    removed_mapping = destination / "receipt-without-mapping.json"
    edited = json.loads(receipt.read_bytes())
    del edited["setup_topology"][0]["mapping"]
    removed_mapping.write_text(json.dumps(edited), encoding="utf-8")
    failure = cli_call(cli, "verify-group-replay", manifest, fixture, removed_mapping, base, success=False)
    assert "differs from the rebuilt cycles" in failure

    no_probe_receipt = destination / "receipt-without-probes.json"
    del replay["setup_topology"]
    no_probe_receipt.write_text(json.dumps(replay), encoding="utf-8")
    failure = cli_call(cli, "verify-group-replay", manifest, fixture, no_probe_receipt, base, success=False)
    assert "differs from the rebuilt cycles" in failure


def verify_cyclic_topology_guard(cli, destination):
    manifest = ROOT / "samples/input-group.json"
    fixture = destination / "monitored.json"
    captured = cli_call(cli, "generate-group-replay", manifest, "--scenario", "topology-change", "--out", fixture)
    assert captured["schema"] == 5 and captured["virtual_scenario"] == "topology_change"
    assert [item["connection_generation"] for item in captured["setup_topology"]] == [1, 2]
    assert all(len(item["mapping_replies"]) == 14 for item in captured["setup_topology"])
    for ordinal, cycle in enumerate(captured["cycles"]):
        [text] = cycle["received_hex"]
        raw = bytes.fromhex(text)
        assert len(raw) == 126
        for offset, command in ((16, 10), (44, 4), (62, 4), (80, 7), (94, 1), (110, 1)):
            assert raw[offset:offset + 2] == bytes([command, cycle["index"]])
        assert struct.unpack_from("<H", raw, 42)[0] == 2
        assert struct.unpack_from("<H", raw, 92)[0] == 2
        assert struct.unpack_from("<H", raw, 60)[0] == 1 and struct.unpack_from("<H", raw, 78)[0] == 1
        stations = [struct.unpack_from("<H", raw, offset)[0] for offset in (104, 120)]
        assert stations == ([0x1001, 0x1000] if ordinal in (2, 3) else [0x1000, 0x1001])

    base = destination / "every.csv"
    receipt = destination / "every.json"
    report = cli_call(cli, "replay-input-group", manifest, fixture, "--csv", base, "--rotate-rows", 2, "--out", receipt)
    assert report["counts"] == {
        "cycles": 12, "matched_replies": 12, "valid": 6, "unmatched_cycles": 0,
        "topology_rejections": 2, "topology_hold_rejections": 4,
        "wkc_mismatches": 0, "invalid_al": 0, "ignored_frames": 0,
    }
    for ordinal, cycle in enumerate(report["cycles"]):
        assert cycle["actual_wkc"] == 2 and all(al["clean_safeop"] for al in cycle["al"])
        topology = cycle["cyclic_topology"]
        assert topology["count_wkc"] == 2
        assert topology["matches_setup"] == (ordinal not in (2, 3))
        assert topology["held_for_setup"] == (4 <= ordinal <= 7)
        assert cycle["valid"] == (ordinal in (0, 1, 8, 9, 10, 11))
    parts, csv_rows = rows(base)
    assert len(parts) == 3
    positions = [tuple(int(row[key]) for key in ("connection_generation", "cycle_index", "elapsed_us")) for row in csv_rows]
    assert positions == [(1, 1, 0), (1, 2, 1000), (2, 1, 8000), (2, 2, 9000), (2, 3, 10000), (2, 4, 11000)]
    checked = cli_call(cli, "verify-group-replay", manifest, fixture, receipt, base)
    assert checked["complete"] and checked["verified_rows"] == 6
    bundle = destination / "capture-bundle"
    cli_call(cli, "bundle-group-replay", manifest, fixture, receipt, base, "--out", bundle)
    moved = bundle.rename(destination / "moved-bundle")
    assert cli_call(cli, "verify-group-bundle", moved)["audit"]["verified_rows"] == 6

    change_base = destination / "change.csv"
    change_receipt = destination / "change.json"
    change = cli_call(cli, "replay-input-group", manifest, fixture, "--csv", change_base,
                      "--on-change", "--out", change_receipt)
    assert change["counts"] == report["counts"]
    with change_base.open(encoding="utf-8", newline="") as stream:
        changed = list(csv.DictReader(stream, strict=True))
    assert [(row["connection_generation"], row["cycle_index"]) for row in changed] == [("1", "1"), ("2", "1")]

    def write_modified(name, mutate):
        data = json.loads(fixture.read_bytes())
        mutate(data)
        path = destination / f"{name}.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def mutate_probe(data, offset, value):
        raw = bytearray.fromhex(data["cycles"][0]["received_hex"][0])
        raw[offset] = value
        data["cycles"][0]["received_hex"][0] = raw.hex()

    for name, offset, value in (("broadcast-wkc-change", 92, 3), ("position-wkc-zero", 108, 0), ("alias-change", 106, 0x99)):
        altered = write_modified(name, lambda data: mutate_probe(data, offset, value))
        changed = cli_call(cli, "replay-input-group", manifest, altered, "--csv", destination / f"{name}.csv")
        first = changed["cycles"][0]
        assert first["actual_wkc"] == 2 and not first["valid"] and not first["cyclic_topology"]["matches_setup"]
        assert changed["counts"]["topology_rejections"] == 3
        assert changed["counts"]["topology_hold_rejections"] == 5 and changed["counts"]["valid"] == 4
        if name == "alias-change":
            assert first["cyclic_topology"]["valid"]

    for name, mutate, message in [
        ("setup-missing", lambda data: data["setup_topology"].pop(), "missing setup topology for generation 2"),
        ("setup-downgrade", lambda data: data.update(schema=4), "requires a monitored group replay fixture"),
        ("wrong-traversal", lambda data: mutate_probe(data, 96, 0xFF), "auto-increment address differs"),
    ]:
        altered = write_modified(name, mutate)
        failed_csv = destination / "blocked.csv"
        failed_report = destination / "blocked.json"
        failure = cli_call(cli, "replay-input-group", manifest, altered, "--csv", failed_csv,
                           "--out", failed_report, success=False)
        assert message in failure
        assert not failed_csv.exists() and not failed_report.exists()

    amended = destination / "incorrect-hold.json"
    report["cycles"][4]["cyclic_topology"]["held_for_setup"] = False
    amended.write_text(json.dumps(report), encoding="utf-8")
    failed = cli_call(cli, "verify-group-replay", manifest, fixture, amended, base, success=False)
    assert "differs from the rebuilt cycles" in failed


def verify_three_station_group(cli, destination):
    sample = ROOT / "samples"
    manifest = sample / "input-group-three.json"
    plan = cli_call(cli, "inspect-input-group", manifest)
    assert plan["input_bytes"] == 16 and plan["expected_wkc"] == 2
    assert [item["offset"] for item in plan["devices"]] == [0, None, 8]
    assert [item["tx_bytes"] for item in plan["devices"]] == [8, 0, 8]
    setup = cli_call(cli, "inspect-virtual-group-mapping", manifest, "--out", destination / "preflight.json")
    assert setup["valid"] and len(setup["wire_audit"]) == 3
    assert all(audit["logical_reads"] == audit["register_writes"] == 0 for audit in setup["wire_audit"])
    topology = setup["inspection"]["topology"]
    assert topology["expected_count"] == topology["before_mapping"]["count_wkc"] == 3
    for key in ("fmmu_snapshot", "sync_manager_snapshot"):
        slots = setup[key]["devices"][1]["slots"]
        assert len(slots) == 2 and all(slot["wkc"] == 1 and not any(slot["value"]) for slot in slots)
    swapped = cli_call(cli, "inspect-virtual-group-mapping", manifest, "--scenario", "swap-during-readback")
    assert not swapped["valid"] and swapped["inspection"]["fmmu"]["valid"]
    assert swapped["inspection"]["sync_managers"]["valid"]
    assert [p["station_address"] for p in swapped["inspection"]["topology"]["after_mapping"]["positions"]] == [4096, 4098, 4097]

    for scenario, accepted in (
        ("clean", list(range(12))),
        ("faults", [0, 1, 5, 8, 9, 10, 11]),
        ("topology-change", [0, 1, 8, 9, 10, 11]),
    ):
        fixture = destination / f"{scenario}-frames.json"
        raw = cli_call(cli, "generate-group-replay", manifest, "--scenario", scenario, "--out", fixture)
        assert raw["schema"] == (5 if scenario == "topology-change" else 4)
        assert raw["stations"] == [4096, 4097, 4098]
        assert [g["connection_generation"] for g in raw["setup_topology"]] == [1, 2]
        assert all(len(g["mapping_replies"]) == 20 for g in raw["setup_topology"])
        csv_base = destination / f"{scenario}.csv"
        receipt = destination / f"{scenario}-replay.json"
        report = cli_call(cli, "replay-input-group", manifest, fixture, "--csv", csv_base,
                          "--rotate-rows", 2, "--out", receipt)
        assert all(g["expected_count"] == 3 and g["mapping"]["fmmu"]["valid"] for g in report["setup_topology"])
        matched = [item for item in report["cycles"] if item["actual_wkc"] is not None]
        assert all(item["actual_wkc"] == 2 and len(item["al"]) == 3 for item in matched)
        assert [i for i, item in enumerate(report["cycles"]) if item["valid"]] == accepted
        assert report["counts"]["wkc_mismatches"] == 0
        if scenario == "faults":
            cycles = report["cycles"]
            assert report["counts"]["invalid_al"] == 3
            assert cycles[2]["al"][1]["status"]["state"] == "PREOP"
            assert cycles[3]["al"][1]["status"]["code"] == 0x001e
            assert cycles[6]["al"][1]["actual_wkc"] == 0 and cycles[6]["al"][1]["status"] is None
            for index in (2, 3, 6):
                assert all(cycles[index]["al"][position]["clean_safeop"] for position in (0, 2))
        if scenario == "topology-change":
            assert report["counts"]["topology_rejections"] == 2
            assert report["counts"]["topology_hold_rejections"] == 4
            failed = report["cycles"][2]["cyclic_topology"]
            assert failed["count_wkc"] == 3 and not failed["matches_setup"]
            assert [p["station_address"] for p in failed["positions"]] == [4096, 4098, 4097]

        _, csv_rows = rows(csv_base)
        assert len(csv_rows) == len(accepted)
        for row, ordinal in zip(csv_rows, accepted, strict=True):
            assert int(row["elapsed_us"]) == ordinal * 1000
            assert int(row["Position 0 Counter"]) == ordinal // 4
            assert int(row["Position 2 Counter"]) == ordinal // 4 + 2
            assert not any(name.startswith("Position 1 ") for name in row)
        checked = cli_call(cli, "verify-group-replay", manifest, fixture, receipt, csv_base)
        assert checked["verified_rows"] == len(accepted)
        assert checked["verified_topology_generations"] == checked["verified_mapping_generations"] == 2
        if scenario == "faults":
            bundle = destination / "three-station-bundle"
            cli_call(cli, "bundle-group-replay", manifest, fixture, receipt, csv_base, "--out", bundle)
            relocated = bundle.rename(destination / "relocated-three-station-bundle")
            reopened = cli_call(cli, "verify-group-bundle", relocated)
            assert reopened["audit"]["verified_rows"] == 7
            assert json.loads((relocated / "profiles/01.json").read_bytes())["tx_bytes"] == 0
            assert json.loads((relocated / "profiles/02.json").read_bytes())["tx_bytes"] == 8

    wrong_manifest = destination / "wrong-pdo-layout.json"
    wrong = json.loads(manifest.read_bytes())
    for device in wrong["devices"]:
        device["profile"] = str((sample / device["profile"]).resolve())
    wrong["devices"][1]["profile"] = wrong["devices"][2]["profile"]
    wrong_manifest.write_text(json.dumps(wrong), encoding="utf-8")
    refusal = destination / "wrong-pdo-layout-frames.json"
    assert "authored CoE and SII identities in order" in cli_call(
        cli, "generate-group-replay", wrong_manifest, "--out", refusal, success=False)
    assert not refusal.exists()


def verify_generated_group_replay(cli, destination):
    sample = ROOT / "samples"
    manifest = sample / "input-group.json"
    setup = cli_call(cli, "inspect-virtual-group-mapping", manifest)
    evidence = []
    for name, key in (("fmmu", "fmmu_snapshot"), ("sync-managers", "sync_manager_snapshot")):
        file = destination / f"matching-{name}.json"
        file.write_text(json.dumps(setup[key]), encoding="utf-8")
        evidence.extend((f"--{name}", file))
    evidence.extend(("--pdo", sample / "input-group-pdo.json"))
    for scenario in ("clean", "faults"):
        faults = scenario == "faults"
        expected_valid = [0, 1, 5, 8, 9, 10, 11] if faults else list(range(12))
        fixture = destination / f"virtual-{scenario}.json"
        generated = cli_call(cli, "generate-group-replay", manifest, "--scenario", scenario, "--out", fixture)
        fixture_bytes = fixture.read_bytes()
        assert generated == json.loads(fixture_bytes)
        assert generated["schema"] == 4 and generated["stations"] == [0x1000, 0x1001]
        assert generated["virtual_scenario"] == scenario
        sent = generated["cycles"]
        assert [cycle["index"] for cycle in sent] == [((254 + i) & 255) for i in range(12)]
        assert [(cycle["connection_generation"], cycle["cycle_index"]) for cycle in sent] == (
            [(1, i) for i in range(1, 9)] + [(2, i) for i in range(1, 5)]
        )
        assert "exists" in cli_call(cli, "generate-group-replay", manifest, "--out", fixture, success=False)
        assert fixture_bytes == fixture.read_bytes()
        if faults:
            assert sent[4]["received_hex"] == sent[3]["received_hex"]
            assert len(sent[5]["received_hex"]) == 2
            assert not sent[7]["received_hex"]
        repeat = destination / f"repeat-{scenario}.json"
        generate_options = ["--scenario", "faults"] if faults else []
        assert cli_call(cli, "generate-group-replay", manifest, "--out", repeat, *generate_options) == generated
        assert repeat.read_bytes() == fixture_bytes

        for mode in ("every", "change"):
            base = destination / f"{scenario}-{mode}.csv"
            receipt = base.with_suffix(".json")
            expected_rows = expected_valid if mode == "every" else [0, 5 if faults else 4, 8]
            mode_options = ["--on-change"] if mode == "change" else []
            replay = cli_call(cli, "replay-input-group", manifest, fixture, "--csv", base,
                              "--rotate-rows", 2, "--out", receipt, *evidence, *mode_options)
            assert replay["virtual_scenario"] == scenario
            counts = replay["counts"]
            assert counts == {
                "cycles": 12, "valid": len(expected_valid), "matched_replies": 10 if faults else 12,
                "unmatched_cycles": 2 if faults else 0, "wkc_mismatches": int(faults),
                "invalid_al": 3 if faults else 0, "ignored_frames": 2 if faults else 0,
            }
            assert replay["error"] is None and replay["capture"]["overruns"] == 0
            assert replay["capture"]["written"] == len(expected_rows)
            assert replay["receive_spacing"]["longest_gap_us"] == (2000 if faults else 1000)
            assert replay["valid_receive_spacing"]["longest_gap_us"] == (4000 if faults else 1000)
            cycles = replay["cycles"]
            assert [i for i, cycle in enumerate(cycles) if cycle["valid"]] == expected_valid
            if faults:
                assert cycles[2]["actual_wkc"] == 1 and cycles[2]["al"][1]["status"]["state"] == "PREOP"
                assert cycles[3]["actual_wkc"] == 2 and cycles[3]["al"][1]["status"]["code"] == 0x1e
                assert cycles[4]["actual_wkc"] is None and cycles[4]["ignored_frames"] == 1
                assert cycles[5]["actual_wkc"] == 2 and cycles[5]["ignored_frames"] == 1
                assert cycles[6]["actual_wkc"] == 2 and cycles[6]["al"][1]["actual_wkc"] == 0
                assert cycles[7]["actual_wkc"] is None and cycles[7]["ignored_frames"] == 0
            parts, observations = rows(base)
            assert len(parts) == (len(expected_rows) + 1) // 2 and not base.exists()
            for index, (ordinal, row) in enumerate(zip(expected_rows, observations, strict=True), 1):
                assert row["capture_start_utc"] == generated["capture_start_utc"]
                assert int(row["elapsed_us"]) == ordinal * 1000 and int(row["sample_index"]) == index
                assert int(row["connection_generation"]) == sent[ordinal]["connection_generation"]
                assert int(row["cycle_index"]) == sent[ordinal]["cycle_index"]
                for position in (0, 1):
                    counter = ordinal // 4 + position
                    assert row[f"Position {position} Counter"] == str(counter)
                    assert row[f"Position {position} Sensor active"] == ("true" if counter & 1 else "false")
                    assert float(row[f"Position {position} Scaled counter"]) == counter / 4
            audited = cli_call(cli, "verify-group-replay", manifest, fixture, receipt, base, *evidence)
            assert audited["complete"] and audited["verified_rows"] == len(expected_rows)
            if faults and mode == "every":
                bundle = destination / "virtual-group-bundle"
                bundled = cli_call(cli, "bundle-group-replay", manifest, fixture, receipt, base,
                                   "--out", bundle, *evidence)
                relocated = bundle.rename(destination / "relocated-virtual-group-bundle")
                reopened = cli_call(cli, "verify-group-bundle", relocated)
                assert reopened["receipt"] == bundled and reopened["audit"]["complete"]
                assert reopened["audit"]["verified_rows"] == len(expected_rows)
                assert reopened["audit"]["verified_mapping_generations"] == 2
                assert bundled["complete"] and bundled["verified_rows"] == len(expected_rows)
                assert (relocated / "fixture.json").read_bytes() == fixture_bytes

    wrong_manifest = destination / "swapped-devices.json"
    plan = json.loads(manifest.read_bytes())
    plan["devices"].reverse()
    for position, device in enumerate(plan["devices"]):
        device["position"] = position
        device["profile"] = str((sample / device["profile"]).resolve())
    wrong_manifest.write_text(json.dumps(plan), encoding="utf-8")
    refused = destination / "unexpected.json"
    error = cli_call(cli, "generate-group-replay", wrong_manifest, "--out", refused, success=False)
    assert "authored CoE and SII identities in order" in error and not refused.exists()


def verify_group_replay_bundle(cli, destination):
    original = destination / "source files"
    original.mkdir()
    manifest = original / "manifest.json"
    fixture = original / "fixture.json"
    receipt = original / "replay.json"
    csv_base = original / "log.csv"
    sample = ROOT / "samples"
    plan = json.loads((sample / "input-group.json").read_bytes())
    original_profiles = []
    for position, device in enumerate(plan["devices"]):
        profile = original / f"profile {position}.json"
        shutil.copyfile(sample / device["profile"], profile)
        original_profiles.append(profile)
        device["profile"] = str(profile.resolve()) if position == 0 else profile.name
    manifest.write_text(json.dumps(plan), encoding="utf-8")
    shutil.copyfile(sample / "input-group-replay.json", fixture)
    evidence_names = ["fmmu", "sync-managers", "pdo"]
    evidence = []
    for name in evidence_names:
        path = original / (name + ".json")
        shutil.copyfile(sample / f"input-group-{name}.json", path)
        evidence.extend([f"--{name}", path])
    replay = cli_call(cli, "replay-input-group", manifest, fixture, "--csv", csv_base,
                      "--rotate-rows", 2, "--out", receipt, *evidence)
    expected_rows = replay["capture"]["written"]
    assert expected_rows == 6

    def bundle(out, saved=receipt, base=csv_base, options=evidence, success=True):
        return cli_call(cli, "bundle-group-replay", manifest, fixture, saved, base, *options,
                        "--out", out, success=success)

    def verify(path, *args, success=True):
        return cli_call(cli, "verify-group-bundle", path, *args, success=success)

    folder = destination / "verified bundle"
    checked = bundle(folder)
    assert checked == json.loads((folder / "bundle.json").read_bytes())
    assert checked["complete"] and checked["rotated"] and checked["verified_rows"] == expected_rows
    expected_files = {
        "manifest.json": manifest,
        "fixture.json": fixture,
        "replay.json": receipt,
        **{f"profiles/{i:02}.json": file for i, file in enumerate(original_profiles)},
        **{name + ".json": original / (name + ".json") for name in evidence_names},
        **{f"csv/capture.{i:04}.csv": original / f"log.{i:04}.csv" for i in range(1, 4)},
    }
    assert {path.relative_to(folder).as_posix() for path in folder.rglob("*") if path.is_file()} == (
        set(expected_files) | {"bundle.json"}
    )
    sealed = [(checked[key], expected_files[name]) for key, name in [
        ("manifest", "manifest.json"), ("fixture", "fixture.json"), ("replay", "replay.json"),
        ("fmmu", "fmmu.json"), ("sync_managers", "sync-managers.json"), ("pdo", "pdo.json"),
    ]]
    sealed.extend(zip(checked["profiles"], original_profiles, strict=True))
    sealed.extend(zip(checked["csv"], [expected_files[f"csv/capture.{i:04}.csv"] for i in range(1, 4)], strict=True))
    for record, file in sealed:
        data = file.read_bytes()
        assert record == {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    for target, source in expected_files.items():
        assert (folder / target).read_bytes() == source.read_bytes()
    assert "already exists" in bundle(folder, success=False)
    assert checked == json.loads((folder / "bundle.json").read_bytes())

    rejected_output = destination / "must remain absent"
    incorrect = original / "edited.json"
    changed = json.loads(receipt.read_bytes())
    changed["cycles"][2]["valid"] = True
    incorrect.write_text(json.dumps(changed), encoding="utf-8")
    assert "rebuilt cycles" in bundle(rejected_output, saved=incorrect, success=False)
    assert not rejected_output.exists()

    partial_base = original / "partial.csv"
    collision = original / "partial.0002.csv"
    collision.write_bytes(b"existing part stays here\n")
    partial_receipt = original / "partial.json"
    cli_call(cli, "replay-input-group", manifest, fixture, "--csv", partial_base,
             "--rotate-rows", 2, "--out", partial_receipt, success=False)
    partial_folder = destination / "partial bundle"
    incomplete = bundle(partial_folder, saved=partial_receipt, base=partial_base, options=[])
    assert not incomplete["complete"] and incomplete["verified_rows"] == 2 and incomplete["expected_rows"] == 6
    assert len(incomplete["csv"]) == 1 and not (partial_folder / "csv/capture.0002.csv").exists()
    assert not verify(partial_folder)["audit"]["complete"]
    assert collision.read_bytes() == b"existing part stays here\n"

    plain_csv = original / "on-change.csv"
    plain_receipt = original / "on-change.json"
    cli_call(cli, "replay-input-group", manifest, fixture, "--csv", plain_csv,
             "--on-change", "--out", plain_receipt)
    plain_folder = destination / "unrotated bundle"
    plain = bundle(plain_folder, saved=plain_receipt, base=plain_csv, options=[])
    assert plain["complete"] and not plain["rotated"] and plain["verified_rows"] == 3
    assert (plain_folder / "csv/capture.csv").read_bytes() == plain_csv.read_bytes()
    assert verify(plain_folder)["audit"]["verified_rows"] == 3

    relocated = destination / "case relocated"
    shutil.copytree(folder, relocated)
    parked = destination / "source files parked"
    assert original.resolve().parent == parked.resolve().parent == destination.resolve()
    original.rename(parked)
    assert not original.exists()
    audit_file = destination / "relocated-audit.json"
    result = verify(relocated, "--out", audit_file)
    assert result == json.loads(audit_file.read_bytes())
    assert result["receipt_sha256"] == hashlib.sha256((folder / "bundle.json").read_bytes()).hexdigest()
    assert result["audit"]["complete"] and result["audit"]["verified_rows"] == 6
    assert "exists" in verify(relocated, "--out", audit_file, success=False)
    assert result == json.loads(audit_file.read_bytes())

    tampered = destination / "changed bundle"
    shutil.copytree(relocated, tampered)
    edited_manifest = tampered / "manifest.json"
    before = edited_manifest.read_bytes()
    modified = before.replace(b'"devices": ', b'"devices":\t', 1)
    assert modified != before and len(modified) == len(before)
    edited_manifest.write_bytes(modified)
    assert "SHA-256" in verify(tampered, success=False)
    edited_manifest.write_bytes(before)
    csv = tampered / "csv/capture.0001.csv"
    raw = csv.read_bytes()
    modified = raw.replace(b",42,true,", b",43,true,", 1)
    assert modified != raw and len(modified) == len(raw)
    csv.write_bytes(modified)
    assert "differs from recorded input" in verify(tampered, success=False)
    csv.write_bytes(raw)
    verified_receipt = tampered / "bundle.json"
    forged = json.loads(verified_receipt.read_bytes())
    forged["csv"].pop()
    verified_receipt.write_text(json.dumps(forged), encoding="utf-8")
    assert "layout differs from bundle inventory" in verify(tampered, success=False)
    shutil.copyfile(relocated / "bundle.json", verified_receipt)
    missing = tampered / "csv/capture.0002.csv"
    missing.rename(missing.with_suffix(".unused"))
    assert "capture.0002.csv" in verify(tampered, success=False)
    incomplete_dir = destination / "interrupted export"
    incomplete_dir.mkdir()
    assert "bundle.json" in verify(incomplete_dir, success=False)


def verify_pcap(cli, destination):
    """Authored PCAP records: no capture hardware or packet transmission."""
    fixture = json.loads((ROOT / "samples/synthetic-replay.json").read_text(encoding="utf-8"))
    request = bytes.fromhex(fixture["exchanges"][0]["request_hex"])
    reply = bytes.fromhex(fixture["exchanges"][0]["received_hex"][0])

    def frame(raw, sequence, wkc=None, state=None):
        packet = bytearray(raw)
        packet[17] = packet[37] = sequence
        if wkc is not None:
            packet[34:36] = struct.pack("<H", wkc)
        if state is not None:
            packet[46] = state
        return bytes(packet)

    other = bytearray(reply)
    other[12:14] = b"\x08\x00"
    vlan = bytearray(reply)
    vlan[12:14] = b"\x81\x00"
    wrong = bytearray(reply)
    wrong[38] = 1
    packets = [(0, frame(request, 1), None), (100, frame(reply, 1), None),
               (1000, frame(request, 2), None), (1100, frame(reply, 2, wkc=0), None),
               (2000, frame(request, 3), None), (2100, frame(reply, 3, state=0x14), None),
               (3100, frame(reply, 4), None), (3100, frame(reply, 4), None),
               (3200, other, None), (3300, vlan, None), (3400, wrong, None),
               (3500, reply, 100)]

    def pcap(endian, nano, records=packets):
        data = struct.pack(endian + "IHHIIII", 0xa1b23c4d if nano else 0xa1b2c3d4,
                           2, 4, 0, 0, 65535, 1)
        for fraction, packet, original in records:
            data += struct.pack(endian + "IIII", 1700000000,
                                fraction * (1000 if nano else 1), len(packet),
                                len(packet) if original is None else original) + packet
        return data

    reports = []
    for endian in ("<", ">"):
        for nano in (False, True):
            path = destination / f"authored-{'le' if endian == '<' else 'be'}-{'ns' if nano else 'us'}.pcap"
            data = pcap(endian, nano)
            path.write_bytes(data)
            result = cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path,
                              "--station", "0x1000", "--preview", 64)
            assert result["file_sha256"] == hashlib.sha256(data).hexdigest()
            assert result["file_bytes"] == len(data) and result["profile"]["requested_cycle_us"] == 1000
            assert result["timestamp_resolution"] == ("nanoseconds" if nano else "microseconds")
            assert result["schema"] == 4 and result["capture_format"] == "pcap" and result["pcapng"] is None
            assert result["counts"] == dict(packets=12, snapshot_truncated=1, ethercat=10,
                requests=3, replies=5, valid_safeop_replies=3, wkc_mismatches=1, al_mismatches=1,
                unmatched_ethercat=2, other_packets=2, vlan_packets=1, timestamp_regressions=0)
            assert result["request_spacing"]["longest_gap_ns"] == 1000000
            assert result["reply_spacing"]["longest_gap_ns"] == 1000000
            assert result["valid_reply_spacing"]["longest_gap_ns"] == 3000000
            assert result["request_spacing"]["count"] == 2 and result["reply_spacing"]["count"] == 4
            assert len(result["preview"]) == 5
            assert [v["value"] for v in result["preview"][0]["values"]] == ["4", "false", "1"]
            assert [v["valid_safeop"] for v in result["preview"]] == [True, False, False, True, True]
            assert result["capture_first_utc"] == "2023-11-14T22:13:20.000000000Z"
            limited = cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path, "--preview", 1)
            assert limited["counts"] == result["counts"] and len(limited["preview"]) == 1
            reports.append(result)
    path = destination / "regressing.pcap"
    path.write_bytes(pcap("<", True, [(100, reply, None), (90, reply, None)]))
    result = cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path, "--preview", 0)
    assert result["counts"]["timestamp_regressions"] == 1 and result["preview"] == []
    assert result["request_spacing"] is None and result["reply_spacing"] is None and result["valid_reply_spacing"] is None
    good = pcap("<", False)
    bad_cases = {"pcapng": b"\x0a\x0d\x0d\x0a" + bytes(24), "truncated": good[:-1],
                 "partial-header": good + b"\x00", "linktype": good[:20] + struct.pack("<I", 101) + good[24:],
                 "fraction": good[:28] + struct.pack("<I", 1000000) + good[32:]}
    for name, data in bad_cases.items():
        path = destination / f"bad-{name}.pcap"
        path.write_bytes(data)
        failure = cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path, success=False)
        assert "Error" in failure
    path = destination / "authored-le-us.pcap"
    exported = destination / "inspection.json"
    result = cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path, "--out", exported)
    saved = exported.read_bytes()
    assert not saved.startswith(b"\xef\xbb\xbf") and saved.endswith(b"\n")
    assert json.loads(saved) == result
    cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path, "--out", exported, success=False)
    assert exported.read_bytes() == saved
    before = path.read_bytes()
    cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path, "--out", path, success=False)
    assert path.read_bytes() == before
    for option, value in [("--preview", 65), ("--station", 0), ("--station", 65536)]:
        cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path, option, value, success=False)
    (destination / "inspection-reports.json").write_text(json.dumps(reports, indent=2), encoding="utf-8")


def verify_pcapng(cli, destination, classic_fixture):
    """Independent block/option writer, using already-checked authored Ethernet records."""
    raw = classic_fixture.read_bytes()
    records = []
    at = 24
    while at < len(raw):
        sec, fraction, captured, original = struct.unpack_from("<IIII", raw, at)
        records.append((sec * 1000000000 + fraction * 1000, raw[at + 16:at + 16 + captured], original))
        at += 16 + captured
    reference = cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", classic_fixture, "--preview", 64)

    def block(endian, kind, body):
        body += bytes((-len(body)) % 4)
        return struct.pack(endian + "II", kind, len(body) + 12) + body + struct.pack(endian + "I", len(body) + 12)

    def option(endian, code, value):
        return struct.pack(endian + "HH", code, len(value)) + value + bytes((-len(value)) % 4)

    def capture(endian="<", nano=False, offset=0, *, opts=None, selected=records, interface=0):
        shb = block(endian, 0x0a0d0d0a, struct.pack(endian + "IHHq", 0x1a2b3c4d, 1, 0, -1))
        if opts is None:
            opts = option(endian, 9, bytes([9 if nano else 6])) + option(endian, 14, struct.pack(endian + "q", offset))
        idb = block(endian, 1, struct.pack(endian + "HHI", 1, 0, 65535) + opts)
        epbs = []
        for timestamp, packet, original in selected:
            ticks = timestamp // (1 if nano else 1000)
            epbs.append(block(endian, 6, struct.pack(endian + "IIIII", interface, ticks >> 32, ticks & 0xffffffff,
                                                   len(packet), original) + packet + bytes((-len(packet)) % 4)))
        return shb, idb, epbs

    results = []
    for endian in ("<", ">"):
        for nano in (False, True):
            for offset in (-2, 3):
                shb, idb, epbs = capture(endian, nano, offset)
                data = shb + idb + b"".join(epbs)
                path = destination / f"authored-{'le' if endian == '<' else 'be'}-{'ns' if nano else 'us'}-{offset}.pcapng"
                path.write_bytes(data)
                r = cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path, "--preview", 64)
                assert r["schema"] == 4 and r["capture_format"] == "pcapng"
                assert r["file_sha256"] == hashlib.sha256(data).hexdigest() and r["file_bytes"] == len(data)
                assert r["counts"] == reference["counts"]
                assert all(r[k] == reference[k] for k in ["request_spacing", "reply_spacing", "valid_reply_spacing"])
                assert r["timestamp_resolution"] == ("nanoseconds" if nano else "microseconds")
                assert r["pcapng"] == dict(minor_version=0, declared_section_bytes=None, interface_id=0, link_type=1,
                    snaplen=65535, timestamp_resolution_exponent=9 if nano else 6, timestamp_offset_seconds=offset,
                    blocks=14, skipped_blocks=0, skipped_options=0, selection_explicit=False,
                    total_packets=12, skipped_packets=0, statistics=[],
                    interfaces=[dict(interface_id=0, link_type=1, snaplen=65535, timestamp_resolution_exponent=9 if nano else 6,
                                     timestamp_offset_seconds=offset, packets=12)])
                for expected, actual in zip(reference["preview"], r["preview"], strict=True):
                    expected = dict(expected, timestamp_unix_ns=expected["timestamp_unix_ns"] + offset * 1000000000)
                    assert actual == expected
                results.append(r)
    shb, idb, epbs = capture()
    good = shb + idb + b"".join(epbs)
    cases = {"second-interface": good + idb, "second-section": good + shb,
             "no-interface": shb + epbs[0], "simple-packet": shb + idb + block("<", 3, b"\x00" * 8),
             "repeated-length": good[:-4] + struct.pack("<I", 12), "truncated": good[:-1],
             "binary-resolution": b"".join(capture(opts=option("<", 9, b"\x89"))[:2]) + b"".join(epbs),
             "duplicate-resolution": shb + capture(opts=option("<", 9, b"\x06") * 2)[1] + b"".join(epbs),
             "bad-offset-size": shb + capture(opts=option("<", 14, b"\x00" * 7))[1] + b"".join(epbs)}
    for name, data in cases.items():
        path = destination / f"bad-{name}.pcapng"
        path.write_bytes(data)
        export = destination / f"bad-{name}.json"
        cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path, "--out", export, success=False)
        assert not export.exists()
    # Unknown metadata is counted, not interpreted; the default clock is microseconds.
    shb, idb, epbs = capture(opts=option("<", 1, b"Authored comment"))
    path = destination / "default-clock-and-skipped-metadata.pcapng"
    path.write_bytes(shb + idb + block("<", 0x12345678, b"Authored custom data") + b"".join(epbs))
    result = cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path)
    assert result["pcapng"]["skipped_blocks"] == result["pcapng"]["skipped_options"] == 1
    assert result["pcapng"]["timestamp_resolution_exponent"] == 6 and result["counts"] == reference["counts"]
    # Regressions still suppress all spacing, regardless of the container.
    shb, idb, epbs = capture(nano=True, selected=[records[1], (records[1][0] - 1, records[1][1], records[1][2])])
    path = destination / "regressing.pcapng"
    path.write_bytes(shb + idb + b"".join(epbs))
    result = cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path)
    assert result["counts"]["timestamp_regressions"] == 1 and result["reply_spacing"] is None
    shb, idb, epbs = capture(nano=True, selected=[(0, records[1][1], records[1][2]),
        ((1 << 63) - 1, records[1][1], records[1][2])])
    path = destination / "timestamp-boundary.pcapng"
    path.write_bytes(shb + idb + b"".join(epbs))
    result = cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path)
    assert result["reply_spacing"]["longest_gap_ns"] == (1 << 63) - 1
    # Different interface clocks and excluded regressions must never enter selected timing.
    for endian in ("<", ">"):
        shb, selected_idb, selected_epbs = capture(endian, True, -2, interface=1)
        _, _, other_epbs = capture(endian, selected=[records[-1], records[0]])
        other_idb = block(endian, 1, struct.pack(endian + "HHI", 101, 0, 65535))
        empty_idb = capture(endian)[1]
        data = shb + other_idb + selected_idb + empty_idb + other_epbs[0] + selected_epbs[0] + other_epbs[1] + b"".join(selected_epbs[1:])
        path = destination / f"multiple-{'le' if endian == '<' else 'be'}.pcapng"
        path.write_bytes(data)
        output = path.with_suffix(".json")
        r = cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path, "--interface", 1, "--preview", 64, "--out", output)
        assert r == json.loads(output.read_bytes())
        assert r["counts"] == reference["counts"] and r["counts"]["timestamp_regressions"] == 0
        assert all(r[k] == reference[k] for k in ["request_spacing", "reply_spacing", "valid_reply_spacing"])
        assert r["timestamp_resolution"] == "nanoseconds"
        m = r["pcapng"]
        assert m["interface_id"] == 1 and m["selection_explicit"]
        assert (m["total_packets"], m["skipped_packets"]) == (14, 2)
        assert [i["packets"] for i in m["interfaces"]] == [2, 12, 0]
        assert [i["link_type"] for i in m["interfaces"]] == [101, 1, 1]
        for expected, actual in zip(reference["preview"], r["preview"], strict=True):
            assert actual == dict(expected, packet_index=expected["packet_index"] + 2,
                                  timestamp_unix_ns=expected["timestamp_unix_ns"] - 2_000_000_000)
        empty = cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path, "--interface", 2)
        assert empty["counts"]["packets"] == 0 and empty["first_timestamp_unix_ns"] is None
        assert empty["pcapng"]["skipped_packets"] == 14
        for args in [[], ["--interface", 0], ["--interface", 3], ["--interface", 32]]:
            failed = destination / f"failed-selection-{endian == '<'}-{len(args)}-{args[-1] if args else 'auto'}.json"
            cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path, *args, "--out", failed, success=False)
            assert not failed.exists()
        preserved = output.read_bytes()
        cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path, "--interface", 1, "--out", output, success=False)
        assert output.read_bytes() == preserved and path.read_bytes() == data
        # Excluded malformed packet lengths are still rejected, rather than silently skipped.
        malformed = bytearray(other_epbs[0]); struct.pack_into(endian + "I", malformed, 24, 0)
        bad = destination / f"malformed-excluded-{endian == '<'}.pcapng"
        bad.write_bytes(shb + other_idb + selected_idb + malformed + b"".join(selected_epbs))
        failed = bad.with_suffix(".json")
        cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", bad, "--interface", 1, "--out", failed, success=False)
        assert not failed.exists()
        results.append(r)
    cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", classic_fixture, "--interface", 0, success=False)
    # Interface Statistics Blocks have split-word timestamps but scalar u64 counters.
    # Preserve declared snapshots; statistics must not change frame indexes or timing.
    def statistics(endian, interface, ticks, counters=None, start=None, end=None, extra=b""):
        opts = b""
        for code, value in [(2, start), (3, end)]:
            if value is not None:
                opts += option(endian, code, struct.pack(endian + "II", value >> 32, value & 0xffffffff))
        for code, value in (counters or {}).items():
            opts += option(endian, code, struct.pack(endian + "Q", value))
        return block(endian, 5, struct.pack(endian + "III", interface, ticks >> 32, ticks & 0xffffffff) + opts + extra)

    for endian in ("<", ">"):
        for nano in (False, True):
            unit = 1 if nano else 1000
            shb, idb, epbs = capture(endian, nano, -2, interface=1)
            other_idb = block(endian, 1, struct.pack(endian + "HHI", 101, 0, 65535) + option(endian, 14, struct.pack(endian + "q", 3)))
            first, last = records[0][0] // unit, records[-1][0] // unit
            declared = statistics(endian, 1, last + 1000, {4: (1 << 64) - 1, 5: 0, 6: (1 << 64) - 2, 7: 5, 8: 42}, first, last,
                                  option(endian, 1, b"Authored capture statistics"))
            other = statistics(endian, 0, 4_000_000, {5: 99})
            decreasing = statistics(endian, 1, first - 1, {4: 3, 5: 2}, last, first)
            empty = statistics(endian, 1, first, {})
            data = shb + other_idb + idb + other + declared + b"".join(epbs) + decreasing + empty
            path = destination / f"statistics-{'le' if endian == '<' else 'be'}-{'ns' if nano else 'us'}.pcapng"
            path.write_bytes(data)
            export = path.with_suffix(".json")
            r = cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path, "--interface", 1, "--preview", 64, "--out", export)
            assert r == json.loads(export.read_bytes()) and r["schema"] == 4
            assert r["counts"] == reference["counts"]
            assert all(r[k] == reference[k] for k in ["request_spacing", "reply_spacing", "valid_reply_spacing"])
            for expected, actual in zip(reference["preview"], r["preview"], strict=True):
                assert actual == dict(expected, timestamp_unix_ns=expected["timestamp_unix_ns"] - 2_000_000_000)
            m = r["pcapng"]; stats = m["statistics"]
            assert m["total_packets"] == 12 and m["skipped_packets"] == m["skipped_blocks"] == 0 and m["skipped_options"] == 1
            assert len(stats) == 4 and [s["block_index"] for s in stats] == [4, 5, 18, 19]
            assert [s["interface_id"] for s in stats] == [0, 1, 1, 1]
            assert stats[0]["timestamp_unix_ns"] == 7_000_000_000 and stats[0]["interface_dropped"] == 99
            assert stats[1] == dict(block_index=5, interface_id=1, timestamp_unix_ns=(last + 1000) * unit - 2_000_000_000,
                                   start_timestamp_unix_ns=first * unit - 2_000_000_000, end_timestamp_unix_ns=last * unit - 2_000_000_000,
                                   received=(1 << 64) - 1, interface_dropped=0, filter_accepted=(1 << 64) - 2, os_dropped=5, user_delivered=42, notes=[])
            assert stats[2]["received"] == 3 and stats[2]["interface_dropped"] == 2 and stats[2]["os_dropped"] is None
            assert "end precedes" in stats[2]["notes"][0]
            assert all(stats[3][k] is None for k in ["start_timestamp_unix_ns", "end_timestamp_unix_ns", "received", "interface_dropped", "filter_accepted", "os_dropped", "user_delivered"])
            original_export = export.read_bytes()
            cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path, "--interface", 1, "--out", export, success=False)
            assert export.read_bytes() == original_export and path.read_bytes() == data
            # A structurally valid, inconsistent range is retained with a note; malformed
            # statistics fail, including records belonging to an excluded interface.
            bad_stats = {"short-header": block(endian, 5, bytes(8)), "missing-interface": statistics(endian, 2, 1),
                         "header-time-range": statistics(endian, 0, (1 << 64) - 1)}
            for code in range(2, 9):
                bad_stats[f"wrong-size-{code}"] = statistics(endian, 0, 1, extra=option(endian, code, bytes(7)))
                bad_stats[f"duplicate-{code}"] = statistics(endian, 0, 1, extra=option(endian, code, bytes(8)) * 2)
            for code in (2, 3):
                bad_stats[f"option-time-range-{code}"] = statistics(endian, 0, 1, extra=option(endian, code, struct.pack(endian + "II", 0xffffffff, 0xffffffff)))
            for label, bad_record in bad_stats.items():
                bad = destination / f"statistics-bad-{endian == '<'}-{nano}-{label}.pcapng"
                bad.write_bytes(shb + other_idb + idb + bad_record + b"".join(epbs))
                failed = bad.with_suffix(".json")
                cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", bad, "--interface", 1, "--out", failed, success=False)
                assert not failed.exists()
            results.append(r)
    shb, idb, _ = capture(selected=[])
    snapshots = statistics("<", 0, 1) * 128
    path = destination / "statistics-bound.pcapng"; path.write_bytes(shb + idb + snapshots)
    r = cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path)
    assert len(r["pcapng"]["statistics"]) == 128 and r["counts"]["packets"] == 0 and r["first_timestamp_unix_ns"] is None
    path = destination / "statistics-over-bound.pcapng"; path.write_bytes(shb + idb + snapshots + statistics("<", 0, 1))
    cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path, success=False)
    path = destination / "statistics-before-descriptor.pcapng"; path.write_bytes(shb + statistics("<", 0, 1) + idb)
    cli_call(cli, "inspect-pcap", ROOT / "samples/synthetic.json", path, success=False)
    (destination / "inspection-reports.json").write_text(json.dumps(results, indent=2), encoding="utf-8")


def verify_output_staging(cli, destination):
    sample = ROOT / "samples/output-staging.json"
    original_bytes = sample.read_bytes()
    baseline = cli_call(cli, "validate", sample)
    changes = ["0=true", "1=5", "2=-1234", "3=1.5", "4=0x11223344", "5=CA FE BA BE", "7=0.5"]
    arguments = [value for change in changes for value in ("--set", change)]
    preview = cli_call(cli, "stage-rx", sample, *arguments)
    assert preview["schema"] == 1 and preview["scope"] == "offline_rxpdo_only"
    assert preview["value_source"] == "manual_offline" and preview["rx_bytes"] == 24 and preview["expected_identity"] is None
    expected_hex = "AB5A2EFB3FC0000033441122CAFEBABE000000000000E03F"
    assert preview["after_hex"] == expected_hex and not preview["initialized_from_zero"]
    alias = next(i for i in preview["impacts"] if i["field"] == 6)
    assert not alias["selected"] and alias["bits_changed"] and alias["before"] == "A0" and alias["after"] == "AB"
    expected_values = {0:"true",1:"5",2:"-1234",3:"1.5",4:"287454020",5:"CAFEBABE",6:"AB",7:"0.5"}
    assert {i["field"]:i["after"] for i in preview["impacts"]} == expected_values
    saved = destination / "staged.json"
    saved_preview = cli_call(cli, "stage-rx", sample, *arguments, "--out", saved)
    assert saved_preview == preview
    staged = cli_call(cli, "validate", saved)
    assert staged == dict(baseline, staged_rx_hex=expected_hex)
    decoded = cli_call(cli, "decode", saved, expected_hex, "--rx")
    assert [i["value"] for i in decoded] == [expected_values[i] for i in range(8)]
    protected = saved.read_bytes()
    cli_call(cli, "stage-rx", sample, *arguments, "--out", saved, success=False)
    assert saved.read_bytes() == protected and sample.read_bytes() == original_bytes
    for index, bad in enumerate([[], ["0=false","6=FF"], ["0=true","0=true"], ["1=8"], ["2=-32769"],
        ["3=NaN"], ["7=inf"], ["5=00"], ["99=1"], ["-1=0"], ["missing equals"]]):
        path = destination / f"bad-{index}.json"
        args = [item for change in bad for item in ("--set", change)]
        cli_call(cli, "stage-rx", sample, *args, "--out", path, success=False)
        assert not path.exists()
    agreeing = cli_call(cli, "stage-rx", sample, "--set", "0=true", "--set", "6=A1")
    assert agreeing["after_hex"].startswith("A15A")
    blank = destination / "blank.json"
    blank.write_text(json.dumps(dict(baseline, staged_rx_hex="")), encoding="utf-8")
    cli_call(cli, "stage-rx", blank, "--set", "0=true", success=False)
    initialized = cli_call(cli, "stage-rx", blank, "--set", "0=true", "--zero")
    assert initialized["initialized_from_zero"] and initialized["before_hex"] == "00" * 24
    assert initialized["after_hex"] == "01" + "00" * 23
    cli_call(cli, "stage-rx", sample, "--set", "0=true", "--zero", success=False)
    esi = destination / "esi.json"
    cli_call(cli, "esi-import", ROOT / "samples/synthetic.esi.xml", "--device", 0, "--out", esi)
    esi_original = cli_call(cli, "validate", esi)
    esi_saved = destination / "esi-staged.json"
    esi_preview = cli_call(cli, "stage-rx", esi, "--set", "0=-123", "--zero", "--out", esi_saved)
    assert esi_preview["after_hex"] == "85FF" and esi_preview["impacts"][0]["mapping_source"] == "esi"
    assert esi_preview["expected_identity"] == esi_original["expected_identity"] and esi_preview["value_source"] == "manual_offline"
    assert cli_call(cli, "validate", esi_saved) == dict(esi_original, staged_rx_hex="85FF")
    (destination / "preview.json").write_text(json.dumps(preview, indent=2), encoding="utf-8")


def verify_http(cli, destination):
    def fetch(port, target, method="GET"):
        client = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        try:
            client.request(method, target)
            response = client.getresponse()
            data = response.read()
            assert response.getheader("Cache-Control") == "no-store"
            assert len(data) == int(response.getheader("Content-Length")) <= 2 * 1024 * 1024
            return response.status, json.loads(data)
        finally:
            client.close()

    reports = []
    streams = []
    observed = []
    for schedule in ("deadline", "relative"):
        case = destination / schedule
        profile = json.loads((ROOT / "samples/synthetic.json").read_text(encoding="utf-8"))
        profile["http"] = dict(port=0, queue_capacity=2, history_capacity=8, freshness_ms=20)
        # Non-logged fields must still be exported by the read-only interface.
        profile["tx"][2]["log"] = False
        saved = case.with_suffix(".profile.json")
        saved.write_text(json.dumps(profile), encoding="utf-8")
        report = case.with_suffix(".json")
        base = case.with_suffix(".csv")
        stdout = case.with_suffix(".stdout.json")
        stderr = case.with_suffix(".stderr.txt")
        with stdout.open("wb") as output, stderr.open("wb") as errors:
            proc = subprocess.Popen([str(cli), "run", str(saved), "--seconds", "2", "--scheduler", schedule,
                "--simulate-faults", "--input-loss-timeout-ms", "0", "--csv", str(base), "--report", str(report)],
                stdout=output, stderr=errors)
            try:
                deadline = time.monotonic() + 6
                port = None
                while port is None:
                    text = stderr.read_text(encoding="utf-8")
                    import re
                    match = re.search(r"HTTP input feed bound at http://127\.0\.0\.1:(\d+)", text)
                    if match:
                        port = int(match.group(1)); break
                    assert proc.poll() is None and time.monotonic() < deadline, text
                    time.sleep(.01)
                status, metadata = fetch(port, "/v1/metadata")
                assert status == 200 and metadata["schema"] == 1
                assert metadata["data"]["backend"] == "Synthetic fixture" and metadata["data"]["tx_bytes"] == 8
                assert len(metadata["data"]["fields"]) == 3
                streams.append(metadata["stream_id"])
                # Hold incomplete requests past the header deadline. This must not stop cyclic I/O or CSV.
                for _ in range(3):
                    stalled = socket.create_connection(("127.0.0.1", port), timeout=1)
                    stalled.sendall(b"GET /v1/status HTTP/1.1\r\n")
                    time.sleep(.04)
                    stalled.close()
                assert fetch(port, "/v1/latest", "POST")[0] == 405
                assert fetch(port, "/outputs")[0] == 404
                assert fetch(port, "/v1/samples?limit=65")[0] == 400
                cursor = 0
                while proc.poll() is None:
                    try:
                        code, result = fetch(port, f"/v1/samples?after={cursor}&limit=64")
                        if code != 200: break
                        assert result["stream_id"] == streams[-1]
                        for sample in result["data"]["samples"]:
                            assert sample["event_index"] > cursor
                            cursor = sample["event_index"]
                            if sample["valid"]:
                                payload = bytes.fromhex(sample["payload_hex"])
                                count = int.from_bytes(payload[:2], "little")
                                assert sample["values"]["Counter"] == str(count)
                                assert sample["values"]["Scaled counter"] == str(count / 4).removesuffix(".0")
                            else:
                                assert sample["payload_hex"] is None and sample["values"] is None
                        observed.append(result)
                    except (OSError, http.client.HTTPException):
                        if proc.poll() is None: time.sleep(.005)
                        else: break
                    time.sleep(.005)
                proc.wait(timeout=5)
            finally:
                if proc.poll() is None:
                    proc.kill(); proc.wait()
        assert proc.returncode == 0, stderr.read_text(encoding="utf-8")
        r = json.loads(report.read_text(encoding="utf-8"))
        feed = r["http"]
        assert feed["offered"] == r["cycles"] == feed["dispatched"] + feed["queue_drops"]
        assert not feed["active"] and not feed["worker_failed"] and feed["pending"] == 0 and feed["worker_error"] is None
        assert feed["queue_drops"] > 0 and feed["history_evictions"] > 0 and feed["io_errors"] > 0 and feed["rejected_requests"] >= 3
        assert r["capture"]["overruns"] == 0 and r["capture"]["written"] == r["valid"]
        parts, entries = rows(base)
        assert len(entries) == r["valid"] and len(parts) == r["capture"]["parts"]
        assert all("Scaled counter" not in row for row in entries)
        audit = cli_call(cli, "verify-capture", report, base)
        assert audit["rows"] == r["valid"]
        reports.append(r)
    assert streams[0] != streams[1] and observed
    comparison = cli_call(cli, "compare-runs", destination / "deadline.json", destination / "relative.json",
        "--csv", destination / "deadline.csv", "--csv", destination / "relative.csv")
    assert all(trial["http"]["queue_drops"] > 0 for trial in comparison["trials"])
    assert any("HTTP feed loss" in warning for warning in comparison["warnings"])
    (destination / "comparison.json").write_text(json.dumps(comparison, indent=2), encoding="utf-8")
    (destination / "observed.json").write_text(json.dumps(observed, indent=2), encoding="utf-8")
    # Sustained invalid virtual input must retain only an explicitly historical last-good payload.
    case = destination / "lost"
    lost_profile = json.loads((ROOT / "samples/virtual.json").read_text(encoding="utf-8"))
    lost_profile["http"] = dict(port=0, queue_capacity=128, history_capacity=16, freshness_ms=20)
    lost_file = case.with_suffix(".profile.json")
    lost_file.write_text(json.dumps(lost_profile), encoding="utf-8")
    lost_out = case.with_suffix(".stdout.json");lost_err = case.with_suffix(".stderr.txt")
    invalid_seen = False
    with lost_out.open("wb") as output, lost_err.open("wb") as errors:
        proc = subprocess.Popen([str(cli), "run", str(lost_file), "--backend", "virtual", "--virtual-fault", "io-lost",
            "--seconds", "1", "--input-loss-timeout-ms", "0", "--csv", str(case.with_suffix(".csv")),
            "--report", str(case.with_suffix(".json"))], stdout=output, stderr=errors)
        try:
            until = time.monotonic()+6
            while proc.poll() is None and time.monotonic()<until:
                import re
                match = re.search(r"HTTP input feed bound at http://127\.0\.0\.1:(\d+)",lost_err.read_text(encoding="utf-8"))
                if match:
                    try:
                        _, value = fetch(int(match.group(1)),"/v1/latest")
                        latest = value["data"]["latest"]
                        if latest and not latest["valid"]:
                            assert not value["fresh"] and latest["payload_hex"] is None and latest["values"] is None
                            assert latest["actual_wkc"] is None and latest["al_status"] is None
                            assert value["data"]["last_valid"] is not None
                            invalid_seen=True
                    except (OSError,http.client.HTTPException): pass
                time.sleep(.01)
            proc.wait(timeout=5)
        finally:
            if proc.poll() is None:proc.kill();proc.wait()
    assert proc.returncode==0 and invalid_seen,lost_err.read_text(encoding="utf-8")
    lost=json.loads(case.with_suffix(".json").read_text(encoding="utf-8"))
    assert lost["timeouts"]>0 and lost["http"]["offered"]==lost["cycles"] and lost["capture"]["overruns"]==0
    assert lost["stopped_al"]==[1,0]
    assert all(lost["virtual_esc"][key]==0 for key in ["logical_writes","physical_output_writes","coe_downloads","op_requests","dc_enable_requests"])
    cli_call(cli,"verify-capture",case.with_suffix(".json"),case.with_suffix(".csv"))
    return reports


def verify_coe_cycle(cli, destination):
    """Setup-only cycle diagnostics; optional aborts differ from malformed values."""
    expected = dict(tx=dict(object_index=0x1c33, cycle_ns=dict(value=2_000_000, unavailable=None), minimum_cycle_ns=dict(value=0, unavailable=None)),
                    rx=dict(object_index=0x1c32, cycle_ns=dict(value=1_000_000, unavailable=None), minimum_cycle_ns=dict(value=250_000, unavailable=None)))
    results = []
    for model, sample in [("coe", "virtual.json"), ("coe-normal", "virtual-normal.json"), ("coe-segmented", "virtual-segmented.json")]:
        for fault in [None, "sync-timing-unavailable", "sync-timing-size"]:
            base = destination / f"{model}-{fault or 'complete'}"
            flags = ["--virtual-fault", fault] if fault else []
            good = fault != "sync-timing-size"
            r = cli_call(cli, "run", ROOT / "samples" / sample, "--backend", "virtual", "--virtual-model", model,
                         *flags, "--seconds", 1, "--csv", base.with_suffix(".csv"), "--report", base.with_suffix(".json"), success=good)
            # Failed setup still preserves a structured receipt at its reserved report path.
            if not good:
                r = json.loads(base.with_suffix(".json").read_bytes())
            assert r["stopped_al"] == [1, 0]
            values = r["synchronization"]["coe_cycle"]
            assert r["requested_cycle_us"] == 1000
            if not fault:
                assert values == expected and r["valid"] > 100 and r["error"] is None
                assert values["tx"]["cycle_ns"]["value"] != r["requested_cycle_us"] * 1000
                assert "CoE setup ns" in r["device_sync"]
            elif good:
                assert r["error"] is None and r["valid"] > 100
                for direction in ["tx", "rx"]:
                    for field in ["cycle_ns", "minimum_cycle_ns"]:
                        assert values[direction][field]["value"] is None
                        assert "aborted" in values[direction][field]["unavailable"]
            else:
                assert r["cycles"] == 0 and r["error"] and r["virtual_esc"]["state_requests"] == [1, 2, 1]
                assert values["tx"]["cycle_ns"]["value"] is None and values["tx"]["cycle_ns"]["unavailable"]
            assert all(r["virtual_esc"][k] == 0 for k in ["op_requests", "logical_writes", "physical_output_writes", "coe_downloads", "dc_enable_requests", "dc_clock_distribution"])
            if good:
                audit_capture(cli, base.with_suffix(".json"), base.with_suffix(".csv"), r)
            results.append(r)
    # Longer acquisition must not cause more mailbox uploads; snapshots are setup observations.
    extended = cli_call(cli, "run", ROOT / "samples/virtual.json", "--backend", "virtual", "--seconds", 2)
    assert extended["virtual_esc"]["coe_uploads"] == results[0]["virtual_esc"]["coe_uploads"]
    assert extended["synchronization"]["coe_cycle"] == expected
    # Old saved timing metadata remains usable without inventing current cycle values.
    path = destination / "older-no-coe-cycle.json"
    staged = destination / "staged-mode.json"
    cli_call(cli, "esi-import", ROOT / "samples/mode-sync-managers.esi.xml", "--device", 0, "--dc-mode", 0, "--out", staged)
    # The authored mode fixture has DC identity 3; use the matching identity from a DC model.
    dc = cli_call(cli, "run", ROOT / "samples/virtual-dc.json", "--backend", "virtual", "--virtual-model", "coe-dc", "--seconds", 1)
    dc["synchronization"].pop("coe_cycle"); path.write_text(json.dumps(dc), encoding="utf-8")
    reviewed = cli_call(cli, "review-sync", staged, "--readback", path)
    assert reviewed["applied"] is False and all(s["sync_type"]["state"] == "matched" for s in reviewed["sync_managers"])
    (destination / "coe-cycle-checks.json").write_text(json.dumps(results, indent=2), encoding="utf-8")


def verify_initializer_compatibility(cli, destination):
    """Legal non-expedited PDO replies before Workbench's own uploader can be used."""
    results = {}
    for fault, form in [("init-normal-upload", "normal"), ("init-segmented-upload", "segmented_initiation")]:
        report_path = destination / f"{fault}.json"
        csv_path = destination / f"{fault}.csv"
        cli_call(cli, "run", ROOT / "samples/virtual.json", "--backend", "virtual", "--virtual-fault", fault,
                 "--seconds", 1, "--report", report_path, "--csv", csv_path, success=False)
        r = json.loads(report_path.read_bytes())
        assert r["error"] and "configure FMMU/SyncManagers" in r["error"]
        assert r["cycles"] == r["valid"] == r["replies"] == 0
        assert r["stopped_al"] == [1, 0] and r["synchronization"] is None
        audit = r["virtual_esc"]
        assert audit["initial_mapping_upload"] == dict(object_index=0x1c13, subindex=0, declared_bytes=1, form=form)
        assert audit["state_requests"] == [1, 2, 1] and audit["coe_segments"] == 0
        assert audit["coe_normal_uploads"] == (1 if form == "normal" else 0)
        assert audit["coe_segmented_uploads"] == (1 if form == "segmented_initiation" else 0)
        assert all(audit[k] == 0 for k in ["logical_reads", "logical_writes", "physical_output_writes", "coe_downloads", "op_requests", "dc_enable_requests", "dc_clock_distribution"])
        assert not csv_path.exists() and r["capture"] is None
        assert r["context"]["source"]["kind"] == "virtual"
        results[fault] = r
    for model, profile in [("coe", "virtual.json"), ("sii", "virtual-sii.json")]:
        flags = ["--virtual-fault", "init-normal-upload"] if model == "sii" else []
        r = cli_call(cli, "run", ROOT / "samples" / profile, "--backend", "virtual", "--virtual-model", model, *flags, "--seconds", 1)
        assert r["error"] is None and r["valid"] > 100 and r["stopped_al"] == [1, 0]
        assert r["virtual_esc"].get("initial_mapping_upload") is None
        if model == "sii":
            assert r["virtual_esc"]["coe_uploads"] == 0
        results[model + "-control"] = r
    (destination / "initializer-compatibility.json").write_text(json.dumps(results, indent=2), encoding="utf-8")


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("bin_dir", type=Path)
    args.add_argument("destination", type=Path, help="new directory under .local")
    args.add_argument("--gui", action="store_true")
    args.add_argument("--gui-seconds", type=int, default=5)
    args.add_argument("--gui-trials", type=int, default=1)
    options = args.parse_args()
    bin_dir = options.bin_dir.resolve()
    destination = options.destination.resolve()
    assert ".local" in destination.parts, "keep synthetic captures under .local"
    destination.mkdir(parents=True, exist_ok=False)
    cli = bin_dir / "ethercat-workbench-cli.exe"
    initializer_destination = destination / "initializer-compatibility"
    initializer_destination.mkdir()
    verify_initializer_compatibility(cli, initializer_destination)
    cycle_destination = destination / "coe-cycle"
    cycle_destination.mkdir()
    verify_coe_cycle(cli, cycle_destination)
    shared_destination = destination / "shared-memory"
    shared_destination.mkdir()
    verify_shared_memory(cli, ROOT, shared_destination, cli_call)
    mqtt_destination = destination / "mqtt"
    mqtt_destination.mkdir()
    verify_mqtt(cli, ROOT, mqtt_destination, cli_call)
    profile = ROOT / "samples/synthetic.json"
    http_destination = destination / "http"
    http_destination.mkdir()
    verify_http(cli, http_destination)
    staging_destination = destination / "output-staging"
    staging_destination.mkdir()
    verify_output_staging(cli, staging_destination)
    rehearsal_destination = destination / "output-rehearsal"
    rehearsal_destination.mkdir()
    verify_output_rehearsal(cli, rehearsal_destination)
    output_plan_destination = destination / "output-plan"
    output_plan_destination.mkdir()
    verify_output_plan(cli, output_plan_destination)
    output_timing_destination = destination / "output-timing"
    output_timing_destination.mkdir()
    verify_output_timing(cli, output_timing_destination)
    dc_rehearsal_destination = destination / "dc-rehearsal"
    dc_rehearsal_destination.mkdir()
    verify_dc_rehearsal(cli, dc_rehearsal_destination)
    dc_esi_destination = destination / "dc-esi-rehearsal"
    dc_esi_destination.mkdir()
    verify_dc_esi_modes(cli, dc_esi_destination)
    pcap_destination = destination / "pcap"
    pcap_destination.mkdir()
    verify_pcap(cli, pcap_destination)
    pcapng_destination = destination / "pcapng"
    pcapng_destination.mkdir()
    verify_pcapng(cli, pcapng_destination, pcap_destination / "authored-le-us.pcap")
    esi = ROOT / "samples/synthetic.esi.xml"
    legacy = json.loads(profile.read_text(encoding="utf-8"))
    legacy.pop("input_loss_timeout_ms", None)
    legacy_path = destination / "legacy-profile.json"
    legacy_path.write_text(json.dumps(legacy), encoding="utf-8")
    assert cli_call(cli, "validate", legacy_path)["input_loss_timeout_ms"] == 1000
    legacy["input_loss_timeout_ms"] = 60001
    bad_limit = destination / "bad-loss-limit.json"
    bad_limit.write_text(json.dumps(legacy), encoding="utf-8")
    assert "input loss timeout" in cli_call(cli, "validate", bad_limit, success=False)

    listing = cli_call(cli, "esi-list", esi)
    assert [entry["source"]["identity"]["revision"] for entry in listing] == [1, 2]
    assert listing[0]["source"]["sha256"] == hashlib.sha256(esi.read_bytes()).hexdigest()
    assert listing[0]["tx_bytes"] == 8 and listing[0]["rx_bytes"] == 2
    assert "omitted" in listing[0]["notes"][0]
    utf16 = destination / "synthetic-utf16.xml"
    utf16.write_text(esi.read_text(encoding="utf-8").replace("UTF-8", "UTF-16"), encoding="utf-16")
    assert len(cli_call(cli, "esi-list", utf16)) == 2
    imported = destination / "imported.json"
    cli_call(cli, "esi-import", esi, "--device", 0, "--out", imported)
    saved = cli_call(cli, "validate", imported)
    assert [f["bit"] for f in saved["tx"]] == [0, 16, 32]
    assert all(f["source"] == "esi" for f in saved["tx"] + saved["rx"])
    readback = ROOT / "samples/synthetic-pdo.json"
    verified = cli_call(cli, "verify-pdo", imported, readback)
    assert all(field["state"] == "matched" for d in ("tx", "rx") for field in verified[d]["fields"])
    reordered = destination / "reordered-pdo.json"
    mismatch = json.loads(readback.read_text(encoding="utf-8"))
    entries = mismatch["tx"]["sync_managers"][0]["pdos"][0]["entries"]
    entries[0], entries[3] = entries[3], entries[0]
    reordered.write_text(json.dumps(mismatch), encoding="utf-8")
    rejected = cli_call(cli, "verify-pdo", imported, reordered, success=False)
    assert rejected["tx"]["image_bytes"] == 8 and rejected["tx"]["errors"]
    manual = cli_call(cli, "verify-pdo", profile, readback)
    assert all(field["state"] == "manual" for d in ("tx", "rx") for field in manual[d]["fields"])
    assert cli_call(cli, "decode", profile, "FE FF", "--rx")[0]["value"] == "-2"
    assert [v["value"] for v in cli_call(cli, "decode", imported, "04 00 00 00 00 00 80 3F")] == ["4", "false", "1"]
    denied = cli_call(cli, "run", profile, "--backend", "safeop", success=False)
    assert "requires approval" in denied

    reports = {}
    discovery_destination = destination / "discovery"
    discovery_destination.mkdir()
    verify_discovery(cli, discovery_destination)
    group_destination = destination / "input-group"
    group_destination.mkdir()
    verify_input_group(cli, group_destination)
    frame_destination = destination / "input-group-frame"
    frame_destination.mkdir()
    verify_input_group_frame(cli, frame_destination)
    fmmu_destination = destination / "input-group-fmmu"
    fmmu_destination.mkdir()
    verify_input_group_fmmu(cli, fmmu_destination)
    sm_destination = destination / "input-group-sync-managers"
    sm_destination.mkdir()
    verify_input_group_sync_managers(cli, sm_destination)
    pdo_destination = destination / "input-group-pdo"
    pdo_destination.mkdir()
    verify_input_group_pdo(cli, pdo_destination)
    replay_group_destination = destination / "input-group-replay"
    replay_group_destination.mkdir()
    verify_input_group_replay(cli, replay_group_destination)
    group_bundle_destination = destination / "input-group-bundle"
    group_bundle_destination.mkdir()
    verify_group_replay_bundle(cli, group_bundle_destination)
    generated_group_destination = destination / "input-group-generated"
    generated_group_destination.mkdir()
    verify_generated_group_replay(cli, generated_group_destination)
    group_topology_replay_destination = destination / "input-group-topology-replay"
    group_topology_replay_destination.mkdir()
    verify_replay_setup_topology(cli, group_topology_replay_destination)
    cyclic_topology_destination = destination / "input-group-cyclic-topology"
    cyclic_topology_destination.mkdir()
    verify_cyclic_topology_guard(cli, cyclic_topology_destination)
    three_station_destination = destination / "input-group-three-stations"
    three_station_destination.mkdir()
    verify_three_station_group(cli, three_station_destination)
    virtual_group_mapping_destination = destination / "input-group-virtual-mapping"
    virtual_group_mapping_destination.mkdir()
    verify_virtual_group_mapping(cli, virtual_group_mapping_destination)
    virtual_group_pdo_destination = destination / "virtual-group-pdo"
    virtual_group_pdo_destination.mkdir()
    verify_virtual_group_pdo_readback(cli, virtual_group_pdo_destination)
    recorded_setup_pdo_destination = destination / "recorded-setup-pdo"
    recorded_setup_pdo_destination.mkdir()
    verify_group_pdo_against_recorded_setup(cli, recorded_setup_pdo_destination)
    group_dc_destination = destination / "input-group-dc"
    group_dc_destination.mkdir()
    verify_group_dc(cli, group_dc_destination)
    group_dc_replay_destination = destination / "input-group-dc-replay"
    group_dc_replay_destination.mkdir()
    verify_group_dc_replay(cli, group_dc_replay_destination)
    group_dc_three_destination = destination / "input-group-dc-three"
    group_dc_three_destination.mkdir()
    verify_three_station_group_dc(cli, group_dc_three_destination)
    clock_topology_destination = destination / "group-clock-topology"
    clock_topology_destination.mkdir()
    verify_clock_and_topology(cli, clock_topology_destination)
    clock_reconnect_destination = destination / "group-clock-reconnect"
    clock_reconnect_destination.mkdir()
    verify_clock_reconnect(cli, clock_reconnect_destination)
    for scheduler, flags, generation in [
        ("deadline", ["--simulate-faults"], 3),
        ("relative", ["--on-change"], 4),
    ]:
        base = destination / f"{scheduler}.csv"
        report = cli_call(cli, "run", profile, "--seconds", 3, "--csv", base,
                          "--scheduler", scheduler, "--generation", generation, *flags)
        verify_csv(report, base, generation, change="--on-change" in flags, faults="--simulate-faults" in flags)
        reports[scheduler] = report

    fixture = ROOT / "samples/synthetic-replay.json"
    collision = destination / "collision.0002.csv"
    collision.write_bytes(b"preserve existing part\n")
    collision_profile = destination / "collision-profile.json"
    collision_profile.write_text(
        json.dumps({**json.loads(profile.read_bytes()), "rotate_rows": 2}), encoding="utf-8",
    )
    report = cli_call(cli, "run", collision_profile, "--backend", "replay", "--replay", fixture,
                      "--seconds", 10, "--csv", destination / "collision.csv", success=False)
    assert collision.read_bytes() == b"preserve existing part\n"
    assert report["capture"]["written"] == 2 and "CSV capture incomplete" in report["error"]

    for on_change in (False, True):
        case = destination / ("replay-change.csv" if on_change else "replay-every.csv")
        flags = ["--on-change"] if on_change else []
        replay = cli_call(cli, "run", profile, "--backend", "replay", "--replay", fixture,
                          "--seconds", 2, "--csv", case, *flags)
        assert replay["replay_exchanges"] == replay["cycles"] == 12
        assert replay["valid"] == 6 and replay["replies"] == 10
        assert replay["wkc_mismatches"] == 1 and replay["state_mismatches"] == 3
        assert replay["timeouts"] == 2 and replay["ignored_frames"] == 6
        assert replay["error"] is None and replay["stopped_al"] is None
        _, replay_rows = rows(case)
        expected = [4, 6, 7, 8] if on_change else [4, 4, 6, 6, 7, 8]
        assert [int(row["Counter"]) for row in replay_rows] == expected
        assert [int(row["sample_index"]) for row in replay_rows] == list(range(1, len(expected) + 1))
        assert replay["capture"]["written"] == len(expected) and replay["capture"]["overruns"] == 0
        for row in replay_rows:
            counter = int(row["Counter"])
            assert row["Sensor active"] == str(bool(counter & 1)).lower()
            assert float(row["Scaled counter"]) == counter / 4
        reports["replay-change" if on_change else "replay-every"] = replay

    bad_request = json.loads(fixture.read_text(encoding="utf-8"))
    request = bytearray.fromhex(bad_request["exchanges"][0]["request_hex"])
    request[16] = 0x0c
    bad_request["exchanges"][0]["request_hex"] = request.hex()
    invalid_fixture = destination / "write-request.json"
    invalid_fixture.write_text(json.dumps(bad_request), encoding="utf-8")
    rejected = cli_call(cli, "run", profile, "--backend", "replay", "--replay", invalid_fixture,
                        "--seconds", 2, success=False)
    assert "differs from the LRD/AL read path" in rejected["error"]
    assert rejected["cycles"] == 0 and rejected["capture"] is None

    invalid_data = json.loads(fixture.read_text(encoding="utf-8"))
    invalid_data["exchanges"] = [invalid_data["exchanges"][2]]
    no_valid = destination / "no-valid-pdo.json"
    no_valid.write_text(json.dumps(invalid_data), encoding="utf-8")
    rejected = cli_call(cli, "run", profile, "--backend", "replay", "--replay", no_valid,
                        "--seconds", 2, success=False)
    assert rejected["cycles"] == 1 and rejected["wkc_mismatches"] == 1
    assert rejected["valid"] == 0 and "no valid SAFEOP" in rejected["error"]

    limited = json.loads(fixture.read_text(encoding="utf-8"))
    limited["exchanges"] = [limited["exchanges"][0]] * 1200
    limited_fixture = destination / "duration-limit.json"
    limited_fixture.write_text(json.dumps(limited), encoding="utf-8")
    rejected = cli_call(cli, "run", profile, "--backend", "replay", "--replay", limited_fixture,
                        "--seconds", 1, success=False)
    assert rejected["cycles"] < 1200 and "duration expired" in rejected["error"]

    unavailable = destination / "unavailable-pdo.json"
    unavailable.write_text(json.dumps({"tx": None, "rx": None}), encoding="utf-8")
    unknown = cli_call(cli, "verify-pdo", imported, unavailable)
    assert unknown["tx"]["unavailable"] and all(f["state"] == "unavailable" for f in unknown["tx"]["fields"])

    verify_virtual(cli, ROOT / "samples/virtual.json", destination, reports)
    verify_input_loss(cli, ROOT / "samples/virtual.json", destination)
    sii_destination = destination / "sii"
    sii_destination.mkdir()
    verify_virtual(cli, ROOT / "samples/virtual-sii.json", sii_destination, reports, model="sii")
    verify_input_loss(cli, ROOT / "samples/virtual-sii.json", sii_destination, model="sii")
    dc_destination = destination / "dc"
    dc_destination.mkdir()
    verify_virtual(cli, ROOT / "samples/virtual-dc.json", dc_destination, reports, model="coe-dc")
    verify_input_loss(cli, ROOT / "samples/virtual-dc.json", dc_destination, model="coe-dc")

    coe_destination = destination / "coe-uploads"
    coe_destination.mkdir()
    verify_coe_uploads(cli, coe_destination, reports)

    sync_destination = destination / "sync-modes"
    sync_destination.mkdir()
    verify_sync_modes(cli, sync_destination)
    identity_destination = destination / "esi-identity"
    identity_destination.mkdir()
    verify_esi_identity(cli, identity_destination)
    runtime_destination = destination / "runtime-check"
    runtime_destination.mkdir()
    verify_runtime_check(cli, runtime_destination)
    mode_destination = destination / "mode-pdo-staging"
    mode_destination.mkdir()
    verify_mode_pdo_staging(cli, mode_destination)
    pdo_destination = destination / "pdo-choices"
    pdo_destination.mkdir()
    verify_pdo_choices(cli, pdo_destination)

    comparison_destination = destination / "comparison"
    comparison_destination.mkdir()
    verify_valid_spacing_boundaries(cli, comparison_destination)
    verify_comparison(cli, comparison_destination)
    audit_destination = destination / "capture-audit"
    audit_destination.mkdir()
    verify_capture_audit(cli, audit_destination, comparison_destination)

    if options.gui:
        assert os.name == "nt"
        assert options.gui_trials > 0
        for i in range(options.gui_trials):
            trial = destination / f"trial-{i + 1}"
            trial.mkdir()
            schedulers = ("deadline", "relative") if i % 2 == 0 else ("relative", "deadline")
            for scheduler in schedulers:
                reports[f"gui-{scheduler}-{i + 1}"] = gui_trial(bin_dir / "ethercat-workbench.exe",
                    profile, trial, scheduler, options.gui_seconds)
    (destination / "reports.json").write_text(json.dumps(reports, indent=2), encoding="utf-8")
    for label, report in reports.items():
        print(f"{label}  {report['cycles']} cycles  {report['capture']['written']} rows"
              f"  missed {report['missed_deadlines']}  send {report['send_spacing']}"
              f"  receive {report['receive_spacing']}")


if __name__ == "__main__":
    main()
