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
    assert report["requested_cycle_us"] == 1000
    parts, entries = rows(base)
    cap = report["capture"]
    assert len(parts) == cap["parts"]
    assert cap["overruns"] == 0
    assert len(entries) == cap["written"] == cap["selected"] > 0
    times = [int(r["elapsed_us"]) for r in entries]
    assert all(a <= b for a, b in zip(times, times[1:]))
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
        else:
            assert sync["tx_sync_type"] is sync["rx_sync_type"] is None
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
    (destination / "sync-checks.json").write_text(json.dumps({"preview": preview, "compared": compared, "matched": matched}, indent=2), encoding="utf-8")


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
        assert row["capture"] == original["capture"] and row["cyclic_elapsed_us"] == original["cyclic_elapsed_us"]
    for group in result["schedules"]:
        p99 = sorted(r["receive_spacing"]["p99_us"] for r in trials if r["scheduler"] == group["scheduler"])
        assert group["receive_p99_us"] == {"min": p99[0], "median": p99[1], "max": p99[2]}
    assert any("Offline fixture" in w for w in result["warnings"])
    assert any("CSV bytes" in w for w in result["warnings"])
    assert not any("fewer than three" in w for w in result["warnings"])
    (destination / "comparison.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    for index, path in enumerate(paths):
        audit_capture(cli, path, destination / f"trial-{index}.csv", trials[index])
    audited = cli_call(cli, "compare-runs", paths[0], paths[1],
        "--csv", destination / "trial-0.csv", "--csv", destination / "trial-1.csv")
    assert len(audited["csv_audits"]) == 2 and all(r["rows"] > 0 for r in audited["csv_audits"])
    assert not any("CSV bytes and field values are not inspected" in w for w in audited["warnings"])
    assert "one --csv base per report" in cli_call(cli, "compare-runs", paths[0], paths[1],
        "--csv", destination / "trial-0.csv", success=False)
    (destination / "audited-comparison.json").write_text(json.dumps(audited, indent=2), encoding="utf-8")
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
    for scheduler, flags, generation in [
        ("deadline", ["--simulate-faults"], 3),
        ("relative", ["--on-change"], 4),
    ]:
        base = destination / f"{scheduler}.csv"
        report = cli_call(cli, "run", profile, "--seconds", 3, "--csv", base,
                          "--scheduler", scheduler, "--generation", generation, *flags)
        verify_csv(report, base, generation, change="--on-change" in flags, faults="--simulate-faults" in flags)
        reports[scheduler] = report

    collision = destination / "collision.0002.csv"
    collision.write_bytes(b"preserve existing part\n")
    report = cli_call(cli, "run", profile, "--seconds", 2, "--csv", destination / "collision.csv", success=False)
    assert collision.read_bytes() == b"preserve existing part\n"
    assert report["capture"]["written"] == 500 and "CSV capture incomplete" in report["error"]

    fixture = ROOT / "samples/synthetic-replay.json"
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
    pdo_destination = destination / "pdo-choices"
    pdo_destination.mkdir()
    verify_pdo_choices(cli, pdo_destination)

    comparison_destination = destination / "comparison"
    comparison_destination.mkdir()
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
