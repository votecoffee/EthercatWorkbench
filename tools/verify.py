"""Verify the Windows CLI, synthetic capture pipeline and optional GUI smoke run."""
import argparse
import csv
import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


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


def verify_csv(report, base, generation=1, change=False, faults=False):
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
    for index, (row, cycle) in enumerate(zip(entries, cycles), 1):
        assert int(row["connection_generation"]) == generation
        assert int(row["sample_index"]) == index
        assert row["capture_start_utc"] == cap["utc_start"]
        counter = ((cycle - 1) // 4) % 65536
        assert int(row["Counter"]) == counter
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



def verify_virtual(cli, profile, destination, reports, model="coe"):
    model_flags = ["--virtual-model", model]
    prefix = "virtual" if model == "coe" else f"virtual-{model}"
    for on_change in (False, True):
        base = destination / ("virtual-change.csv" if on_change else "virtual-every.csv")
        flags = ["--on-change"] if on_change else []
        report = cli_call(cli, "run", profile, "--backend", "virtual", *model_flags, "--seconds", 1, "--csv", base, *flags)
        (destination / (base.stem + ".json")).write_text(json.dumps(report, indent=2), encoding="utf-8")
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
    profile = ROOT / "samples/synthetic.json"
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

    sync_destination = destination / "sync-modes"
    sync_destination.mkdir()
    verify_sync_modes(cli, sync_destination)

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
