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
