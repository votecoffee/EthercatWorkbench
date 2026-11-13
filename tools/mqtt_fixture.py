"""Independent, bounded local MQTT 3.1.1 fixture. Not a production broker."""
from collections import deque
import http.client
import json
from pathlib import Path
import re
import socket
import struct
import subprocess
import threading
import time


class Broker:
    def __init__(self):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(4)
        self.listener.settimeout(.05)
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.plan = []
        self.records = deque(maxlen=256)
        self.connects = []
        self.disconnects = 0
        self.pings = 0
        self.errors = []
        self.thread = threading.Thread(target=self.serve, name="authored-mqtt-broker")
        self.thread.start()

    def exact(self, peer, count):
        result = bytearray()
        until = time.monotonic() + 2
        while len(result) < count and not self.stop.is_set():
            try:
                part = peer.recv(count - len(result))
                if not part:
                    raise EOFError()
                result.extend(part)
            except socket.timeout:
                if time.monotonic() >= until:
                    raise EOFError()
        if len(result) != count:
            raise EOFError()
        return bytes(result)

    def packet(self, peer):
        kind = self.exact(peer, 1)[0]
        length = 0
        for index in range(4):
            byte = self.exact(peer, 1)[0]
            length += (byte & 127) << (7 * index)
            if byte < 128:
                assert length <= 2 * 1024 * 1024 + 1024
                return kind, self.exact(peer, length)
        raise AssertionError("overlong MQTT remaining length")

    @staticmethod
    def string(body, offset):
        size = struct.unpack_from("!H", body, offset)[0]
        end = offset + 2 + size
        assert end <= len(body)
        return body[offset + 2:end].decode("utf-8"), end

    def connection(self, peer):
        peer.settimeout(.05)
        kind, body = self.packet(peer)
        assert kind == 0x10 and body[:10] == b"\x00\x04MQTT\x04\x06\x00\x0a"
        client, offset = self.string(body, 10)
        topic, offset = self.string(body, offset)
        will, offset = self.string(body, offset)
        assert offset == len(body) and len(client) == 23 and client.isalnum()
        will = json.loads(will)
        assert will["kind"] == "unavailable" and not will["active"] and not will["fresh"]
        with self.lock:
            action = self.plan.pop(0) if self.plan else "accept"
            self.connects.append(dict(client_id=client, topic=topic, will=will, action=action))
        if action == "silent":
            self.stop.wait(.18)
            return
        if action in ("reject", "malformed"):
            peer.sendall(b"\x20\x02\x00\x05" if action == "reject" else b"\x20\x02\x01\x00")
            return
        # Deliberately fragment CONNACK and PINGRESP across reads.
        peer.sendall(b"\x20\x02")
        self.stop.wait(.002)
        peer.sendall(b"\x00\x00")
        if action == "stall":
            self.stop.wait(.8)
            return
        while not self.stop.is_set():
            kind, body = self.packet(peer)
            if kind == 0x30:
                got_topic, offset = self.string(body, 0)
                assert got_topic == topic
                data = json.loads(body[offset:])
                assert data["schema"] == 1 and data["kind"] == "input"
                assert data["stream_id"] == will["stream_id"]
                assert data["broker_attempt"] == will["broker_attempt"]
                with self.lock:
                    self.records.append(data)
                if action == "close":
                    return
            elif kind == 0xc0:
                assert body == b""
                with self.lock:
                    self.pings += 1
                peer.sendall(b"\xd0")
                self.stop.wait(.002)
                peer.sendall(b"\x00")
            elif kind == 0xe0:
                assert body == b""
                with self.lock:
                    self.disconnects += 1
                return
            else:
                raise AssertionError(f"unexpected client packet {kind:#x}; no subscription/output path allowed")

    def serve(self):
        while not self.stop.is_set():
            try:
                peer, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.stop.is_set():
                    return
                raise
            try:
                with peer:
                    self.connection(peer)
            except (EOFError, ConnectionError, OSError):
                pass  # Intentional abrupt client/server disconnects and shutdown.
            except Exception as error:
                self.errors.append(repr(error))

    def snapshot(self):
        with self.lock:
            return list(self.records)

    def reset(self, plan=()):
        with self.lock:
            self.plan = list(plan)
            self.records.clear()

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=3)
        assert not self.thread.is_alive() and not self.errors, self.errors


def verify_mqtt(cli, root, destination, cli_call):
    broker = Broker()
    streams = []
    clients = []
    reports = []

    def trial(label, profile, seconds, extra=(), schedule="deadline"):
        case = destination / label
        config = case.with_suffix(".profile.json")
        config.write_text(json.dumps(profile), encoding="utf-8")
        output = case.with_suffix(".stdout.json")
        errors = case.with_suffix(".stderr.txt")
        with output.open("wb") as stdout, errors.open("wb") as stderr:
            proc = subprocess.Popen([str(cli), "run", str(config), "--seconds", str(seconds),
                "--scheduler", schedule, "--csv", str(case.with_suffix(".csv")),
                "--report", str(case.with_suffix(".json")), *extra], stdout=stdout, stderr=stderr)
            http_cycles = []
            try:
                until = time.monotonic() + seconds + 10
                while proc.poll() is None and time.monotonic() < until:
                    text = errors.read_text(encoding="utf-8")
                    match = re.search(r"HTTP input feed bound at http://127\.0\.0\.1:(\d+)", text)
                    if match:
                        client = http.client.HTTPConnection("127.0.0.1", int(match.group(1)), timeout=.2)
                        try:
                            client.request("GET", "/v1/status")
                            response = client.getresponse()
                            data = json.loads(response.read())
                            if response.status == 200 and data["data"]["acquisition"]:
                                http_cycles.append(data["data"]["acquisition"]["cycles"])
                        except (OSError, http.client.HTTPException):
                            pass
                        finally:
                            client.close()
                    time.sleep(.01)
                proc.wait(timeout=2)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
        assert proc.returncode == 0, errors.read_text(encoding="utf-8")
        report = json.loads(case.with_suffix(".json").read_bytes())
        feed = report["mqtt"]
        assert feed["offered"] == report["cycles"] == feed["drained"] + feed["queue_drops"] + feed["queue_pending"]
        assert feed["drained"] == feed["coalesced"] + feed["attempted_events"] + feed["unsent_events"]
        assert feed["publish_attempts"] == feed["write_completions"] + feed["publish_errors"]
        assert not feed["active"] and not feed["connected"] and not feed["worker_failed"] and feed["worker_error"] is None
        assert feed["queue_pending"] == 0 and report["capture"]["overruns"] == 0
        assert report["capture"]["written"] == report["valid"]
        audit = cli_call(cli, "verify-capture", case.with_suffix(".json"), case.with_suffix(".csv"))
        assert audit["rows"] == report["valid"]
        assert len(http_cycles) > 2 and max(http_cycles) > min(http_cycles)
        assert report["http"]["offered"] == report["cycles"] and report["http"]["queue_drops"] == 0
        time.sleep(.05)  # Allow the fixture to observe the final buffered packet/DISCONNECT.
        return report

    try:
        for schedule in ("deadline", "relative"):
            broker.reset(["silent", "reject", "malformed", "close", "accept"])
            profile = json.loads((root / "samples/synthetic.json").read_bytes())
            profile["mqtt"] = dict(port=broker.port, queue_capacity=2, period_ms=10, freshness_ms=20)
            profile["http"] = dict(port=0)
            profile["tx"][2]["log"] = False
            report = trial(schedule, profile, 3, ["--simulate-faults", "--input-loss-timeout-ms", "0"], schedule)
            feed = report["mqtt"]
            connections = [c for c in broker.connects if c["will"]["stream_id"] == feed["stream_id"]]
            assert all(c["client_id"] == feed["client_id"] and c["topic"] == feed["topic"] for c in connections)
            attempts = [c["will"]["broker_attempt"] for c in connections]
            assert len(connections) >= 5 and all(b > a for a, b in zip(attempts, attempts[1:]))
            assert feed["connections"] >= 2 and feed["connect_errors"] >= 3 and feed["queue_drops"] > 0 and feed["coalesced"] > 0
            assert feed["shutdown_written"] and feed["disconnect_written"]
            records = broker.snapshot()
            assert records and not records[-1]["active"] and not records[-1]["fresh"]
            indexes = [r["publication_index"] for r in records]
            assert all(b > a for a, b in zip(indexes, indexes[1:]))
            assert all(r["metadata"]["backend"] == "Synthetic fixture" for r in records)
            for record in records:
                assert record["stream_id"] == feed["stream_id"]
                latest = record["latest"]
                if latest and latest["valid"]:
                    counter = int.from_bytes(bytes.fromhex(latest["payload_hex"])[:2], "little")
                    assert latest["values"]["Counter"] == str(counter)
                    assert latest["values"]["Scaled counter"] == str(counter / 4).removesuffix(".0")
                elif latest:
                    assert latest["payload_hex"] is None and latest["values"] is None
            streams.append(feed["stream_id"])
            clients.append(feed["client_id"])
            (destination / f"{schedule}.mqtt-observed.json").write_text(json.dumps(records[-16:], indent=2), encoding="utf-8")
            reports.append(report)
        assert len(set(streams)) == len(set(clients)) == 2
        compared = cli_call(cli, "compare-runs", destination / "deadline.json", destination / "relative.json",
            "--csv", destination / "deadline.csv", "--csv", destination / "relative.csv")
        assert all(t["mqtt"]["coalesced"] > 0 for t in compared["trials"])
        assert any("MQTT feed loss" in w for w in compared["warnings"])
        (destination / "comparison.json").write_text(json.dumps(compared, indent=2), encoding="utf-8")

        broker.reset()
        profile = json.loads((root / "samples/virtual.json").read_bytes())
        profile.update(mqtt=dict(port=broker.port, period_ms=10), http=dict(port=0))
        lost = trial("lost", profile, 1, ["--backend", "virtual", "--virtual-fault", "io-lost", "--input-loss-timeout-ms", "0"])
        invalid = [r for r in broker.snapshot() if r["latest"] and not r["latest"]["valid"]]
        assert invalid and all(not r["fresh"] and r["latest"]["payload_hex"] is None and r["latest"]["values"] is None for r in invalid)
        assert all(r["latest"]["actual_wkc"] is None and r["latest"]["al_status"] is None and r["last_valid"] for r in invalid)
        assert lost["stopped_al"] == [1, 0]
        assert all(lost["virtual_esc"][key] == 0 for key in ["logical_writes", "physical_output_writes", "coe_downloads", "op_requests", "dc_enable_requests"])

        broker.reset()
        profile = json.loads((root / "samples/synthetic.json").read_bytes())
        profile.update(mqtt=dict(port=broker.port, period_ms=60000), http=dict(port=0))
        pings = broker.pings
        idle = trial("keepalive", profile, 3)
        assert broker.pings > pings and idle["mqtt"]["disconnect_written"]

        broker.reset(["stall", "accept"])
        profile["mqtt"] = dict(port=broker.port, period_ms=1, queue_capacity=2)
        profile["tx_bytes"] = 1024
        profile["tx"] = [dict(name="Counter", bit=0, width=16), dict(name="x" * 16000, bit=0, width=8192, kind="raw", log=False)]
        backpressure = trial("backpressure", profile, 2)
        assert backpressure["mqtt"]["publish_errors"] > 0 and backpressure["mqtt"]["queue_drops"] > 0

        with socket.socket() as unavailable:
            unavailable.bind(("127.0.0.1", 0))  # Reserve the port without a listener.
            profile = json.loads((root / "samples/synthetic.json").read_bytes())
            profile.update(mqtt=dict(port=unavailable.getsockname()[1]), http=dict(port=0))
            absent = trial("absent", profile, 1)
            assert absent["mqtt"]["connections"] == 0 and absent["mqtt"]["connect_errors"] > 0
            assert absent["mqtt"]["unsent_events"] == 1 and absent["mqtt"]["coalesced"] > 0
        summary = dict(trials=[dict(cycles=r["cycles"], mqtt=r["mqtt"], csv_overruns=r["capture"]["overruns"]) for r in reports],
            virtual_loss_init="passed", keepalive="passed", backpressure=backpressure["mqtt"], absent=absent["mqtt"], fixture_connections=broker.connects)
        (destination / "mqtt-verification.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return summary
    finally:
        broker.close()
