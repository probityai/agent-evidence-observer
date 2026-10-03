"""Controlled nonreader fixtures test prelaunch selection and stream retention."""
import logging
import sys
from pathlib import Path

import pytest

import consume_installed as consumer
from joint_host_gate import reader_closure
from probity_observer.crypto import VerificationError, canonical


def selected(tmp_path, body="raise SystemExit(17)\n"):
    """Select explicit miniature nonreader bytes; no native result is claimed."""
    packet = tmp_path / "packet"
    packet.mkdir()
    pins = tmp_path / "pins.json"
    pins.write_bytes(canonical({"fixture": "consumer-boundary-only"}))
    prefix = tmp_path / "environment"
    (prefix / "bin").mkdir(parents=True)
    (prefix / "bin/python").symlink_to(Path(sys.executable).resolve())
    (prefix / "pyvenv.cfg").write_text("include-system-site-packages = false\n")
    site = prefix / ("lib/python" + str(sys.version_info.major) + "." + str(sys.version_info.minor) + "/site-packages")
    site.mkdir(parents=True)
    for name, version in (("probity-joint-recovery-reader", "0.0.2"), ("agent-evidence-observer", "0.0.1")):
        metadata = site / (name + ".dist-info/METADATA")
        metadata.parent.mkdir()
        metadata.write_text("Name: " + name + "\nVersion: " + version + "\n")
    reader = prefix / "bin/controlled-nonreader"
    reader.write_text("#!" + str(prefix / "bin/python") + "\n" + body)
    closure = tmp_path / "selected-closure.json"
    closure.write_bytes(canonical(reader_closure(reader)))
    return packet, pins, reader, closure, tmp_path / "receipts"


class TestConsumerBoundary:
    class TestPassingCases:
        def test_nonreader_streams_are_retained_under_isolated_invocation(self, tmp_path):
            args = selected(tmp_path, "import sys\nprint('controlled output')\nsys.stderr.write('controlled diagnostic\\n')\nraise SystemExit(17)\n")
            with pytest.raises(VerificationError, match="^installed-reader-outcome$"):
                consumer.consume(*args)
            assert (args[-1] / "reader.stdout").read_bytes() == b"controlled output\n"
            assert (args[-1] / "reader.stderr").read_bytes() == b"controlled diagnostic\n"
            process = consumer.load(args[-1], "reader.process.json")
            assert process["command"][1] == "-I"
            assert process["command"][2] == "-B"
            assert process["returncode"] == 17
            assert not (args[-1] / "consumer-decision.json").exists()

    class TestFailingCases:
        def test_changed_selected_installation_refuses_before_launch(self, tmp_path, monkeypatch, caplog):
            args = selected(tmp_path)
            args[2].write_text(args[2].read_text() + "# changed selected bytes\n")
            def forbidden(*args, **kwargs):
                raise AssertionError("changed installation launched")
            monkeypatch.setattr(consumer.subprocess, "run", forbidden)
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^reader-installed-closure$"):
                consumer.consume(*args)
            assert "Joint recovery refused: reader-installed-closure" in caplog.messages
            assert not (args[-1] / "reader.process.json").exists()

        def test_packet_cannot_supply_its_own_selection(self, tmp_path):
            packet, pins, reader, closure, output = selected(tmp_path)
            inside = packet / "untrusted-pins.json"
            inside.write_bytes(pins.read_bytes())
            with pytest.raises(VerificationError, match="^selection-must-be-outside-packet$"):
                consumer.consume(packet, inside, reader, closure, output)
            assert not output.exists()

        def test_timeout_retains_partial_streams(self, tmp_path, monkeypatch):
            args = selected(tmp_path)
            def timeout(*args, **kwargs):
                raise consumer.subprocess.TimeoutExpired(args[0], 30, output=b"partial", stderr=b"diagnostic")
            monkeypatch.setattr(consumer.subprocess, "run", timeout)
            with pytest.raises(VerificationError, match="^installed-reader-outcome$"):
                consumer.consume(*args)
            assert (args[-1] / "reader.stdout").read_bytes() == b"partial"
            assert (args[-1] / "reader.stderr").read_bytes() == b"diagnostic"
            assert consumer.load(args[-1], "reader.process.json")["timedOut"] is True
