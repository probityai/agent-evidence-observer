"""Exercise source refusal with real local Git trees and retained receipt bytes."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "selected_adk_tox", Path(__file__).with_name("apply_tox_corrections.py")
)
assert spec is not None and spec.loader is not None
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SourceSelection(unittest.TestCase):
    """Small Git fixtures exercise real index/checkout and inherited-config behavior."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.checkout, self.profile = self.root / "sdk", self.root / "profile"
        self.checkout.mkdir()
        self.profile.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Source fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.code = self.checkout / "code.py"
        self.code.write_text("original = True\n")
        (self.checkout / "tox.ini").write_text("[tox]\nenv_list = py310\n")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "Original local fixture")
        base = self.git("rev-parse", "HEAD")
        original = sha(self.code)
        self.code.write_text("corrected = True\n")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "Correct local fixture")
        corrected_commit = self.git("rev-parse", "HEAD")
        corrected_tree = self.git("write-tree")
        corrected_sha = sha(self.code)
        (self.profile / "fix.mbox").write_text(
            self.git("format-patch", "-1", "--stdout") + "\n"
        )
        self.git("checkout", "-q", base)
        (self.profile / "LICENSE").write_text("Local test fixture\n")
        (self.profile / "native.json").write_text(json.dumps({"commit": base}))
        sample = self.profile / "upstream-sample"
        sample.mkdir()
        (sample / "sample.py").write_text("sample = True\n")
        self.selected = {
            "schemaVersion": "probity.adk-full-tox-source.v1",
            "baseCommit": base,
            "patchedSourceTree": corrected_tree,
            "patchedSourceCommits": [corrected_commit],
            "patchFile": "fix.mbox",
            "patchSHA256": sha(self.profile / "fix.mbox"),
            "licenseFile": "LICENSE",
            "licenseSHA256": sha(self.profile / "LICENSE"),
            "license": "local-test-fixture",
            "originalFileSHA256": {"code.py": original},
            "patchedFileSHA256": {"code.py": corrected_sha},
            "unchangedFileSHA256": {"tox.ini": sha(self.checkout / "tox.ini")},
            "nativeSourceSelection": {
                "file": "native.json",
                "sha256": sha(self.profile / "native.json"),
                "commit": base,
            },
            "sampleOverlaySHA256": {"sample.py": sha(sample / "sample.py")},
            "scope": "local source-selection control, not the ADK qualification",
        }
        self.save_selection()

    def git(self, *arguments: str) -> str:
        return host.git_output(self.checkout, *arguments)

    def save_selection(self) -> None:
        (self.profile / "full-tox-source-selection.json").write_text(
            json.dumps(self.selected)
        )

    def apply(self) -> dict:
        return host.apply_selection(self.checkout, self.profile)

    def test_exact_complete_tree_and_unchanged_metadata(self) -> None:
        receipt = self.apply()
        self.assertEqual(receipt["patchedSourceTree"], self.git("write-tree"))
        self.assertEqual(receipt["baseCommit"], self.git("rev-parse", "HEAD"))
        self.assertEqual(receipt["nativeConsumerSDKCommit"], receipt["baseCommit"])
        self.assertEqual(sha(self.code), self.selected["patchedFileSHA256"]["code.py"])
        self.assertEqual(
            sha(self.checkout / "tox.ini"), receipt["unchangedFileSHA256"]["tox.ini"]
        )
        self.assertEqual(self.git("diff", "--cached", "--name-only"), "code.py")
        self.assertEqual(
            receipt["sourceSelectionSHA256"],
            sha(self.profile / "full-tox-source-selection.json"),
        )

    def test_inherited_git_repository_and_config_cannot_redirect_selection(self) -> None:
        other = self.root / "other"
        other.mkdir()
        host.git_output(other, "init", "-q")
        config = self.root / "redirect.conf"
        config.write_text("[core]\n\tworktree = " + str(other) + "\n")
        with patch.dict(
            os.environ,
            {
                "GIT_DIR": str(other / ".git"),
                "GIT_WORK_TREE": str(other),
                "GIT_INDEX_FILE": str(other / ".git/index"),
                "GIT_CONFIG_GLOBAL": str(config),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.worktree",
                "GIT_CONFIG_VALUE_0": str(other),
            },
        ):
            self.assertEqual(self.apply()["patchedSourceTree"], self.selected["patchedSourceTree"])
        self.assertEqual(host.git_output(other, "status", "--porcelain=v1"), "")
        self.assertFalse((other / "code.py").exists())

    def test_repository_subdirectory_refused(self) -> None:
        child = self.checkout / "child"
        child.mkdir()
        with self.assertRaisesRegex(SystemExit, "wrong owning repository"):
            host.apply_selection(child, self.profile)

    def test_wrong_base_refused_before_patch(self) -> None:
        self.selected["baseCommit"] = "0" * 40
        self.save_selection()
        with self.assertRaisesRegex(SystemExit, "wrong base commit"):
            self.apply()
        self.assertEqual(self.git("status", "--porcelain=v1"), "")

    def test_dirty_checkout_refused_before_patch(self) -> None:
        (self.checkout / "unselected.txt").write_text("uncommitted owner work\n")
        with self.assertRaisesRegex(SystemExit, "checkout is not clean"):
            self.apply()
        self.assertEqual(self.code.read_text(), "original = True\n")

    def test_selected_input_changes_refused_before_patch(self) -> None:
        for relative in ("fix.mbox", "LICENSE", "native.json", "upstream-sample/sample.py"):
            with self.subTest(file=relative):
                path = self.profile / relative
                original = path.read_bytes()
                path.write_bytes(original + b"changed\n")
                with self.assertRaisesRegex(SystemExit, "selected bytes differ"):
                    self.apply()
                path.write_bytes(original)
                self.assertEqual(self.git("status", "--porcelain=v1"), "")

    def test_wrong_original_inventory_refused_before_patch(self) -> None:
        self.selected["originalFileSHA256"]["code.py"] = "0" * 64
        self.save_selection()
        with self.assertRaisesRegex(SystemExit, "selected bytes differ: code.py"):
            self.apply()
        self.assertEqual(self.git("status", "--porcelain=v1"), "")

    def test_wrong_complete_tree_refused_even_with_valid_selected_files(self) -> None:
        self.selected["patchedSourceTree"] = "0" * 40
        self.save_selection()
        with self.assertRaisesRegex(SystemExit, "patched tree differs"):
            self.apply()

    def test_nonapplicable_patch_refused_without_source_change(self) -> None:
        patch_file = self.profile / "fix.mbox"
        patch_file.write_text(patch_file.read_text().replace("original = True", "absent = True"))
        self.selected["patchSHA256"] = sha(patch_file)
        self.save_selection()
        with self.assertRaises(subprocess.CalledProcessError):
            self.apply()
        self.assertEqual(self.git("status", "--porcelain=v1"), "")

    def test_wrong_patched_inventory_refused(self) -> None:
        self.selected["patchedFileSHA256"]["code.py"] = "0" * 64
        self.save_selection()
        with self.assertRaisesRegex(SystemExit, "selected bytes differ: code.py"):
            self.apply()

    def test_unsupported_contract_refused_before_patch(self) -> None:
        self.selected["schemaVersion"] = "other-contract"
        self.save_selection()
        with self.assertRaisesRegex(SystemExit, "unsupported source contract"):
            self.apply()
        self.assertEqual(self.git("status", "--porcelain=v1"), "")

    def test_missing_file_refused(self) -> None:
        with self.assertRaisesRegex(SystemExit, "selected bytes differ: missing.py"):
            host.check_files(self.checkout, {"missing.py": "0" * 64})

    def test_symlink_and_path_escape_refused(self) -> None:
        linked = self.checkout / "linked.py"
        linked.symlink_to(self.code)
        for relative in ("linked.py", "../profile/LICENSE"):
            with self.subTest(file=relative):
                with self.assertRaisesRegex(SystemExit, "redirected file"):
                    host.check_files(self.checkout, {relative: sha(linked)})

    def test_cli_success_retains_exact_receipt(self) -> None:
        receipt = self.root / "receipt.json"
        output = io.StringIO()
        with patch.object(host, "__file__", str(self.profile / "apply_tox_corrections.py")), patch(
            "sys.argv", ["apply_tox_corrections.py", str(self.checkout), str(receipt)]
        ), contextlib.redirect_stdout(output):
            host.main()
        self.assertEqual(json.loads(output.getvalue()), json.loads(receipt.read_bytes()))
        self.assertEqual(json.loads(receipt.read_bytes())["patchedSourceTree"], self.git("write-tree"))

    def test_cli_refusal_has_no_success_stdout_or_receipt(self) -> None:
        receipt = self.root / "receipt.json"
        self.selected["baseCommit"] = "0" * 40
        self.save_selection()
        output = io.StringIO()
        with patch.object(host, "__file__", str(self.profile / "apply_tox_corrections.py")), patch(
            "sys.argv", ["apply_tox_corrections.py", str(self.checkout), str(receipt)]
        ), contextlib.redirect_stdout(output), self.assertRaises(SystemExit):
            host.main()
        self.assertEqual(output.getvalue(), "")
        self.assertFalse(receipt.exists())

    def test_existing_receipt_and_owner_work_preserved(self) -> None:
        receipt = self.root / "receipt.json"
        receipt.write_text("existing retained bytes\n")
        with patch("sys.argv", ["apply_tox_corrections.py", str(self.checkout), str(receipt)]), self.assertRaisesRegex(
            SystemExit, "receipt already exists"
        ):
            host.main()
        self.assertEqual(receipt.read_text(), "existing retained bytes\n")
        self.assertEqual(self.git("status", "--porcelain=v1"), "")

    def test_dangling_receipt_link_refused_before_source_change(self) -> None:
        receipt = self.root / "receipt.json"
        receipt.symlink_to(self.root / "missing.json")
        with patch("sys.argv", ["apply_tox_corrections.py", str(self.checkout), str(receipt)]), self.assertRaisesRegex(
            SystemExit, "receipt already exists"
        ):
            host.main()
        self.assertTrue(receipt.is_symlink())
        self.assertEqual(self.git("status", "--porcelain=v1"), "")


if __name__ == "__main__":
    unittest.main()
