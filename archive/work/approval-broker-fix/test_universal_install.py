"""Exercise installation only against temporary copies, never the live broker."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent


class InstallTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("installer_test", HERE / "install_universal_broker.py")
        self.installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.installer)
        self.temporary = tempfile.TemporaryDirectory(prefix="universal-install-test-")
        self.root = Path(self.temporary.name)
        self.live = self.root / "scripts"
        self.live.mkdir()
        controls = self.root / "controls"
        controls.mkdir()
        self.policy = controls / "broker-policy.json"
        for name, hashes in self.installer.FILES.items():
            if hashes["before"] is not None:
                shutil.copy2(HERE / "before" / name, self.live / name)
        self.paths = patch.multiple(self.installer, LIVE=self.live, POLICY=self.policy, ROOT=self.root)
        self.paths.start()

    def tearDown(self):
        self.paths.stop()
        self.temporary.cleanup()

    def test_install_enables_requested_mode_last_and_retains_backup(self):
        self.assertEqual(self.installer.preflight()["status"], "ready")
        self.assertFalse(self.policy.exists())
        result = self.installer.install()
        self.assertEqual(result["status"], "installed")
        self.assertEqual(json.loads(self.policy.read_text()), {"version": 1, "mode": "no_prompt"})
        self.assertEqual(self.policy.stat().st_mode & 0o777, 0o600)
        self.assertTrue((Path(result["backup"]) / "RESTORE.json").is_file())
        for name, hashes in self.installer.FILES.items():
            self.assertEqual(self.installer.digest((self.live / name).read_bytes()), hashes["after"])
        self.assertFalse((self.root / "state").exists())

    def test_failed_setting_write_rolls_back_all_code(self):
        original = self.installer.write_atomic
        def failure(path, data, mode):
            if path == self.policy:
                raise OSError("Injected test failure")
            return original(path, data, mode)
        with patch.object(self.installer, "write_atomic", side_effect=failure):
            with self.assertRaisesRegex(RuntimeError, "Rollback conflicts: \\[\\]"):
                self.installer.install()
        self.assertFalse(self.policy.exists())
        for name, hashes in self.installer.FILES.items():
            target = self.live / name
            if hashes["before"] is None:
                self.assertFalse(target.exists())
            else:
                self.assertEqual(self.installer.digest(target.read_bytes()), hashes["before"])

    def test_existing_edits_and_settings_are_not_overwritten(self):
        target = self.live / "accessible_approval_broker.py"
        target.write_text("A concurrent user edit")
        with self.assertRaisesRegex(RuntimeError, "Installed file changed"):
            self.installer.preflight()
        self.assertEqual(target.read_text(), "A concurrent user edit")
        self.policy.write_text('{"version":1,"mode":"prompt"}')
        with self.assertRaisesRegex(RuntimeError, "broker policy now exists"):
            self.installer.preflight()
        self.assertEqual(json.loads(self.policy.read_text())["mode"], "prompt")


if __name__ == "__main__":
    unittest.main(verbosity=2)
