import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('install_state', Path(__file__).resolve().parents[1]/'install_state.py')
state = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(state)


class RecoveryTests(unittest.TestCase):
    def test_existing_addon_and_current_profile_restored_without_discarding_failed_code(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root); addon = root/'addon'; addon.mkdir()
            (addon/'session_ops.py').write_text('previous version')
            profile = root/'tunnel.yaml'; profile.write_text('already points to addon')
            backup = state.snapshot(addon, profile)
            (addon/'session_ops.py').write_text('failed new version')
            profile.write_text('modified profile')
            self.assertTrue(state.restore(backup)['restored'])
            self.assertEqual(profile.read_text(), 'already points to addon')
            self.assertEqual((addon/'session_ops.py').read_text(), 'previous version')
            self.assertEqual((backup/'failed-addon/session_ops.py').read_text(), 'failed new version')
            self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
            self.assertEqual(profile.stat().st_mode & 0o777, 0o600)

    def test_first_install_failure_restores_no_addon_state(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root); profile = root/'profile'; profile.write_text('original server')
            addon = root/'addon'; backup = state.snapshot(addon, profile)
            addon.mkdir(); (addon/'new.py').write_text('new')
            state.restore(backup)
            self.assertFalse(addon.exists())
            self.assertTrue((backup/'failed-addon/new.py').is_file())

    def test_snapshots_are_unique_and_previous_recovery_is_preserved(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root); profile = root/'profile'; profile.write_text('first')
            first = state.snapshot(root/'addon', profile)
            profile.write_text('second')
            second = state.snapshot(root/'addon', profile)
            self.assertNotEqual(first, second)
            self.assertEqual((first/'profile.before').read_text(), 'first')
            self.assertEqual((second/'profile.before').read_text(), 'second')

    def test_corrupt_snapshot_refuses_before_replacing_current_files(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root); profile = root/'profile'; profile.write_text('original')
            addon = root/'addon'; addon.mkdir(); (addon/'code').write_text('old')
            backup = state.snapshot(addon, profile)
            (backup/'profile.before').write_text('tampered')
            with self.assertRaises(ValueError): state.restore(backup)
            self.assertEqual((addon/'code').read_text(), 'old')

    def test_symlink_profile_and_destination_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root); profile = root/'profile'; profile.write_text('real')
            link = root/'link'; link.symlink_to(profile)
            with self.assertRaises(ValueError): state.snapshot(root/'addon', link)
            directory = root/'directory'; directory.mkdir()
            link.unlink(); link.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(ValueError): state.snapshot(link, profile)

    def test_corrupt_previous_code_refuses_without_replacing_current_version(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root); profile = root/'profile'; profile.write_text('original')
            addon = root/'addon'; addon.mkdir(); (addon/'code').write_text('old')
            backup = state.snapshot(addon, profile)
            (backup/'addon.before/code').write_text('corrupted backup')
            (addon/'code').write_text('current')
            with self.assertRaises(ValueError): state.restore(backup)
            self.assertEqual((addon/'code').read_text(), 'current')
