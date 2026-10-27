import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from change_bundle import prepare, apply, restore


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.target_root = self.root / 'client'
        self.target_root.mkdir()
        self.target = self.target_root / 'core.yaml'
        self.target.write_text('mode: global\n', encoding='utf-8')
        self.candidate = self.root / 'candidate.yaml'
        self.candidate.write_text('mode: rule\n', encoding='utf-8')
        self.core = self.root / 'test-core.exe'
        self.core.write_bytes(b'test-only; never executed')
        self.plan = self.root / 'plan.json'
        self.plan.write_text(json.dumps({'status': 'ready', 'authorization': {'client_modify': True},
                                        'allowed_client_roots': [str(self.target_root)],
                                        'claude': {'session_policy': 'do-not-touch-existing'}}), encoding='utf-8')
        self.changes = self.root / 'changes.json'
        self.changes.write_text(json.dumps({'target_root': str(self.target_root), 'files': [
            {'target': str(self.target), 'candidate': str(self.candidate)}]}), encoding='utf-8')
        self.bundle = self.root / 'private-bundle'

    def prepare(self):
        with patch('change_bundle.subprocess.run', return_value=subprocess.CompletedProcess([], 0)) as run:
            result = prepare(self.plan, self.changes, self.bundle, self.core, self.candidate, self.target_root)
            self.assertEqual(run.call_args.args[0][1], '-t')
            return result

    def test_prepare_does_not_write_source_and_apply_restore_are_exact(self):
        original = self.target.read_bytes()
        self.assertFalse(self.prepare()['targets_modified'])
        self.assertEqual(self.target.read_bytes(), original)
        self.assertFalse(apply(self.bundle, self.plan)['runtime_applied'])
        self.assertEqual(self.target.read_bytes(), self.candidate.read_bytes())
        self.assertFalse(restore(self.bundle)['runtime_restored'])
        self.assertEqual(self.target.read_bytes(), original)

    def test_refuses_stale_target_and_changed_plan(self):
        self.prepare()
        self.target.write_text('new user edit', encoding='utf-8')
        with self.assertRaises(ValueError):
            apply(self.bundle, self.plan)
        self.assertEqual(self.target.read_text(encoding='utf-8'), 'new user edit')
        self.target.write_text('mode: global\n', encoding='utf-8')
        self.plan.write_text('{}', encoding='utf-8')
        with self.assertRaises(ValueError):
            apply(self.bundle, self.plan)

    def test_refuses_altered_candidate_core_and_later_edits(self):
        self.prepare()
        candidate = self.bundle / 'candidate-0.bin'
        saved = candidate.read_bytes()
        candidate.write_text('tampered', encoding='utf-8')
        with self.assertRaises(ValueError):
            apply(self.bundle, self.plan)
        candidate.write_bytes(saved)
        self.core.write_bytes(b'updated core')
        with self.assertRaises(ValueError):
            apply(self.bundle, self.plan)
        self.core.write_bytes(b'test-only; never executed')
        apply(self.bundle, self.plan)
        self.target.write_text('later user setting', encoding='utf-8')
        with self.assertRaises(ValueError):
            restore(self.bundle)
        self.assertEqual(self.target.read_text(encoding='utf-8'), 'later user setting')

    def test_rejects_git_bundle_and_outside_target(self):
        self.prepare()
        tracked = self.root / 'checkout'
        tracked.mkdir()
        (tracked / '.git').mkdir()
        with patch('change_bundle.subprocess.run', return_value=subprocess.CompletedProcess([], 0)):
            with self.assertRaises(ValueError):
                prepare(self.plan, self.changes, tracked / 'bundle', self.core, self.candidate, self.target_root)
        spec = json.loads(self.changes.read_text(encoding='utf-8'))
        spec['files'][0]['target'] = str(self.candidate)
        self.changes.write_text(json.dumps(spec), encoding='utf-8')
        with self.assertRaises(ValueError):
            prepare(self.plan, self.changes, self.root / 'other', self.core, self.candidate, self.target_root)

    def test_failed_core_validation_never_creates_bundle_or_changes_target(self):
        with patch('change_bundle.subprocess.run', side_effect=subprocess.CalledProcessError(1, ['test-core'])):
            with self.assertRaises(subprocess.CalledProcessError):
                prepare(self.plan, self.changes, self.bundle, self.core, self.candidate, self.target_root)
        self.assertFalse(self.bundle.exists())
        self.assertEqual(self.target.read_text(encoding='utf-8'), 'mode: global\n')

    def test_write_error_restores_already_written_files(self):
        extra = self.target_root / 'extension.js'
        extra.write_text('old', encoding='utf-8')
        source = self.root / 'extension.js'
        source.write_text('new', encoding='utf-8')
        spec = json.loads(self.changes.read_text(encoding='utf-8'))
        spec['files'].append({'target': str(extra), 'candidate': str(source)})
        self.changes.write_text(json.dumps(spec), encoding='utf-8')
        self.prepare()
        import change_bundle
        actual_write = change_bundle.atomic_write

        def controlled_write(target, data):
            if target == extra:
                raise OSError('test write failure')
            return actual_write(target, data)

        with patch('change_bundle.atomic_write', side_effect=controlled_write):
            with self.assertRaises(OSError):
                apply(self.bundle, self.plan)
        self.assertEqual(self.target.read_text(encoding='utf-8'), 'mode: global\n')
        self.assertEqual(extra.read_text(encoding='utf-8'), 'old')


if __name__ == '__main__':
    unittest.main()
