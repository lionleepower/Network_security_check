import tempfile
import unittest
from pathlib import Path
from build_release import build, findings, ROOT_FILES, TREES


class ReleaseTests(unittest.TestCase):
    def test_only_public_files_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'repo'; root.mkdir()
            for name in ROOT_FILES:
                (root / name).write_text('public', encoding='utf-8')
            for tree in TREES:
                (root / tree).mkdir(parents=True)
                (root / tree / 'fixture.md').write_text('public', encoding='utf-8')
            (root / 'reports').mkdir()
            (root / 'reports/private.json').write_text('excluded')
            out = Path(tmp) / 'release'
            self.assertTrue(build(root, out)['built'])
            self.assertFalse((out / 'source/reports').exists())
            with self.assertRaises(ValueError): build(root, out)

    def test_privacy_hits_report_positions_not_values(self):
        value = 'C:' + '/Users/' + 'fixture-person/private'
        hits = findings(value)
        self.assertEqual(hits, [{'kind': 'personal_windows_path', 'line': 1}])
        self.assertNotIn(value, str(hits))

    def test_unexpected_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ROOT_FILES: (root / name).write_text('public')
            (root / TREES[0]).mkdir(parents=True)
            (root / TREES[0] / 'unknown.bin').write_bytes(b'unknown')
            with self.assertRaises(ValueError): build(root, root / 'out')


if __name__ == '__main__': unittest.main()
