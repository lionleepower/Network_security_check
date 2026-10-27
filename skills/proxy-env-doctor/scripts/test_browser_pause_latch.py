import json
from pathlib import Path
import tempfile
import unittest
from browser_pause_latch import pause, resume
from guard_store import save


class FakeNative:
    def __init__(self): self.paused = []; self.resumed = []
    def open(self, row): return row['pid']
    def close(self, handle): pass
    def pause(self, handle): self.paused.append(handle)
    def resume(self, handle): self.resumed.append(handle)


class PauseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.profile = root / 'io.github.clash-verge-rev.clash-verge-rev' / 'claude-isolated-browser'
        self.profile.mkdir(parents=True)
        self.journal = root / 'pause.json'; self.native = FakeNative()
        self.rows = [{'pid': 1, 'parent': 0, 'created': 100, 'name': 'msedge.exe', 'command': f'edge --user-data-dir="{self.profile}" --proxy-server=http://127.0.0.1:18081'},
                     {'pid': 2, 'parent': 1, 'created': 200, 'name': 'msedge.exe', 'command': ''},
                     {'pid': 3, 'parent': 0, 'created': 300, 'name': 'msedge.exe', 'command': ''}]
        self.scan = lambda profile: self.rows

    def test_pause_survives_caller_and_idempotent_resume(self):
        pause(self.profile, self.journal, self.native, self.scan)
        pause(self.profile, self.journal, self.native, self.scan)
        self.assertEqual(self.native.paused, [1, 2])
        self.assertEqual(self.native.resumed, [])
        resume(self.journal, self.native, self.scan)
        resume(self.journal, self.native, self.scan)
        self.assertEqual(self.native.resumed, [2, 1])

    def test_pid_reuse_skipped_on_recovery(self):
        pause(self.profile, self.journal, self.native, self.scan)
        self.rows[1]['created'] = 999
        resume(self.journal, self.native, self.scan)
        self.assertEqual(self.native.resumed, [1])

    def test_native_transition_ambiguity_never_guessed(self):
        save(self.journal, {'phase': 'pausing', 'profile': str(self.profile), 'targets': [{'pid': 1, 'created': 100, 'step': 'pause_pending'}]})
        with self.assertRaises(RuntimeError): resume(self.journal, self.native, self.scan)
        self.assertFalse(self.native.resumed)


if __name__ == '__main__': unittest.main()
