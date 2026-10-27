import unittest
from isolated_browser_pause import flag,select


class ScopedPauseTests(unittest.TestCase):
    def rows(self):
        return [dict(pid=1,parent=0,name='msedge.exe',command='edge --user-data-dir="/private/claude-isolated-browser" --proxy-server=http://127.0.0.1:18081'),
                dict(pid=2,parent=1,name='msedge.exe',command=''),
                dict(pid=3,parent=0,name='msedge.exe',command='edge --user-data-dir=/other'),
                dict(pid=4,parent=3,name='msedge.exe',command=''),
                dict(pid=5,parent=1,name='Claude.exe',command='')]

    def test_only_exact_root_and_edge_descendants(self):
        root,rows=select(self.rows(),'/private/claude-isolated-browser')
        self.assertEqual(root,1)
        self.assertEqual({r['pid'] for r in rows},{1,2})

    def test_prefix_path_and_wrong_proxy_rejected(self):
        with self.assertRaises(ValueError):select(self.rows(),'/private/claude-isolated')
        rows=self.rows();rows[0]['command']=rows[0]['command'].replace('18081','7897')
        with self.assertRaises(ValueError):select(rows,'/private/claude-isolated-browser')

    def test_ambiguous_roots_rejected(self):
        rows=self.rows();rows.append({**rows[0],'pid':6})
        with self.assertRaises(ValueError):select(rows,'/private/claude-isolated-browser')

    def test_quoted_paths_and_flag_boundaries(self):
        self.assertEqual(flag('edge --user-data-dir="C:/Some Folder" --foo=1','user-data-dir'),'C:/Some Folder')
        self.assertIsNone(flag('edge --fake-user-data-dir=/wrong','user-data-dir'))


if __name__=='__main__':unittest.main()
