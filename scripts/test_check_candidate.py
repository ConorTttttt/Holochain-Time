"""Standalone, offline regression checks against a synthetic Git history."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from check_candidate import check


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], text=True,
                          capture_output=True, check=True).stdout.strip()


class CandidateAuditTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        git(self.root, 'init', '-q')
        git(self.root, 'config', 'user.email', 'tester@example.invalid')
        git(self.root, 'config', 'user.name', 'Test')
        (self.root / 'base.txt').write_text('base')
        git(self.root, 'add', 'base.txt')
        git(self.root, 'commit', '-qm', 'base')
        base = git(self.root, 'rev-parse', 'HEAD')
        git(self.root, 'checkout', '-qb', 'upstream')
        (self.root / 'upstream.txt').write_text('upstream')
        git(self.root, 'add', 'upstream.txt')
        git(self.root, 'commit', '-qm', 'upstream')
        self.upstream = git(self.root, 'rev-parse', 'HEAD')
        git(self.root, 'checkout', '-qb', 'downstream', base)
        (self.root / 'downstream.txt').write_text('downstream')
        git(self.root, 'add', 'downstream.txt')
        git(self.root, 'commit', '-qm', 'downstream')
        self.downstream = git(self.root, 'rev-parse', 'HEAD')

    def test_unreconciled_history_rejected(self):
        r = check(self.root, self.downstream, (self.upstream,))
        self.assertFalse(r['ancestry_passed'])
        self.assertFalse(r['release_ready'])

    def test_reviewed_merge_has_both_parents(self):
        git(self.root, 'merge', '--no-ff', '-m', 'integrate', 'upstream')
        sha = git(self.root, 'rev-parse', 'HEAD')
        r = check(self.root, sha, (self.downstream, self.upstream))
        self.assertTrue(r['ancestry_passed'])
        self.assertFalse(r['release_ready'])

    def test_dirty_tracked_source_refused(self):
        (self.root / 'base.txt').write_text('changed')
        r = check(self.root, self.downstream, (self.downstream,))
        self.assertFalse(r['ancestry_passed'])
        self.assertIn('dirty tracked worktree', r['problems'])

    def test_unknown_commit_is_rejected(self):
        r = check(self.root, 'a' * 40, (self.downstream,))
        self.assertFalse(r['ancestry_passed'])

    def test_incomplete_commit_id_is_rejected(self):
        r = check(self.root, 'abc', (self.downstream,))
        self.assertFalse(r['ancestry_passed'])

    def test_cli_machine_readable_and_nonzero(self):
        script = Path(__file__).with_name('check_candidate.py')
        result = subprocess.run([sys.executable, str(script), '--repo', str(self.root),
                                 '--candidate', self.downstream, '--require', self.upstream],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(json.loads(result.stdout)['release_ready'], False)


if __name__ == '__main__':
    unittest.main()
