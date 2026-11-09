#!/usr/bin/env python3
"""Check a *local* integration candidate contains two reviewed parent commits.

This checks source ancestry, NOT Rust compilation, conductor behavior or release
readiness. Exits nonzero on any missing Git dependency or dirty tracked source.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

PARENTS = (
    'f2cacae8cd61c709af0deb4934de3a8eb76ccff3',  # Sprint 8
    '97988483e1eeca6ba53c3ce39aa94d3fb847bafd',  # reconciled Sprint 3
)


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], text=True,
                          capture_output=True, check=False)


def check(root, candidate, required=PARENTS):
    result = {'candidate': candidate, 'required': list(required),
              'ancestry_passed': False, 'release_ready': False, 'problems': []}
    errors = result['problems']
    if not re.fullmatch('[0-9a-f]{40}', candidate):
        errors.append('candidate must be full lowercase commit SHA')
        return result
    for sha in required:
        if not re.fullmatch('[0-9a-f]{40}', sha):
            errors.append('invalid required parent SHA: ' + sha)
    if errors:
        return result
    if git(root, 'rev-parse', '--is-inside-work-tree').stdout.strip() != 'true':
        errors.append('not in a local Git worktree')
        return result
    if git(root, 'status', '--porcelain', '--untracked-files=no').stdout.strip():
        errors.append('dirty tracked worktree')
    for sha in [candidate, *required]:
        resolved = git(root, 'rev-parse', '--verify', f'{sha}^{{commit}}')
        if resolved.returncode or resolved.stdout.strip() != sha:
            errors.append('commit is not locally available: ' + sha)
    if errors:
        return result
    for parent in required:
        r = git(root, 'merge-base', '--is-ancestor', parent, candidate)
        if r.returncode:
            errors.append(f'missing required ancestor: {parent}')
    if git(root, 'ls-files', '-u').stdout.strip():
        errors.append('unmerged index entries exist')
    result['ancestry_passed'] = not errors
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--repo', type=Path, default=Path('.'))
    ap.add_argument('--candidate', help='Exact candidate SHA; defaults to current HEAD')
    ap.add_argument('--require', action='append', default=None,
                    help='Full ancestor SHA to require; defaults to Sprint 8 and current Sprint 3')
    ap.add_argument('--output', type=Path)
    opts = ap.parse_args(argv)
    candidate = opts.candidate or git(opts.repo, 'rev-parse', 'HEAD').stdout.strip()
    report = check(opts.repo, candidate, tuple(opts.require) if opts.require else PARENTS)
    rendered = json.dumps(report, indent=2, sort_keys=True) + '\n'
    print(rendered, end='')
    if opts.output:
        opts.output.write_text(rendered, encoding='utf-8')
    return 0 if report['ancestry_passed'] else 3


if __name__ == '__main__':
    sys.exit(main())
