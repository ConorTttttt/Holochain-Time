#!/usr/bin/env python3
"""Independently re-pack the signed-quorum TEST-ONLY DNA on one exact commit.

Never deploy this DNA: public deterministic signing keys are insecure. Reuses
the signed runner's published public keys and recorded random network seed,
then regenerates the manifest from the checked-in placeholder DNA in a second
temporary detached worktree. Byte-compares both packed archives.
"""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from make_signed_test_manifest import make_manifest, ManifestError
from check_test_dna_config import check as preflight, ConfigError

FULL_SHA = re.compile(r"[a-f0-9]{40}\Z")
SEED = re.compile(r'network_seed: "DO-NOT-DEPLOY-signed-quorum-([a-f0-9]{16,64})"')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def execute(command, *, cwd=None, log=None):
    if log:
        with Path(log).open("ab") as stream:
            result = subprocess.run(command, cwd=cwd, stdout=stream,
                                    stderr=subprocess.STDOUT, check=False)
    else:
        result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode:
        raise ValueError(f"command failed ({result.returncode}): {command[0]}")
    return result


def compare(repo, signed_dir, output_dir, expected_sha):
    repo, signed_dir, output_dir = map(lambda p: Path(p).resolve(),
                                       (repo, signed_dir, output_dir))
    result = {
        "schema": "hc-vtime/dna-repack/v1",
        "expected_sha": expected_sha,
        "status": "FAIL",
        "operator_independence_proven": False,
        "deployment_safe": False,
        "checks": {},
        "reason": "incomplete",
    }
    if not FULL_SHA.fullmatch(expected_sha):
        raise ValueError("expected SHA must be a full lowercase 40-hex commit")
    if repo == output_dir or repo in output_dir.parents:
        raise ValueError("repack output must live outside the source repository")
    if output_dir.exists():
        raise ValueError("repack output must not overwrite an existing directory")
    output_dir.mkdir(parents=True)
    temporary = None
    added_worktree = False
    try:
        head = subprocess.check_output(["git", "-C", str(repo), "rev-parse",
                                        "--verify", "HEAD"], text=True).strip()
        if head != expected_sha:
            raise ValueError("checked-out repository SHA is not the required candidate")
        for name in ("vtime.dna", "dna.yaml", "keys-public.json", "provenance.txt"):
            if not (signed_dir / name).is_file():
                raise ValueError("signed runner did not produce " + name)
        provenance = (signed_dir / "provenance.txt").read_text(encoding="utf-8")
        if f"git_sha={expected_sha}\n" not in provenance + "\n":
            raise ValueError("signed DNA originated from a different Git SHA")
        if "signed_quorum_command_exit=0" not in provenance:
            raise ValueError("signed-quorum suite was not recorded as passed")
        if "conductor_smoke_command_exit=0" not in provenance:
            raise ValueError("conductor smoke suite was not recorded as passed")
        keys = json.loads((signed_dir / "keys-public.json").read_text(encoding="utf-8"))
        text = (signed_dir / "dna.yaml").read_text(encoding="utf-8")
        seed_match = SEED.search(text)
        if not seed_match:
            raise ValueError("signed test manifest lacks a safe, recorded seed")
        seed = seed_match.group(1)
        template = (repo / "dnas/vtime/workdir/dna.yaml").read_text(encoding="utf-8")
        regenerated = make_manifest(template, keys, seed)
        if regenerated != text:
            raise ValueError("signed runner manifest is not reproducible from this source and keys")
        preflight(regenerated)
        result["checks"]["manifest_match"] = True
        result["checks"]["source_template_sha256"] = hashlib.sha256(
            template.encode("utf-8")).hexdigest()
        result["checks"]["signed_manifest_sha256"] = digest(signed_dir / "dna.yaml")
        result["checks"]["signed_dna_sha256"] = digest(signed_dir / "vtime.dna")

        temporary = Path(tempfile.mkdtemp(prefix="hc-vtime-repack-",
                                          dir=str(repo.parent)))
        temporary.rmdir()
        execute(["git", "-C", str(repo), "worktree", "add", "--quiet",
                 "--detach", str(temporary), expected_sha],
                log=output_dir / "repack.log")
        added_worktree = True
        (temporary / "target").symlink_to(repo / "target", target_is_directory=True)
        (temporary / "dnas/vtime/workdir/dna.yaml").write_text(
            regenerated, encoding="utf-8")
        execute(["python3", "scripts/check_test_dna_config.py", "--manifest",
                 "dnas/vtime/workdir/dna.yaml"], cwd=temporary,
                log=output_dir / "repack.log")
        execute(["hc", "dna", "pack", "dnas/vtime/workdir"], cwd=temporary,
                log=output_dir / "repack.log")
        fresh = temporary / "dnas/vtime/workdir/vtime.dna"
        if not fresh.is_file() or not fresh.stat().st_size:
            raise ValueError("second pack produced no DNA archive")
        shutil.copyfile(fresh, output_dir / "fresh-vtime.dna")
        result["checks"]["fresh_dna_sha256"] = digest(output_dir / "fresh-vtime.dna")
        result["checks"]["archive_byte_identical"] = (
            (signed_dir / "vtime.dna").read_bytes() ==
            (output_dir / "fresh-vtime.dna").read_bytes()
        )
        if not result["checks"]["archive_byte_identical"]:
            raise ValueError("independently packed DNA differs byte-for-byte")
        result["status"] = "PASS"
        result["reason"] = "independent fresh pack reproduces the exact signed-quorum test DNA"
    except (OSError, ValueError, ManifestError, ConfigError,
            subprocess.CalledProcessError, json.JSONDecodeError) as error:
        result["reason"] = str(error)
    finally:
        if added_worktree:
            subprocess.run(["git", "-C", str(repo), "worktree", "remove",
                            "--force", str(temporary)], capture_output=True,
                           check=False)
        if temporary and temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
        (output_dir / "dna-comparison.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--signed-report", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument("--expected-sha", required=True)
    opts = ap.parse_args(argv)
    try:
        result = compare(opts.repo, opts.signed_report, opts.output_dir,
                         opts.expected_sha)
    except (OSError, ValueError) as error:
        print("BLOCKED: " + str(error), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
