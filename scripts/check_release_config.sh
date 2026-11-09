#!/usr/bin/env bash
# GitHub-first offline release configuration checks only. NO deployment/funding.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONDONTWRITEBYTECODE=1
python3 -m unittest discover -s scripts -p 'test_deployment_preflight.py' -v
if python3 scripts/deployment_preflight.py    --environment production    --manifest deployment/environments/production.dna.example.yaml    --policy deployment/environments/production.policy.example.json; then
  echo 'BLOCKED: non-approved production example must never preflight' >&2
  exit 1
fi
echo 'Configuration safety tests completed (production deployment NOT authorized).'
