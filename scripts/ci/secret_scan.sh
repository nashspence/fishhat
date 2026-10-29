#!/usr/bin/env bash
set -euo pipefail
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]]
timeout_helper="$(cd "$(dirname "$0")/.." && pwd)/validation_timeouts.py"
connect_budget="$(python3 "$timeout_helper" seconds 10)"
total_budget="$(python3 "$timeout_helper" seconds 120)"
tmp="$(mktemp -d)"; trap 'rm -rf -- "$tmp"' EXIT
curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout "$connect_budget" --max-time "$total_budget" \
  https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz \
  -o "$tmp/gitleaks.tar.gz"
printf '%s  %s\n' 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb "$tmp/gitleaks.tar.gz" | sha256sum -c -
tar -xzf "$tmp/gitleaks.tar.gz" -C "$tmp" gitleaks
"$tmp/gitleaks" git --redact=100 --no-banner --log-opts='--all' .
