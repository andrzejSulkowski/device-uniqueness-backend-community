#!/usr/bin/env bash
# Copyright (C) 2026 Parity Technologies (UK) Ltd.
# SPDX-License-Identifier: GPL-3.0-only
#
# Write a fresh JWT signing seed and its public key into a local env file
# (default `.env`, created from `.env.example` when missing), plus a TURN_SECRET
# when that file selects TURN_PROVIDER=coturn (the dev quickstart does).
#
# Nothing ships a usable default for these: every value ever published as a
# dev default is refused at boot (http_common::config::reject_dev_secret), so
# each checkout generates its own. Existing non-empty values are kept unless
# --force is given, because replacing the seed invalidates every token the
# running stack has issued.
#
# Usage: scripts/dev_secrets.sh [--force] [ENV_FILE]
set -euo pipefail

force=false
if [[ "${1:-}" == "--force" ]]; then
  force=true
  shift
fi
env_file="${1:-.env}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -f "$env_file" ]]; then
  cp "$repo_root/.env.example" "$env_file"
  chmod 600 "$env_file"
  echo "created $env_file from .env.example"
fi

value_of() {
  sed -n "s/^$1=//p" "$env_file" | tail -n1
}

set_key() {
  local key="$1" value="$2"
  if grep -q "^${key}=" "$env_file"; then
    # Every occurrence: .env.example lists the public key once per verifier
    # section, and a later blank line would otherwise win.
    sed -i.bak "s|^${key}=.*|${key}=${value}|" "$env_file"
    rm -f "$env_file.bak"
  else
    printf '%s=%s\n' "$key" "$value" >>"$env_file"
  fi
}

# Values earlier versions of .env.example published. The services refuse them
# at boot, so an .env copied from one is treated like an empty one.
is_published() {
  case "$1" in
    0x0101010101010101010101010101010101010101010101010101010101010101 | \
      0101010101010101010101010101010101010101010101010101010101010101 | \
      AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE= | \
      ZGV2LW9ubHktdHVybi1zZWNyZXQtY2hhbmdlLW1l | \
      QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=)
      return 0
      ;;
  esac
  return 1
}

needs_value() {
  local current
  current="$(value_of "$1")"
  [[ -z "$current" || "$force" == true ]] || is_published "$current"
}

# TURN_SECRET first and independently: an .env from before this script existed
# may already carry a fresh JWT seed but still the refused TURN placeholder.
if [[ "$(value_of TURN_PROVIDER)" == "coturn" ]]; then
  if needs_value TURN_SECRET; then
    set_key TURN_SECRET "$(openssl rand -base64 32)"
    echo "wrote a fresh TURN_SECRET to $env_file (TURN_PROVIDER=coturn)"
  fi
fi

if ! needs_value JWT_ED25519_SECRET; then
  echo "$env_file already sets JWT_ED25519_SECRET; leaving it (pass --force to replace)"
  exit 0
fi

seed="$(openssl rand -hex 32)"
# Ed25519 public key from a raw seed: wrap it as a PKCS#8 DER private key
# (fixed 16-byte prefix for an Ed25519 key), export the SubjectPublicKeyInfo,
# and keep its last 32 bytes.
public_key="$(
  printf '302e020100300506032b657004220420%s' "$seed" \
    | xxd -r -p \
    | openssl pkey -inform DER -pubout -outform DER \
    | tail -c 32 \
    | xxd -p -c 64
)"
if [[ ${#public_key} -ne 64 ]]; then
  echo "failed to derive the Ed25519 public key (is openssl >= 1.1.1 installed?)" >&2
  exit 1
fi

set_key JWT_ED25519_SECRET "0x$seed"
set_key JWT_ED25519_PUBLIC_KEY "0x$public_key"
echo "wrote a fresh JWT_ED25519_SECRET and its JWT_ED25519_PUBLIC_KEY (0x$public_key) to $env_file"
