#!/usr/bin/env bash
#
# Builds the VTA / VTC / PNM release binaries and uploads them to Cloudflare R2
# under both `latest/` and a versioned path
# (`<crate-version>-<git-short-sha>/`).
#
# Builds:
#   vta      — vta-service with config-seed features    (uploaded as vta/)
#   vta-k8s  — vta-service with k8s-secrets features    (uploaded as vta-k8s/)
#   vtc      — vtc-service with config-secret features  (uploaded as vtc/)
#   vtc-k8s  — vtc-service with k8s-secrets features    (uploaded as vtc-k8s/)
#   pnm      — pnm-cli                                  (uploaded as pnm/)
#
# Required env vars (export them, or put them in <repo>/.env):
#   R2_ACCESS_KEY_ID
#   R2_SECRET_ACCESS_KEY
#   R2_ACCOUNT_ID
#   R2_BUCKET
#
# Usage:
#   .scripts/build-and-upload.sh            # build + upload
#   .scripts/build-and-upload.sh --build-only
#   .scripts/build-and-upload.sh --dry-run  # build + print aws cmds, don't upload

set -euo pipefail

BUILD_ONLY=0
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --build-only) BUILD_ONLY=1 ;;
    --dry-run)    DRY_RUN=1 ;;
    -h|--help)
      sed -n '2,24p' "$0"
      exit 0
      ;;
    *)
      echo "unknown arg: $arg" >&2
      exit 2
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

for tool in cargo git jq; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done
if [[ $BUILD_ONLY -eq 0 ]]; then
  command -v aws >/dev/null || { echo "missing tool: aws (install aws-cli)" >&2; exit 1; }
fi

metadata="$(cargo metadata --no-deps --format-version 1)"

resolve_version() {
  local pkg="$1"
  local v
  v="$(printf '%s' "$metadata" | jq -r --arg p "$pkg" '.packages[] | select(.name==$p) | .version')"
  if [[ -z "$v" || "$v" == "null" ]]; then
    echo "Failed to resolve $pkg version" >&2
    exit 1
  fi
  printf '%s' "$v"
}

vta_version="$(resolve_version vta-service)"
vtc_version="$(resolve_version vtc-service)"
pnm_version="$(resolve_version pnm-cli)"
git_hash="$(git rev-parse --short HEAD)"

echo "==> versions: vta=${vta_version} vtc=${vtc_version} pnm=${pnm_version} git=${git_hash}"

echo "==> building vta-service (config-seed)"
cargo build --release --no-default-features \
  --features "setup,config-seed,didcomm,rest,cli-synthesis" \
  -p vta-service
cp target/release/vta target/release/vta-standard

echo "==> building vta-service (vault-secrets)"
cargo build --release --no-default-features \
  --features "setup,vault-secrets,didcomm,rest,cli-synthesis" \
  -p vta-service

echo "==> building vtc-service (config-secret)"
cargo build --release --no-default-features \
  --features "setup,config-secret,website,admin-ui" \
  -p vtc-service
cp target/release/vtc target/release/vtc-standard

echo "==> building vtc-service (vault-secrets)"
cargo build --release --no-default-features \
  --features "setup,vault-secrets,website,admin-ui" \
  -p vtc-service

echo "==> building pnm-cli"
cargo build --release --no-default-features \
  --features "config-session" \
  -p pnm-cli

for bin in target/release/vta-standard target/release/vta target/release/vtc-standard target/release/vtc target/release/pnm; do
  [[ -f "$bin" ]] || { echo "build succeeded but $bin missing" >&2; exit 1; }
done

if [[ $BUILD_ONLY -eq 1 ]]; then
  echo "==> --build-only set; skipping upload."
  exit 0
fi

for var in R2_ACCESS_KEY_ID R2_SECRET_ACCESS_KEY R2_ACCOUNT_ID R2_BUCKET; do
  if [[ -z "${!var:-}" ]]; then
    echo "missing env var: $var (set in shell or in <repo>/.env)" >&2
    exit 1
  fi
done

export AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY"
export AWS_DEFAULT_REGION="us-east-1"
ENDPOINT="https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com"

upload() {
  local src="$1" dest="$2"
  echo "==> uploading $src -> $dest"
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "    [dry-run] aws s3 cp $src $dest --endpoint-url $ENDPOINT"
  else
    aws s3 cp "$src" "$dest" --endpoint-url "$ENDPOINT"
  fi
}

upload "target/release/vta-standard" "s3://${R2_BUCKET}/vta/latest/vta"
upload "target/release/vta-standard" "s3://${R2_BUCKET}/vta/${vta_version}-${git_hash}/vta"

upload "target/release/vta"      "s3://${R2_BUCKET}/vta-k8s/latest/vta"
upload "target/release/vta"      "s3://${R2_BUCKET}/vta-k8s/${vta_version}-${git_hash}/vta"

upload "target/release/vtc-standard" "s3://${R2_BUCKET}/vtc/latest/vtc"
upload "target/release/vtc-standard" "s3://${R2_BUCKET}/vtc/${vtc_version}-${git_hash}/vtc"

upload "target/release/vtc"      "s3://${R2_BUCKET}/vtc-k8s/latest/vtc"
upload "target/release/vtc"      "s3://${R2_BUCKET}/vtc-k8s/${vtc_version}-${git_hash}/vtc"

upload "target/release/pnm"      "s3://${R2_BUCKET}/pnm/latest/pnm"
upload "target/release/pnm"      "s3://${R2_BUCKET}/pnm/${pnm_version}-${git_hash}/pnm"

echo "==> done."
