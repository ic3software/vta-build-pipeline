#!/usr/bin/env bash
#
# Builds the VTA / VTC / PNM release binaries and uploads them to Cloudflare R2.
# A tagged release goes to `<tag>-<sha>/` and `latest/`; an untagged build
# goes to `<crate-version>-<sha>/` and `main/`. `<sha>` is the upstream commit
# the build came from — the tag's commit for a release, the upstream/main tip
# otherwise — not this fork's sync commit.
#
# Builds:
#   vta        — vta-service with config-seed features    (uploaded as vta/)
#   vta-k8s    — vta-service with k8s-secrets features    (uploaded as vta-k8s/)
#   vtc        — vtc-service with config-secret features  (uploaded as vtc/)
#   vtc-k8s    — vtc-service with k8s-secrets features    (uploaded as vtc-k8s/)
#   pnm-server — pnm-cli with config-session, tsp         (uploaded as pnm-server/)
#   pnm        — pnm-cli with default features            (uploaded as pnm/)
#
# Required env vars (export them, or put them in <repo>/.env):
#   R2_ACCESS_KEY_ID
#   R2_SECRET_ACCESS_KEY
#   R2_ACCOUNT_ID
#   R2_BUCKET
#
# Usage:
#   .scripts/build-and-upload.sh            # -> main/ + <version>-<sha>/
#   .scripts/build-and-upload.sh <tag>      # -> latest/ + <tag>-<sha>/
#   .scripts/build-and-upload.sh --build-only
#   .scripts/build-and-upload.sh --dry-run  # build + print aws cmds, don't upload

set -euo pipefail

BUILD_ONLY=0
DRY_RUN=0
TAG=""
for arg in "$@"; do
  case "$arg" in
    --build-only) BUILD_ONLY=1 ;;
    --dry-run)    DRY_RUN=1 ;;
    -h|--help)
      sed -n '2,/^$/p' "$0"
      exit 0
      ;;
    -*)
      echo "unknown arg: $arg" >&2
      exit 2
      ;;
    *)
      [[ -z "$TAG" ]] || { echo "unexpected extra arg: $arg" >&2; exit 2; }
      TAG="$arg"
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

# HEAD is this fork's sync commit, which means nothing in the upstream repo, so
# identify the build by the upstream commit it was made from: the tag's commit
# for a release, the upstream/main tip otherwise.
source_ref="${TAG:+refs/tags/${TAG}}"
source_ref="${source_ref:-upstream/main}"
if ! git_hash="$(git rev-parse -q --verify --short "${source_ref}^{commit}")"; then
  git_hash="$(git rev-parse --short HEAD)"
  echo "note: cannot resolve ${source_ref}; using HEAD ${git_hash} instead" >&2
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

echo "==> versions: vta=${vta_version} vtc=${vtc_version} pnm=${pnm_version} git=${git_hash}"

echo "==> building vta-service (config-seed, tsp)"
cargo build --release --no-default-features \
  --features "setup,config-seed,didcomm,rest,cli-synthesis,tsp" \
  -p vta-service
cp target/release/vta target/release/vta-standard

echo "==> building vta-service (vault-secrets, tsp)"
cargo build --release --no-default-features \
  --features "setup,vault-secrets,didcomm,rest,cli-synthesis,tsp" \
  -p vta-service

echo "==> building vtc-service (config-secret, tsp)"
cargo build --release --no-default-features \
  --features "setup,config-secret,website,admin-ui,tsp" \
  -p vtc-service
cp target/release/vtc target/release/vtc-standard

echo "==> building vtc-service (vault-secrets, tsp)"
cargo build --release --no-default-features \
  --features "setup,vault-secrets,website,admin-ui,tsp" \
  -p vtc-service

echo "==> building pnm-cli (config-session, tsp)"
cargo build --release --no-default-features \
  --features "config-session,tsp" \
  -p pnm-cli
cp target/release/pnm target/release/pnm-server

echo "==> building pnm-cli (default features)"
cargo build --release -p pnm-cli

for bin in target/release/vta-standard target/release/vta target/release/vtc-standard target/release/vtc target/release/pnm-server target/release/pnm; do
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

# Publish one binary: a tagged release goes to <tag>-<sha>/ + latest/; an
# untagged build goes to <version>-<sha>/ + main/.
publish() {
  local src="$1" name="$2" filename="$3" version_seg="$4"
  if [[ -n "$TAG" ]]; then
    upload "$src" "s3://${R2_BUCKET}/${name}/${TAG}-${git_hash}/${filename}"
    upload "$src" "s3://${R2_BUCKET}/${name}/latest/${filename}"
  else
    upload "$src" "s3://${R2_BUCKET}/${name}/${version_seg}/${filename}"
    upload "$src" "s3://${R2_BUCKET}/${name}/main/${filename}"
  fi
}

publish "target/release/vta-standard"  vta        vta "${vta_version}-${git_hash}"
publish "target/release/vta"           vta-k8s    vta "${vta_version}-${git_hash}"
publish "target/release/vtc-standard"  vtc        vtc "${vtc_version}-${git_hash}"
publish "target/release/vtc"           vtc-k8s    vtc "${vtc_version}-${git_hash}"
publish "target/release/pnm-server"    pnm-server pnm "${pnm_version}-${git_hash}"
publish "target/release/pnm"           pnm        pnm "${pnm_version}-${git_hash}"

echo "==> done."
