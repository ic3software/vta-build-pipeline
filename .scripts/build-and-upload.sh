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
# The six builds run as three concurrent groups, `vta` (vta-service x2), `vtc`
# (vtc-service x2) and `pnm` (pnm-cli x2). The three crates have no build
# dependency on one another, and the release profile (codegen-units = 1, thin
# LTO) makes the tail of every build a mostly single-threaded link, so running
# the groups side by side overlaps those tails. Each group gets its own
# --target-dir — cargo would otherwise serialise them on the build-directory
# lock. All live under target/ so `git clean -fd` during a sync leaves them
# alone. target/vtc and target/pnm are cold the first time (one full dependency
# compile each, 2.3 GB and 1.6 GB respectively) and warm after that.
#
# Measured warm on a 32-core box at 9-13 minutes, against 25+ minutes for the
# serial script. The total is always the slowest group, but which group that is
# depends on what the sync changed: a leaf-only change gives vta 7m6s, vtc
# 9m24s, pnm 3m19s (vtc leads, held up by an upstream build.rs bug that
# recompiles vtc-service in full every run), while a sync touching vta-sdk or
# vti-common gives vta 13m15s, vtc 9m55s, pnm 4m16s. vta-service sits on 16
# workspace crates to vtc-service's 5 and pnm-cli's 2, so a change at the root
# of the graph costs it far more than the other two, and it is then the long
# pole. pnm was split out of the vtc group because that group led at 12m0s.
#
# No cargo is capped, so during the dependency phase the three oversubscribe
# the cores; that phase is cheap and the tails are where the time goes.
#
# RAM is the hard gate. The three link tails overlap by design, so their peaks
# stack: measured at 12.35 GB concurrent (vta 5.70, vtc-service 3.52, pnm 3.13)
# against 5.85 GB for the largest link alone. Provision 16 GB. Below that, build
# serially instead (see 94e3729 for the pre-split script) — peak is then the
# single-link figure and fits in 8 GB. CARGO_BUILD_JOBS is worth setting on a
# small box for the dependency phase, but it does not reduce the peak: that is
# three single-threaded LTO links, one rustc process each, which -j does not
# divide.
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

# One target dir per concurrent group (see the header). `target` keeps the
# cache the serial script built up; `target/vtc` and `target/pnm` are new.
TARGET_VTA="target"
TARGET_VTC="target/vtc"
TARGET_PNM="target/pnm"

# Each variant pair builds into the same $td/release/<name>, so the first of
# the pair is copied aside before the second overwrites it.
build_vta() {
  local td="$1"

  echo "==> building vta-service (config-seed, tsp)"
  cargo build --release --target-dir "$td" --no-default-features \
    --features "setup,config-seed,didcomm,rest,cli-synthesis,tsp" \
    -p vta-service
  cp "$td/release/vta" "$td/release/vta-standard"

  echo "==> building vta-service (vault-secrets, tsp)"
  cargo build --release --target-dir "$td" --no-default-features \
    --features "setup,vault-secrets,didcomm,rest,cli-synthesis,tsp" \
    -p vta-service
}

build_vtc() {
  local td="$1"

  echo "==> building vtc-service (config-secret, tsp)"
  cargo build --release --target-dir "$td" --no-default-features \
    --features "setup,config-secret,website,admin-ui,tsp" \
    -p vtc-service
  cp "$td/release/vtc" "$td/release/vtc-standard"

  echo "==> building vtc-service (vault-secrets, tsp)"
  cargo build --release --target-dir "$td" --no-default-features \
    --features "setup,vault-secrets,website,admin-ui,tsp" \
    -p vtc-service
}

build_pnm() {
  local td="$1"

  echo "==> building pnm-cli (config-session, tsp)"
  cargo build --release --target-dir "$td" --no-default-features \
    --features "config-session,tsp" \
    -p pnm-cli
  cp "$td/release/pnm" "$td/release/pnm-server"

  echo "==> building pnm-cli (default features)"
  cargo build --release --target-dir "$td" -p pnm-cli
}

# Runs one group with every output line prefixed by its name, so the three
# interleaved logs stay readable. The prefixer is a process substitution rather
# than a pipe: a pipe would need `if fn | sed` or `fn | sed || ...` to read the
# status, and bash ignores `set -e` inside the function body in either of those
# contexts, so a failed first cargo build would not stop the group. Called this
# way the function runs under errexit as written, and the first failure ends
# the group with a non-zero status.
run_group() {
  local name="$1" fn="$2" td="$3"
  local start elapsed
  start=$SECONDS
  "$fn" "$td" > >(sed -u "s/^/[$name] /") 2>&1
  elapsed=$((SECONDS - start))
  echo "[$name] ==> group done in $((elapsed / 60))m$((elapsed % 60))s"
}

# All groups run to completion even if one fails, so a single run shows every
# error; the script then exits non-zero naming the group(s) that failed.
build_start=$SECONDS
echo "==> building in three concurrent groups: vta -> ${TARGET_VTA}/, vtc -> ${TARGET_VTC}/, pnm -> ${TARGET_PNM}/"
run_group vta build_vta "$TARGET_VTA" & pid_vta=$!
run_group vtc build_vtc "$TARGET_VTC" & pid_vtc=$!
run_group pnm build_pnm "$TARGET_PNM" & pid_pnm=$!

failed=()
wait "$pid_vta" || failed+=(vta)
wait "$pid_vtc" || failed+=(vtc)
wait "$pid_pnm" || failed+=(pnm)
build_elapsed=$((SECONDS - build_start))
if [[ ${#failed[@]} -gt 0 ]]; then
  echo "==> build FAILED after $((build_elapsed / 60))m$((build_elapsed % 60))s in group(s): ${failed[*]}" >&2
  exit 1
fi
echo "==> all groups done in $((build_elapsed / 60))m$((build_elapsed % 60))s"

for bin in \
  "$TARGET_VTA/release/vta-standard" "$TARGET_VTA/release/vta" \
  "$TARGET_VTC/release/vtc-standard" "$TARGET_VTC/release/vtc" \
  "$TARGET_PNM/release/pnm-server" "$TARGET_PNM/release/pnm"; do
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

publish "$TARGET_VTA/release/vta-standard" vta        vta "${vta_version}-${git_hash}"
publish "$TARGET_VTA/release/vta"          vta-k8s    vta "${vta_version}-${git_hash}"
publish "$TARGET_VTC/release/vtc-standard" vtc        vtc "${vtc_version}-${git_hash}"
publish "$TARGET_VTC/release/vtc"          vtc-k8s    vtc "${vtc_version}-${git_hash}"
publish "$TARGET_PNM/release/pnm-server"   pnm-server pnm "${pnm_version}-${git_hash}"
publish "$TARGET_PNM/release/pnm"          pnm        pnm "${pnm_version}-${git_hash}"

echo "==> done."
