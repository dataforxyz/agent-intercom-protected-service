#!/bin/sh
set -eu

export TZ=UTC
export LC_ALL=C
export LANG=C
export SOURCE_DATE_EPOCH=0
export CARGO_NET_OFFLINE=true
export NPM_CONFIG_OFFLINE=true
umask 077

if [ "$(id -u)" -eq 0 ]; then
  echo "error: package determinism proof must run as an ordinary non-root user" >&2
  exit 1
fi

if [ "${RUSTUP_TOOLCHAIN+x}" = x ]; then
  echo "error: RUSTUP_TOOLCHAIN overrides are forbidden; provide already-active direct Rust 1.97.1 tools" >&2
  exit 1
fi
unset RUSTUP_TOOLCHAIN

direct_tool() {
  tool_name=$1
  tool_path=$(command -v "$tool_name") || {
    echo "error: required tool is not installed: $tool_name" >&2
    exit 1
  }
  case "$tool_path" in
    /*) ;;
    *)
      echo "error: $tool_name must resolve to an absolute executable path (found: $tool_path)" >&2
      exit 1
      ;;
  esac
  if [ ! -x "$tool_path" ]; then
    echo "error: $tool_name is not executable: $tool_path" >&2
    exit 1
  fi
  printf '%s\n' "$tool_path"
}

direct_rust_tool() {
  tool_name=$1
  tool_path=$(direct_tool "$tool_name")
  resolved_path=$(readlink -f -- "$tool_path") || {
    echo "error: cannot resolve $tool_name executable: $tool_path" >&2
    exit 1
  }
  case "$resolved_path" in
    */rustup|*/rustup.exe)
      echo "error: $tool_name resolves to a rustup shim; select no toolchain and install nothing during this proof" >&2
      exit 1
      ;;
  esac
  if [ ! -x "$resolved_path" ]; then
    echo "error: resolved $tool_name is not executable: $resolved_path" >&2
    exit 1
  fi
  printf '%s\n' "$resolved_path"
}

rustc_path=$(direct_rust_tool rustc)
cargo_path=$(direct_rust_tool cargo)
node_path=$(direct_tool node)
npm_path=$(direct_tool npm)

rustc_version=$("$rustc_path" --version)
set -- $rustc_version
if [ "$#" -lt 2 ] || [ "$1" != rustc ] || [ "$2" != 1.97.1 ]; then
  echo "error: direct rustc must be exactly 1.97.1 (found: $rustc_version)" >&2
  exit 1
fi

cargo_version=$("$cargo_path" --version)
set -- $cargo_version
if [ "$#" -lt 2 ] || [ "$1" != cargo ] || [ "$2" != 1.97.1 ]; then
  echo "error: direct cargo must be exactly 1.97.1 (found: $cargo_version)" >&2
  exit 1
fi

node_version=$("$node_path" --version)
if [ "$node_version" != v26.3.0 ]; then
  echo "error: direct Node.js must be exactly v26.3.0 (found: $node_version)" >&2
  exit 1
fi

npm_version=$("$npm_path" --version)
if [ "$npm_version" != 11.16.0 ]; then
  echo "error: direct npm must be exactly 11.16.0 (found: $npm_version)" >&2
  exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)

scratch=
cleanup() {
  case "${scratch:-}" in
    /tmp/agent-intercom-repro.*)
      rm -rf -- "$scratch"
      ;;
  esac
}
on_signal() {
  trap - EXIT
  cleanup
  exit 1
}
trap cleanup EXIT
trap on_signal HUP INT TERM

scratch=$(mktemp -d /tmp/agent-intercom-repro.XXXXXXXXXX)
case "$scratch" in
  "$repo_root"|"$repo_root"/*)
    echo "error: temporary state must be outside the source tree" >&2
    exit 1
    ;;
esac

source_snapshot="$scratch/source.tar"
(
  cd -- "$repo_root"
  tar --sort=name \
    --mtime="@$SOURCE_DATE_EPOCH" \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --format=ustar \
    --exclude='./.git' \
    --exclude='./target' \
    -cf "$source_snapshot" .
)

run_one=$(mktemp -d "$scratch/one.XXXXXXXXXX")
run_two=$(mktemp -d "$scratch/two.XXXXXXXXXX")

make_source_copy() (
  run_root=$1
  source_dir="$run_root/source"
  mkdir -p -- "$source_dir"
  tar -C "$source_dir" -xf "$source_snapshot"
  if [ -e "$source_dir/.git" ] || [ -e "$source_dir/target" ]; then
    echo "error: source copy contains excluded repository state" >&2
    exit 1
  fi
)

package_source_copy() (
  run_root=$1
  source_dir="$run_root/source"
  isolated_home="$run_root/home"
  cargo_home="$run_root/cargo-home"
  cargo_target="$run_root/cargo-target"
  npm_cache="$run_root/npm-cache"
  npm_destination="$run_root/npm-package"

  mkdir -p -- \
    "$isolated_home" \
    "$cargo_home" \
    "$cargo_target" \
    "$npm_cache" \
    "$npm_destination"

  cd -- "$source_dir"
  HOME="$isolated_home" \
    CARGO_HOME="$cargo_home" \
    CARGO_TARGET_DIR="$cargo_target" \
    RUSTC="$rustc_path" \
    "$cargo_path" package --locked --offline --quiet
  HOME="$isolated_home" \
    NPM_CONFIG_CACHE="$npm_cache" \
    "$npm_path" pack . \
      --ignore-scripts \
      --offline \
      --silent \
      --pack-destination "$npm_destination" >/dev/null
)

make_source_copy "$run_one"
make_source_copy "$run_two"
package_source_copy "$run_one"
package_source_copy "$run_two"

cargo_name=agent-intercom-protected-service-0.1.0.crate
npm_name=dataforxyz-agent-intercom-protected-service-contracts-0.1.0.tgz
cargo_one="$run_one/cargo-target/package/$cargo_name"
cargo_two="$run_two/cargo-target/package/$cargo_name"
npm_one="$run_one/npm-package/$npm_name"
npm_two="$run_two/npm-package/$npm_name"

for artifact in "$cargo_one" "$cargo_two" "$npm_one" "$npm_two"; do
  if [ ! -f "$artifact" ]; then
    echo "error: expected package was not produced: $artifact" >&2
    exit 1
  fi
done

cmp -- "$cargo_one" "$cargo_two"
cmp -- "$npm_one" "$npm_two"

cargo_sha_one=$(sha256sum "$cargo_one")
cargo_sha_one=${cargo_sha_one%% *}
cargo_sha_two=$(sha256sum "$cargo_two")
cargo_sha_two=${cargo_sha_two%% *}
npm_sha_one=$(sha256sum "$npm_one")
npm_sha_one=${npm_sha_one%% *}
npm_sha_two=$(sha256sum "$npm_two")
npm_sha_two=${npm_sha_two%% *}

if [ "$cargo_sha_one" != "$cargo_sha_two" ] || [ "$npm_sha_one" != "$npm_sha_two" ]; then
  echo "error: isolated package-run SHA-256 digests differ" >&2
  exit 1
fi

tar -tzf "$cargo_one" | sort >"$run_one/cargo.inventory"
tar -tzf "$cargo_two" | sort >"$run_two/cargo.inventory"
tar -tzf "$npm_one" | sort >"$run_one/npm.inventory"
tar -tzf "$npm_two" | sort >"$run_two/npm.inventory"

cmp -- "$run_one/cargo.inventory" "$run_two/cargo.inventory"
cmp -- "$run_one/npm.inventory" "$run_two/npm.inventory"
diff -u "$repo_root/packaging/cargo-package-files.txt" "$run_one/cargo.inventory"
diff -u "$repo_root/packaging/npm-package-files.txt" "$run_one/npm.inventory"

echo "Cargo package SHA-256: $cargo_sha_one"
echo "npm package SHA-256:   $npm_sha_one"
echo "Exact-tool package determinism across isolated source/home/cache trees verified."
