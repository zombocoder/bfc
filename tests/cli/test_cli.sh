#!/bin/sh
#
# Copyright 2021 zombocoder (Taras Havryliak)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# End-to-end tests for the bfc CLI: directory paths on extract (#18) and the
# password / key-file options shared by create, extract and verify (#19).
#
# usage: test_cli.sh <path/to/bfc> <path/to/make_symlink_parent>

BFC=$1
MAKE_SYMLINK_PARENT=$2

if [ ! -x "$BFC" ] || [ ! -x "$MAKE_SYMLINK_PARENT" ]; then
  echo "usage: $0 <bfc> <make_symlink_parent>" >&2
  exit 2
fi

T=$(mktemp -d "${TMPDIR:-/tmp}/bfc-cli-test.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT
cd "$T" || exit 2

failures=0
tests=0

ok() {
  tests=$((tests + 1))
  echo "ok - $1"
}

not_ok() {
  tests=$((tests + 1))
  failures=$((failures + 1))
  echo "not ok - $1"
}

check() {
  # check <description> <command...>
  desc=$1
  shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else not_ok "$desc"; fi
}

check_fails() {
  desc=$1
  shift
  if "$@" >/dev/null 2>&1; then not_ok "$desc"; else ok "$desc"; fi
}

# Run a command and keep its stderr in $T/err for later inspection
run() {
  "$@" >"$T/out" 2>"$T/err"
}

# --- test data --------------------------------------------------------------

mkdir -p src/a src/b src/a/deep
echo "from a" >src/a/same.txt
echo "from b" >src/b/same.txt
echo "deep" >src/a/deep/file.txt
echo "top" >src/top.txt
"$BFC" create t.bfc src >/dev/null || { echo "Bail out! cannot create t.bfc"; exit 1; }

# --- #18: directory paths ---------------------------------------------------

mkdir o1
check "extract preserves directory paths by default" \
  "$BFC" extract -C o1 t.bfc
check "  src/a/same.txt has the content from src/a" grep -qx "from a" o1/src/a/same.txt
check "  src/b/same.txt has the content from src/b" grep -qx "from b" o1/src/b/same.txt
check "  nested src/a/deep/file.txt is extracted" test -f o1/src/a/deep/file.txt
check_fails "  nothing is flattened into the output root" test -e o1/same.txt

mkdir o2
run "$BFC" extract -k -C o2 t.bfc
check "-k still works" test -f o2/src/a/same.txt
check "  -k prints a deprecation warning" grep -q "deprecated" "$T/err"

mkdir o3
check_fails "--flatten fails when two entries share a name" \
  "$BFC" extract --flatten -C o3 t.bfc
mkdir o4
check_fails "--flatten -f still refuses to overwrite one entry with another" \
  "$BFC" extract --flatten -f -C o4 t.bfc
check "  the first same.txt is kept intact" grep -qx "from a" o4/same.txt

mkdir -p u/x u/y
echo 1 >u/x/one.txt
echo 2 >u/y/two.txt
"$BFC" create u.bfc u >/dev/null
mkdir o5
check "--flatten extracts files without collisions" \
  "$BFC" extract --flatten -C o5 u.bfc
check "  files land in the output root" test -f o5/one.txt -a -f o5/two.txt
check_fails "  no empty directories are created" test -d o5/u -o -d o5/x

mkdir o6
check "extracting a single subtree keeps its path" \
  "$BFC" extract -C o6 t.bfc src/b
check "  src/b/same.txt is extracted" test -f o6/src/b/same.txt
check_fails "  src/a is not extracted" test -e o6/src/a/same.txt

# --- path safety -----------------------------------------------------------

mkdir outside o7
"$MAKE_SYMLINK_PARENT" sym.bfc "$T/outside" || { echo "Bail out! make_symlink_parent"; exit 1; }
run "$BFC" extract -C o7 sym.bfc
check_fails "extract fails on an entry below a symlink" test $? -eq 0
check "  the refusal names the symlink" grep -q "symlink" "$T/err"
check_fails "  nothing is written through the symlink" test -e outside/file.txt

# --- #17: file modes and umask ---------------------------------------------

# Permission bits of a path as octal, on both GNU and BSD stat
perm() {
  stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1" 2>/dev/null
}

check_perm() {
  # check_perm <description> <expected> <path>
  got=$(perm "$3")
  if [ "$got" = "$2" ]; then ok "$1"; else not_ok "$1 (got $got, expected $2)"; fi
}

mkdir -p m/opendir
echo w >m/world.txt
echo x >m/run.sh
echo r >m/readonly.txt
chmod 666 m/world.txt
chmod 755 m/run.sh
chmod 444 m/readonly.txt
chmod 777 m/opendir
"$BFC" create m.bfc m >/dev/null
chmod 755 m/opendir

mkdir p1
(umask 022 && "$BFC" extract -C p1 m.bfc >/dev/null 2>&1)
check_perm "extract applies the umask to a 0666 file" 644 p1/m/world.txt
check_perm "  executable bits are kept" 755 p1/m/run.sh
check_perm "  a read-only file stays read-only" 444 p1/m/readonly.txt
check_perm "  a new 0777 directory gets the umask" 755 p1/m/opendir

mkdir p2
(umask 077 && "$BFC" extract -C p2 m.bfc >/dev/null 2>&1)
check_perm "a stricter umask (077) is honoured for files" 600 p2/m/world.txt
check_perm "  and for directories" 700 p2/m/opendir

mkdir -p p3/m/opendir
chmod 750 p3/m/opendir
(umask 022 && "$BFC" extract -f -C p3 m.bfc >/dev/null 2>&1)
check_perm "an existing directory keeps its mode" 750 p3/m/opendir

mkdir p4
(umask 022 && "$BFC" extract --preserve-permissions -C p4 m.bfc >/dev/null 2>&1)
check_perm "--preserve-permissions keeps the archived file mode" 666 p4/m/world.txt
check_perm "  and the archived directory mode" 777 p4/m/opendir

mkdir -p p5/m/opendir
chmod 750 p5/m/opendir
(umask 022 && "$BFC" extract -f --preserve-permissions -C p5 m.bfc >/dev/null 2>&1)
check_perm "--preserve-permissions also applies to an existing directory" 777 p5/m/opendir

# --- #19: password and key-file options --------------------------------------

if "$BFC" create -p x probe.bfc src/top.txt 2>&1 | grep -q "Encryption support not available"; then
  echo "# bfc built without libsodium: skipping encryption tests"
else
  printf 'secret\n' >pass.txt
  printf '0123456789abcdef0123456789abcdef' >key.bin

  check "create -p encrypts with a password" "$BFC" create -p secret p.bfc src
  check "create --password encrypts with a password" "$BFC" create --password secret p2.bfc src
  check "create --password-file reads the password from a file" \
    "$BFC" create --password-file pass.txt pf.bfc src
  check "create -K encrypts with a key file" "$BFC" create -K key.bin k.bfc src

  run "$BFC" create -e secret e.bfc src
  check "create -e still works" test -f e.bfc
  check "  -e prints a deprecation warning" grep -q "deprecated" "$T/err"
  run "$BFC" create -k key.bin kold.bfc src
  check "create -k (key file) still works" test -f kold.bfc
  check "  -k prints a deprecation warning" grep -q "deprecated" "$T/err"

  check_fails "create rejects a password and a key file together" \
    "$BFC" create -p secret -K key.bin both.bfc src

  mkdir x1 x2 x3 x4 x5
  check "extract -p decrypts" "$BFC" extract -p secret -C x1 p.bfc
  check "  content is correct" grep -qx "from a" x1/src/a/same.txt
  check "extract --password-file decrypts" "$BFC" extract --password-file pass.txt -C x2 pf.bfc
  check "extract -K decrypts" "$BFC" extract -K key.bin -C x3 k.bfc
  check "extract reads --password-file from stdin" \
    sh -c "printf 'secret\n' | '$BFC' extract --password-file - -C x4 p.bfc"
  check_fails "extract with a wrong password fails" "$BFC" extract -p wrong -C x5 p.bfc
  check_fails "extract without credentials fails without waiting for input" \
    sh -c "'$BFC' extract -C x5 p.bfc </dev/null"

  check "verify --deep -p checks an encrypted container" "$BFC" verify --deep -p secret p.bfc
  check "verify --deep --password-file works" "$BFC" verify --deep --password-file pass.txt pf.bfc
  check "verify --deep -K works" "$BFC" verify --deep -K key.bin k.bfc
  check_fails "verify --deep with a wrong password fails" "$BFC" verify --deep -p wrong p.bfc
  check_fails "verify --deep without credentials fails" sh -c "'$BFC' verify --deep p.bfc </dev/null"
  check "verify --progress --deep works" "$BFC" verify --progress --deep -p secret p.bfc
  check_fails "verify -p needs a value" "$BFC" verify --deep -p
  run "$BFC" verify -p p.bfc
  check_fails "old 'verify -p <container>' fails loudly" test $? -eq 0
fi

echo "1..$tests"
if [ "$failures" -ne 0 ]; then
  echo "# $failures of $tests checks failed"
  exit 1
fi
echo "# all $tests checks passed"
