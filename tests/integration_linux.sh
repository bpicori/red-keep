#!/usr/bin/env bash
# Integration tests for red-keep on Linux.
# Exercises full CLI stack: parsing, profile validation, profile generation, Linux sandbox trampoline.
# Requires: Linux, Go toolchain. Use --skip-network to skip network tests.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$REPO_ROOT/bin/red-keep"
CLEANUP_DIRS=()
SKIP_NETWORK=false

PASS=0
FAIL=0
SKIP=0

if [[ -t 1 ]]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  NC='\033[0m'
else
  RED=''
  GREEN=''
  YELLOW=''
  NC=''
fi

pass() {
  ((PASS++)) || true
  echo -e "${GREEN}PASS${NC} $1"
}

fail() {
  ((FAIL++)) || true
  echo -e "${RED}FAIL${NC} $1"
  [[ -n "${2:-}" ]] && echo -e "  ${RED}$2${NC}"
}

skip() {
  ((SKIP++)) || true
  echo -e "${YELLOW}SKIP${NC} $1"
  [[ -n "${2:-}" ]] && echo -e "  ${YELLOW}$2${NC}"
}

run_red_keep() {
  local stdout_file stderr_file
  stdout_file=$(mktemp)
  stderr_file=$(mktemp)
  set +e
  "$BINARY" "$@" >"$stdout_file" 2>"$stderr_file"
  RK_EXIT=$?
  set -e
  RK_STDOUT=$(cat "$stdout_file")
  RK_STDERR=$(cat "$stderr_file")
  rm -f "$stdout_file" "$stderr_file"
}

resolve_path() {
  python3 -c "import os, sys; print(os.path.realpath(sys.argv[1]))" "$1"
}

register_cleanup() {
  CLEANUP_DIRS+=("$1")
}

cleanup() {
  for d in "${CLEANUP_DIRS[@]}"; do
    [[ -d "$d" ]] && rm -rf "$d"
  done
}
trap cleanup EXIT

for arg in "$@"; do
  if [[ "$arg" == "--skip-network" ]]; then
    SKIP_NETWORK=true
  fi
done

check_prereqs() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "Error: This script requires Linux."
    exit 1
  fi

  if ! command -v go &>/dev/null; then
    echo "Error: Go toolchain is required to build the binary."
    exit 1
  fi

  if ! command -v curl &>/dev/null; then
    echo "Warning: curl not found. Network tests will be skipped."
    SKIP_NETWORK=true
  fi
}

build_binary() {
  echo "Building red-keep..."
  (cd "$REPO_ROOT" && make build)
  if [[ ! -x "$BINARY" ]]; then
    echo "Error: Binary not found at $BINARY"
    exit 1
  fi
  echo "Binary ready: $BINARY"
  echo ""
}

check_kernel_capabilities() {
  run_red_keep run -- /bin/echo cap-probe
  if [[ $RK_EXIT -eq 0 ]]; then
    return
  fi

  if [[ "$RK_STDERR" == *"landlock unavailable"* ]] || [[ "$RK_STDERR" == *"seccomp unavailable"* ]]; then
    echo "Kernel capabilities unavailable for Linux sandbox. Skipping integration suite."
    echo "Details: $RK_STDERR"
    exit 0
  fi

  echo "Error: capability probe failed unexpectedly."
  echo "stderr: $RK_STDERR"
  exit 1
}

test_basic_echo() {
  run_red_keep run -- /bin/echo hello
  if [[ $RK_EXIT -eq 0 ]] && [[ "$RK_STDOUT" == *"hello"* ]]; then
    pass "test_basic_echo"
  else
    fail "test_basic_echo" "exit=$RK_EXIT stdout=$RK_STDOUT stderr=$RK_STDERR"
  fi
}

test_nonzero_exit() {
  run_red_keep run -- /usr/bin/false
  if [[ $RK_EXIT -ne 0 ]]; then
    pass "test_nonzero_exit"
  else
    fail "test_nonzero_exit" "expected non-zero exit, got $RK_EXIT"
  fi
}

test_read_allowed() {
  local dir
  dir=$(mktemp -d)
  register_cleanup "$dir"
  echo "sandbox-ok" >"$dir/hello.txt"

  run_red_keep run --allow-read "$dir" -- /bin/cat "$dir/hello.txt"
  if [[ $RK_EXIT -eq 0 ]] && [[ "$RK_STDOUT" == *"sandbox-ok"* ]]; then
    pass "test_read_allowed"
  else
    fail "test_read_allowed" "exit=$RK_EXIT stdout=$RK_STDOUT stderr=$RK_STDERR"
  fi
}

test_read_denied() {
  local dir file
  dir=$(mktemp -d /var/tmp/red-keep-integ-XXXXXXXX)
  register_cleanup "$dir"
  file="$dir/secret.txt"
  echo "secret" >"$file"

  run_red_keep run -- /bin/cat "$file"
  if [[ $RK_EXIT -ne 0 ]]; then
    pass "test_read_denied"
  else
    fail "test_read_denied" "exit=$RK_EXIT stderr=$RK_STDERR"
  fi
}

test_write_allowed() {
  local dir outfile
  dir=$(mktemp -d)
  register_cleanup "$dir"
  outfile="$dir/out.txt"

  run_red_keep run --allow-exec --allow-rw "$dir" -- /bin/sh -c "echo written > $outfile"
  if [[ $RK_EXIT -eq 0 ]] && [[ -f "$outfile" ]] && [[ "$(cat "$outfile")" == *"written"* ]]; then
    pass "test_write_allowed"
  else
    fail "test_write_allowed" "exit=$RK_EXIT stderr=$RK_STDERR"
  fi
}

test_write_denied() {
  local dir outfile
  dir=$(mktemp -d /var/tmp/red-keep-integ-XXXXXXXX)
  register_cleanup "$dir"
  outfile="$dir/out.txt"

  run_red_keep run --allow-exec --allow-read "$dir" -- /bin/sh -c "echo nope > $outfile"
  if [[ $RK_EXIT -ne 0 ]] && [[ ! -f "$outfile" ]]; then
    pass "test_write_denied"
  else
    fail "test_write_denied" "exit=$RK_EXIT file_should_not_exist"
  fi
}

test_sensitive_path_rejected() {
  run_red_keep run --allow-read /etc -- /bin/cat /etc/passwd
  if [[ $RK_EXIT -ne 0 ]] && [[ "$RK_STDERR" == *"sensitive"* ]]; then
    pass "test_sensitive_path_rejected"
  else
    fail "test_sensitive_path_rejected" "expected sensitive-path validation failure, exit=$RK_EXIT stderr=$RK_STDERR"
  fi
}

test_fork_denied() {
  run_red_keep run -- /bin/sh -c "echo a | cat"
  if [[ $RK_EXIT -ne 0 ]]; then
    pass "test_fork_denied"
  else
    fail "test_fork_denied" "expected non-zero exit when fork denied"
  fi
}

test_fork_allowed() {
  run_red_keep run --allow-exec -- /bin/sh -c "echo piped | /bin/cat"
  if [[ $RK_EXIT -eq 0 ]] && [[ "$RK_STDOUT" == *"piped"* ]]; then
    pass "test_fork_allowed"
  else
    fail "test_fork_allowed" "exit=$RK_EXIT stdout=$RK_STDOUT stderr=$RK_STDERR"
  fi
}

test_network_denied() {
  run_red_keep run --allow-exec -- /usr/bin/curl -s --max-time 3 https://example.com
  if [[ $RK_EXIT -ne 0 ]]; then
    pass "test_network_denied"
  else
    fail "test_network_denied" "expected non-zero exit when network denied"
  fi
}

test_network_allowed() {
  run_red_keep run --allow-exec --allow-net -- /usr/bin/curl -s -o /dev/null -w "%{http_code}" --max-time 5 https://example.com
  if [[ $RK_EXIT -eq 0 ]] && [[ "$(echo "$RK_STDOUT" | tr -d '[:space:]')" == "200" ]]; then
    pass "test_network_allowed"
  else
    fail "test_network_allowed" "exit=$RK_EXIT stdout=$RK_STDOUT stderr=$RK_STDERR"
  fi
}

test_domain_allow_filter() {
  run_red_keep run --allow-exec --allow-domain example.com -- /usr/bin/curl -s -o /dev/null -w "%{http_code}" --max-time 5 https://example.com
  if [[ $RK_EXIT -eq 0 ]] && [[ "$(echo "$RK_STDOUT" | tr -d '[:space:]')" == "200" ]]; then
    pass "test_domain_allow_filter"
  else
    fail "test_domain_allow_filter" "exit=$RK_EXIT stdout=$RK_STDOUT stderr=$RK_STDERR"
  fi
}

test_workdir() {
  local dir
  dir=$(mktemp -d)
  register_cleanup "$dir"

  run_red_keep run --dir "$dir" -- /bin/pwd
  local got want
  got=$(resolve_path "$(echo "$RK_STDOUT" | tr -d '[:space:]')")
  want=$(resolve_path "$dir")
  if [[ $RK_EXIT -eq 0 ]] && [[ "$got" == "$want" ]]; then
    pass "test_workdir"
  else
    fail "test_workdir" "exit=$RK_EXIT got=$got want=$want"
  fi
}

test_show_profile_default() {
  run_red_keep run --show-profile -- /bin/echo test
  if [[ $RK_EXIT -eq 0 ]] && \
     [[ "$RK_STDOUT" == *"engine=landlock+seccomp"* ]] && \
     [[ "$RK_STDOUT" == *"default=deny"* ]] && \
     [[ "$RK_STDOUT" == *"process.fork=deny"* ]] && \
     [[ "$RK_STDOUT" == *"network=deny"* ]]; then
    pass "test_show_profile_default"
  else
    fail "test_show_profile_default" "missing expected Linux profile content"
  fi
}

test_show_profile_allow_net() {
  run_red_keep run --show-profile --allow-net -- /bin/echo test
  if [[ $RK_EXIT -eq 0 ]] && \
     [[ "$RK_STDOUT" == *"network=allow"* ]] && \
     [[ "$RK_STDOUT" != *"network=deny"* ]]; then
    pass "test_show_profile_allow_net"
  else
    fail "test_show_profile_allow_net" "stdout=$RK_STDOUT"
  fi
}

test_show_profile_read_path() {
  run_red_keep run --show-profile --allow-read /tmp/test-read -- /bin/echo test
  if [[ $RK_EXIT -eq 0 ]] && [[ "$RK_STDOUT" == *"allow.read=/tmp/test-read"* ]]; then
    pass "test_show_profile_read_path"
  else
    fail "test_show_profile_read_path" "missing read path rule"
  fi
}

test_no_command() {
  run_red_keep run
  if [[ $RK_EXIT -eq 2 ]] && [[ "$RK_STDERR" == *"no command"* ]]; then
    pass "test_no_command"
  else
    fail "test_no_command" "exit=$RK_EXIT stderr=$RK_STDERR"
  fi
}

test_relative_path_rejected() {
  run_red_keep run --allow-read ./relative -- /bin/echo test
  if [[ $RK_EXIT -ne 0 ]] && [[ "$RK_STDERR" == *"absolute"* ]]; then
    pass "test_relative_path_rejected"
  else
    fail "test_relative_path_rejected" "exit=$RK_EXIT stderr=$RK_STDERR"
  fi
}

test_conflicting_net_flags() {
  run_red_keep run --allow-net --allow-domain example.com -- /bin/echo test
  if [[ $RK_EXIT -ne 0 ]] && [[ "$RK_STDERR" == *"cannot be combined"* ]]; then
    pass "test_conflicting_net_flags"
  else
    fail "test_conflicting_net_flags" "exit=$RK_EXIT stderr=$RK_STDERR"
  fi
}

test_version() {
  run_red_keep version
  if [[ $RK_EXIT -eq 0 ]] && [[ "$RK_STDOUT" == *"0.1.0"* ]]; then
    pass "test_version"
  else
    fail "test_version" "exit=$RK_EXIT stdout=$RK_STDOUT"
  fi
}

test_help() {
  run_red_keep help
  if [[ $RK_EXIT -eq 0 ]] && [[ "$RK_STDERR" == *"Usage:"* ]] && [[ "$RK_STDERR" == *"Commands:"* ]]; then
    pass "test_help"
  else
    fail "test_help" "exit=$RK_EXIT stderr=$RK_STDERR"
  fi
}

summary() {
  echo ""
  echo "--- Summary ---"
  echo -e "${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, ${YELLOW}$SKIP skipped${NC}"
  if [[ $FAIL -gt 0 ]]; then
    exit 1
  fi
  exit 0
}

main() {
  check_prereqs
  build_binary
  check_kernel_capabilities

  echo "Running Linux integration tests..."
  echo ""

  test_basic_echo
  test_nonzero_exit
  test_read_allowed
  test_read_denied
  test_write_allowed
  test_write_denied
  test_sensitive_path_rejected
  test_fork_denied
  test_fork_allowed
  test_workdir
  test_show_profile_default
  test_show_profile_allow_net
  test_show_profile_read_path
  test_no_command
  test_relative_path_rejected
  test_conflicting_net_flags
  test_version
  test_help
  test_network_denied

  if [[ "$SKIP_NETWORK" == true ]]; then
    skip "test_network_allowed" "network tests skipped (--skip-network or no curl)"
    skip "test_domain_allow_filter" "network tests skipped"
  else
    test_network_allowed
    test_domain_allow_filter
  fi

  summary
}

main "$@"
