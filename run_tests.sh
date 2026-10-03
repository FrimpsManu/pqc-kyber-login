#!/bin/sh
# Run every test and save the output to evidence/:
#   1. the official Kyber self-tests and test-vector check (C, kyber/ref)
#   2. the Python/website test suite (pytest)
set -u
cd "$(dirname "$0")"
PY=${PYTHON:-.venv/bin/python}
OUT=evidence/official_kyber_tests.txt

{
  echo "Official Kyber reference tests - $(date -u '+%Y-%m-%d %H:%M:%S UTC') - $(uname -sm)"
  echo
  # -z noexecstack from the upstream Makefile is not supported by the macOS linker.
  make -C kyber/ref -s test CFLAGS="-Wall -Wextra -Wpedantic -O3 -fomit-frame-pointer"
  for k in 512 768 1024; do
    echo "== test_kyber$k (1000 key generations, encapsulations, decapsulations) =="
    ./kyber/ref/test/test_kyber$k && echo "result: PASS" || echo "result: FAIL"
    echo
  done
  echo "== test_vectors: SHA-256 of output vs. published kyber/SHA256SUMS =="
  for k in 512 768 1024; do
    got=$(./kyber/ref/test/test_vectors$k | shasum -a 256 | cut -d' ' -f1)
    want=$(grep "tvecs$k\$" kyber/SHA256SUMS | cut -d' ' -f1)
    [ "$got" = "$want" ] && r=PASS || r=FAIL
    echo "Kyber$k  got $got  expected $want  $r"
  done
} 2>&1 | tee "$OUT"

echo
"$PY" -m pytest -v tests 2>&1 | tee evidence/test_results.txt
