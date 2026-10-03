#!/bin/sh
# Compile the official Kyber768 reference implementation (kyber/ref) into a
# shared library that the Python code loads with ctypes.
set -eu

cd "$(dirname "$0")"
REF=kyber/ref
OUT=pqc/lib
mkdir -p "$OUT"

${CC:-cc} -shared -fPIC -O3 -fomit-frame-pointer -Wall -Wextra -DKYBER_K=3 \
  $REF/kem.c $REF/indcpa.c $REF/polyvec.c $REF/poly.c $REF/ntt.c $REF/cbd.c \
  $REF/reduce.c $REF/verify.c $REF/fips202.c $REF/symmetric-shake.c \
  $REF/randombytes.c \
  -o $OUT/libkyber768.so

echo "built $OUT/libkyber768.so"
