#!/usr/bin/env bash
# Copyright (c) 2026 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C

SH_NAME="$(basename "${0}")"
SH_LS="$(command -v ls)"
SH_PATCHELF="$(command -v patchelf)"
LIBDIR="${1}"
shift

if [ -z "${GUIX_BUILD_CONTAINER}" ]; then
  echo "${SH_NAME}: not in expected environment, goodbye!";
  exit 0;
elif [ ! "${SH_LS}" ]; then
  echo "${SH_NAME}: ls not found, cannot continue!";
  exit 1;
elif [ ! "${SH_PATCHELF}" ]; then
  echo "${SH_NAME}: patchelf not found, cannot continue!";
  exit 1;
elif [ -z "${LIBDIR}" ] || [ $# -eq 0 ]; then
  echo "Usage: ${SH_NAME} <libdir> <binary1> [binary2] ...";
  exit 1;
fi

# Get the interpreter from a known working binary
GUIX_INTERP="$("${SH_PATCHELF}" --print-interpreter "${SH_LS}" 2>/dev/null)"
if [ -z "${GUIX_INTERP}" ]; then
  echo "${SH_NAME}: could not detect interpreter, skipping";
  exit 1;
else
  echo "${SH_NAME}: detected interpreter ${GUIX_INTERP}"
fi


# Find and copy libgcc_s.so.1 into our lib directory
SH_GCC="$(command -v gcc)"
LIBGCC_SRC=""
if [ "${SH_GCC}" ]; then
  # Method 1: Ask gcc directly for the library path
  LIBGCC_PATH="$(gcc -print-file-name=libgcc_s.so.1 2>/dev/null)"
  if [ -f "${LIBGCC_PATH}" ]; then
    LIBGCC_SRC="${LIBGCC_PATH}";
  else
    # Method 2: Search relative to the gcc prefix
    GCC_PREFIX="$(dirname "$(dirname "${SH_GCC}")")"
    if [ -f "${GCC_PREFIX}/lib/libgcc_s.so.1" ]; then
      LIBGCC_SRC="${GCC_PREFIX}/lib/libgcc_s.so.1";
    fi
  fi
fi

if [ -z "${LIBGCC_SRC}" ] && [ -n "${LIBRARY_PATH}" ]; then
  # Method 3: Search LIBRARY_PATH
  IFS=':' read -ra LIB_PATHS <<< "${LIBRARY_PATH}"
  for libpath in "${LIB_PATHS[@]}"
  do
    if [ -f "${libpath}/libgcc_s.so.1" ]; then
      LIBGCC_SRC="${libpath}/libgcc_s.so.1";
      break;
    fi
  done
fi

# Resolve symlinks and copy it
if [ -n "${LIBGCC_SRC}" ]; then
  LIBGCC_REAL="$(readlink -f "${LIBGCC_SRC}")"
  echo "${SH_NAME}: copying libgcc_s.so.1 from ${LIBGCC_REAL}";
  cp "${LIBGCC_REAL}" "${LIBDIR}/libgcc_s.so.1";
else
  echo "${SH_NAME}: libgcc_s.so.1 not found, cannot continue!";
  exit 1;
fi

# RPATH just needs $ORIGIN/../lib as everything is self-contained
GUIX_RPATH="\$ORIGIN/../lib"
echo "${SH_NAME}: using RPATH ${GUIX_RPATH}"

for binary in "${@}"
do
  if [ -f "${binary}" ]; then
    echo "${SH_NAME}: patching ${binary}";
    "${SH_PATCHELF}" --set-interpreter "${GUIX_INTERP}" "${binary}";
    "${SH_PATCHELF}" --print-interpreter "${binary}"
    "${SH_PATCHELF}" --set-rpath "${GUIX_RPATH}" "${binary}";
    "${SH_PATCHELF}" --print-rpath "${binary}"
  fi
done
