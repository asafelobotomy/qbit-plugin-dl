#!/usr/bin/env bash
# Build qbit-plugin-dl-*.AppImage using python-appimage.
#
# Supply-chain notes: Python packages come from requirements/*.lock.txt
# (exported from uv.lock, installed with --require-hashes) and every
# downloaded binary is pinned by sha256.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VENV="${ROOT}/.venv-appimage"
CLEANUP_PATHS=()

cleanup() {
  local path
  for path in "${CLEANUP_PATHS[@]}"; do
    rm -rf "${path}"
  done
}
trap cleanup EXIT

# --- Pinned third-party build inputs ------------------------------------------
# Every download below is checked against a sha256. To bump one, update the
# URL and hash together (GitHub shows asset digests on the release page).
# The base Python image is replaced upstream on each patch release, so expect
# to bump it when the old asset disappears (override via env if needed).
ARCH="$(uname -m)"
if [[ "${ARCH}" != "x86_64" ]]; then
  echo "Pinned build inputs are x86_64-only (got ${ARCH})" >&2
  exit 1
fi
BASE_IMAGE_URL="${BASE_IMAGE_URL:-https://github.com/niess/python-appimage/releases/download/python3.12/python3.12.15-cp312-cp312-manylinux2014_x86_64.AppImage}"
BASE_IMAGE_SHA256="${BASE_IMAGE_SHA256:-a6a9bf619a3e21c5623be144d8ac4e458e1a5b5c133b1cc99b142d6e71b82c76}"
APPIMAGETOOL_VERSION="1.9.1"
APPIMAGETOOL_URL="https://github.com/AppImage/appimagetool/releases/download/${APPIMAGETOOL_VERSION}/appimagetool-x86_64.AppImage"
APPIMAGETOOL_SHA256="ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"
# python-appimage 1.4.6 expects patchelf 0.14.3 and the probonopd excludelist.
PATCHELF_URL="https://github.com/NixOS/patchelf/releases/download/0.14.3/patchelf-0.14.3-x86_64.tar.gz"
PATCHELF_SHA256="aaf20a22dc6c23086c19272dcac5c7cfbcb2f1a8e8569fa37b7516f8b7763f87"
EXCLUDELIST_URL="https://raw.githubusercontent.com/probonopd/AppImages/15a64c20dc23a0154622ba25829364323903b6b5/excludelist"
EXCLUDELIST_SHA256="50db0f894f34b169c47a5cbc0c17dbab61e9edebca5bc8269a1e6ac1bf4bdad9"

fetch_verified() {
  local url="$1" sha256="$2" dest="$3"
  curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "${dest}" "${url}"
  if ! echo "${sha256}  ${dest}" | sha256sum -c --quiet -; then
    echo "Checksum mismatch for ${url}" >&2
    exit 1
  fi
}

# --- Build tooling (hash-pinned) ----------------------------------------------
if [[ ! -d "$VENV" ]]; then
  python3 -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
pip install -q --require-hashes -r "${ROOT}/requirements/build.lock.txt"

chmod +x "${ROOT}/scripts/sync-icons.sh"
"${ROOT}/scripts/sync-icons.sh"

DIST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/qbit-plugin-dl-dist.XXXXXX")"
CLEANUP_PATHS+=("${DIST_TMP}")
python -m build --wheel --no-isolation --outdir "${DIST_TMP}"
WHEELS=( "${DIST_TMP}"/qbit_plugin_dl-*.whl )
if [[ ${#WHEELS[@]} -ne 1 || ! -f "${WHEELS[0]}" ]]; then
  echo "Wheel build failed" >&2
  exit 1
fi

# appimagetool and the base image often need extract-and-run without FUSE.
export APPIMAGE_EXTRACT_AND_RUN="${APPIMAGE_EXTRACT_AND_RUN:-1}"

DOWNLOADS="$(mktemp -d "${TMPDIR:-/tmp}/qbit-plugin-dl-dl.XXXXXX")"
CLEANUP_PATHS+=("${DOWNLOADS}")
BASE_IMAGE="${DOWNLOADS}/$(basename "${BASE_IMAGE_URL}")"
fetch_verified "${BASE_IMAGE_URL}" "${BASE_IMAGE_SHA256}" "${BASE_IMAGE}"
chmod +x "${BASE_IMAGE}"
PYTHON_VERSION="$(basename "${BASE_IMAGE_URL}" | sed -E 's/^python([0-9]+\.[0-9]+)\..*/\1/')"

# --- Runtime dependencies from uv.lock (hash-verified wheelhouse) -------------
# Resolve with the base image's own interpreter so environment markers
# (e.g. typing-extensions on Python < 3.13) and wheel tags match the AppImage.
WHEELHOUSE="$(mktemp -d "${TMPDIR:-/tmp}/qbit-plugin-dl-wheels.XXXXXX")"
CLEANUP_PATHS+=("${WHEELHOUSE}")
"${BASE_IMAGE}" -I -m pip download -q --disable-pip-version-check \
  --require-hashes --no-deps --only-binary=:all: \
  -r "${ROOT}/requirements/runtime.lock.txt" -d "${WHEELHOUSE}"
cp "${WHEELS[0]}" "${WHEELHOUSE}/"

# --- Seed python-appimage's tool cache with verified binaries -----------------
# python-appimage otherwise fetches a moving "continuous" appimagetool and
# unverified patchelf/excludelist into ~/.cache. Give it a private HOME whose
# cache already holds pinned copies so it never downloads them itself.
PA_HOME="$(mktemp -d "${TMPDIR:-/tmp}/qbit-plugin-dl-pahome.XXXXXX")"
CLEANUP_PATHS+=("${PA_HOME}")
PA_CACHE="${PA_HOME}/.cache/python-appimage"
mkdir -p "${PA_CACHE}/bin" "${PA_CACHE}/share"
(
  cd "${DOWNLOADS}"
  fetch_verified "${APPIMAGETOOL_URL}" "${APPIMAGETOOL_SHA256}" appimagetool.AppImage
  chmod +x appimagetool.AppImage
  ./appimagetool.AppImage --appimage-extract >/dev/null
  mv squashfs-root "${PA_CACHE}/bin/.appimagetool-${APPIMAGETOOL_VERSION}.appdir.${ARCH}"

  fetch_verified "${PATCHELF_URL}" "${PATCHELF_SHA256}" patchelf.tar.gz
  tar xzf patchelf.tar.gz ./bin/patchelf
  install -m 0755 bin/patchelf "${PA_CACHE}/bin/patchelf"

  fetch_verified "${EXCLUDELIST_URL}" "${EXCLUDELIST_SHA256}" "${PA_CACHE}/share/excludelist"
)
python_appimage() {
  HOME="${PA_HOME}" python -m python_appimage \
    --appimagetool-version "${APPIMAGETOOL_VERSION}" "$@"
}

echo "Building AppImage with Python ${PYTHON_VERSION}…"

# python-appimage names the output from desktop Name= and joins appimagetool
# args with spaces under shell=True — spaces in Name break the build.
# Stage a copy with a safe Name= so the artifact is qbit-plugin-dl-*.AppImage
# while keeping the pretty Name in the committed desktop file.
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/qbit-plugin-dl-appimage.XXXXXX")"
CLEANUP_PATHS+=("${STAGE}")
cp -a "${ROOT}/appimage/." "${STAGE}/"
sed -i 's/^Name=.*/Name=qbit-plugin-dl/' "${STAGE}/qbit-plugin-dl.desktop"

# python-appimage runs one `pip install` per line (no --hash support), so list
# the verified wheel files and forbid any index lookups.
find "${WHEELHOUSE}" -maxdepth 1 -name '*.whl' | sort > "${STAGE}/requirements.txt"

PIP_NO_INDEX=1 PIP_FIND_LINKS="${WHEELHOUSE}" \
  python_appimage build app -b "${BASE_IMAGE}" "${STAGE}"

# Stage libxcb-cursor.so* into LIB_STAGE for injection into the AppImage.
# Qt 6.5+ xcb needs this; many hosts (and AppImages) omit it.
LIB_STAGE="$(mktemp -d "${TMPDIR:-/tmp}/qbit-plugin-dl-xcb-cursor.XXXXXX")"
CLEANUP_PATHS+=("${LIB_STAGE}")

stage_libxcb_cursor() {
  local found="" candidate real
  # No early `exit` in awk: under pipefail a closed pipe makes ldconfig die
  # with SIGPIPE (exit 141) whenever its cache output is large.
  found="$(ldconfig -p 2>/dev/null | awk '/libxcb-cursor\.so\.0 / && !f {f = $NF} END {print f}')"
  if [[ -z "${found}" || ! -e "${found}" ]]; then
    for candidate in \
      /usr/lib/x86_64-linux-gnu/libxcb-cursor.so.0 \
      /usr/lib64/libxcb-cursor.so.0 \
      /usr/lib/libxcb-cursor.so.0; do
      if [[ -e "${candidate}" ]]; then
        found="${candidate}"
        break
      fi
    done
  fi

  if [[ -z "${found}" || ! -e "${found}" ]]; then
    if command -v apt-get >/dev/null 2>&1 && command -v dpkg-deb >/dev/null 2>&1; then
      local debdir
      debdir="$(mktemp -d "${TMPDIR:-/tmp}/qbit-plugin-dl-xcb-deb.XXXXXX")"
      CLEANUP_PATHS+=("${debdir}")
      (
        cd "${debdir}"
        apt-get download libxcb-cursor0 >/dev/null
        dpkg-deb -x libxcb-cursor0_*.deb root
      )
      found="$(find "${debdir}/root" \( -name 'libxcb-cursor.so.0' -o -name 'libxcb-cursor.so.0.*' \) -print -quit)"
    fi
  fi

  if [[ -z "${found}" || ! -e "${found}" ]]; then
    echo "Could not locate libxcb-cursor.so.0 (install libxcb-cursor0)" >&2
    return 1
  fi

  real="$(readlink -f "${found}")"
  cp -a "${real}" "${LIB_STAGE}/"
  ln -sfn "$(basename "${real}")" "${LIB_STAGE}/libxcb-cursor.so.0"
  echo "Using libxcb-cursor from ${real}"
}

bundle_libxcb_cursor() {
  # Place libs under PySide6/Qt/lib (libqxcb RUNPATH: $ORIGIN/../../lib) and also
  # under usr/lib — AppImage runtime prepends usr/lib to LD_LIBRARY_PATH, which
  # takes precedence over DT_RUNPATH and would otherwise hide the Qt/lib copy.
  local appimage="$1"
  local work qtlib usrlib appimagetool

  work="$(mktemp -d "${TMPDIR:-/tmp}/qbit-plugin-dl-repack.XXXXXX")"
  CLEANUP_PATHS+=("${work}")

  echo "Bundling libxcb-cursor into $(basename "${appimage}")…"
  (
    cd "${work}"
    "${appimage}" --appimage-extract >/dev/null
    qtlib="$(find squashfs-root -type d -path '*/site-packages/PySide6/Qt/lib' -print -quit)"
    if [[ -z "${qtlib}" || ! -d "${qtlib}" ]]; then
      echo "PySide6 Qt/lib not found inside AppImage" >&2
      exit 1
    fi
    cp -a "${LIB_STAGE}/"* "${qtlib}/"
    if [[ ! -e "${qtlib}/libxcb-cursor.so.0" ]]; then
      echo "Failed to place libxcb-cursor.so.0 in ${qtlib}" >&2
      exit 1
    fi

    usrlib="squashfs-root/usr/lib"
    mkdir -p "${usrlib}"
    cp -a "${LIB_STAGE}/"* "${usrlib}/"
    if [[ ! -e "${usrlib}/libxcb-cursor.so.0" ]]; then
      echo "Failed to place libxcb-cursor.so.0 in ${usrlib}" >&2
      exit 1
    fi

    appimagetool="$(python_appimage which appimagetool)"
    rm -f "${appimage}"
    ARCH="$(uname -m)" "${appimagetool}" --no-appstream squashfs-root "${appimage}"
  )
  chmod +x "${appimage}"
}

stage_libxcb_cursor

shopt -s nullglob
APPIMAGES=( "${ROOT}"/qbit-plugin-dl*.AppImage )
if [[ ${#APPIMAGES[@]} -eq 0 ]]; then
  echo "No AppImage produced" >&2
  exit 1
fi
for image in "${APPIMAGES[@]}"; do
  bundle_libxcb_cursor "${image}"
done

echo "Done. AppImage(s):"
ls -lh "${ROOT}"/qbit-plugin-dl*.AppImage 2>/dev/null || ls -lh "${ROOT}"/*.AppImage 2>/dev/null || ls -lh ./*.AppImage
