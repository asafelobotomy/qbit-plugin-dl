#!/usr/bin/env bash
# Build qbit-plugin-dl-*.AppImage using python-appimage.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON_VERSION="${PYTHON_VERSION:-3.12}"
VENV="${ROOT}/.venv-appimage"
CLEANUP_PATHS=()

cleanup() {
  local path
  for path in "${CLEANUP_PATHS[@]}"; do
    rm -rf "${path}"
  done
}
trap cleanup EXIT

if [[ ! -d "$VENV" ]]; then
  python3 -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"

pip install -q --upgrade pip build wheel "python-appimage>=1.4" Pillow
pip install -q -e .

chmod +x "${ROOT}/scripts/sync-icons.sh"
"${ROOT}/scripts/sync-icons.sh"

python -m build --wheel
WHEEL="$(ls -1t dist/qbit_plugin_dl-*.whl | head -1)"
if [[ -z "$WHEEL" || ! -f "$WHEEL" ]]; then
  echo "Wheel build failed" >&2
  exit 1
fi
WHEEL_ABS="$(cd "$(dirname "$WHEEL")" && pwd)/$(basename "$WHEEL")"

cat > appimage/requirements.txt <<EOF
httpx>=0.27
PySide6>=6.6
${WHEEL_ABS}
EOF

echo "Building AppImage with Python ${PYTHON_VERSION}…"
# appimagetool often needs extract-and-run when FUSE is unavailable.
export APPIMAGE_EXTRACT_AND_RUN="${APPIMAGE_EXTRACT_AND_RUN:-1}"

# python-appimage names the output from desktop Name= and joins appimagetool
# args with spaces under shell=True — spaces in Name break the build.
# Stage a copy with a safe Name= so the artifact is qbit-plugin-dl-*.AppImage
# while keeping the pretty Name in the committed desktop file.
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/qbit-plugin-dl-appimage.XXXXXX")"
CLEANUP_PATHS+=("${STAGE}")
cp -a "${ROOT}/appimage/." "${STAGE}/"
sed -i 's/^Name=.*/Name=qbit-plugin-dl/' "${STAGE}/qbit-plugin-dl.desktop"

python -m python_appimage build app -p "${PYTHON_VERSION}" "${STAGE}"

# Restore portable requirements (without machine-local wheel path).
cat > appimage/requirements.txt <<'EOF'
httpx>=0.27
PySide6>=6.6
EOF

# Stage libxcb-cursor.so* into LIB_STAGE for injection into the AppImage.
# Qt 6.5+ xcb needs this; many hosts (and AppImages) omit it.
LIB_STAGE="$(mktemp -d "${TMPDIR:-/tmp}/qbit-plugin-dl-xcb-cursor.XXXXXX")"
CLEANUP_PATHS+=("${LIB_STAGE}")

stage_libxcb_cursor() {
  local found="" candidate real
  found="$(ldconfig -p 2>/dev/null | awk '/libxcb-cursor\.so\.0 /{print $NF; exit}')"
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
      found="$(find "${debdir}/root" \( -name 'libxcb-cursor.so.0' -o -name 'libxcb-cursor.so.0.*' \) | head -1)"
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
  # Place libs under PySide6/Qt/lib so libqxcb.so resolves them via RUNPATH
  # ($ORIGIN/../../lib) without host install or LD_LIBRARY_PATH.
  local appimage="$1"
  local work qtlib appimagetool

  work="$(mktemp -d "${TMPDIR:-/tmp}/qbit-plugin-dl-repack.XXXXXX")"
  CLEANUP_PATHS+=("${work}")

  echo "Bundling libxcb-cursor into $(basename "${appimage}")…"
  (
    cd "${work}"
    "${appimage}" --appimage-extract >/dev/null
    qtlib="$(find squashfs-root -type d -path '*/site-packages/PySide6/Qt/lib' | head -1)"
    if [[ -z "${qtlib}" || ! -d "${qtlib}" ]]; then
      echo "PySide6 Qt/lib not found inside AppImage" >&2
      exit 1
    fi
    cp -a "${LIB_STAGE}/"* "${qtlib}/"
    if [[ ! -e "${qtlib}/libxcb-cursor.so.0" ]]; then
      echo "Failed to place libxcb-cursor.so.0 in ${qtlib}" >&2
      exit 1
    fi

    appimagetool="$(python -m python_appimage which appimagetool)"
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
