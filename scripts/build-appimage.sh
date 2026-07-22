#!/usr/bin/env bash
# Build qbit-plugin-dl-*.AppImage using python-appimage.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON_VERSION="${PYTHON_VERSION:-3.12}"
VENV="${ROOT}/.venv-appimage"

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
cleanup_stage() { rm -rf "${STAGE}"; }
trap cleanup_stage EXIT
cp -a "${ROOT}/appimage/." "${STAGE}/"
sed -i 's/^Name=.*/Name=qbit-plugin-dl/' "${STAGE}/qbit-plugin-dl.desktop"

python -m python_appimage build app -p "${PYTHON_VERSION}" "${STAGE}"

# Restore portable requirements (without machine-local wheel path).
cat > appimage/requirements.txt <<'EOF'
httpx>=0.27
PySide6>=6.6
EOF

echo "Done. AppImage(s):"
ls -lh "${ROOT}"/qbit-plugin-dl*.AppImage 2>/dev/null || ls -lh "${ROOT}"/*.AppImage 2>/dev/null || ls -lh ./*.AppImage
