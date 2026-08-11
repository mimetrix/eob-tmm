#!/usr/bin/env bash
# Rebuild the OpenStack CLI in this sandbox from scratch.
#
# Why this exists: the sandbox has no root/sudo, no system pip, and no
# ensurepip, so the client can't be installed via apt or `pip install
# --user`. It goes into a venv created --without-pip, with pip then
# bootstrapped inside it via get-pip.py. The sandbox is also ephemeral
# (~/.venvs and ~/.local/bin get wiped between sessions), so expect to
# run this every session. ~/docs survives; this script does not live in
# a wiped path.
#
# See env/tmm-build-environment.md and env/openstack-cli-reference.md.
set -euo pipefail

VENV="${HOME}/.venvs/openstack"
BINDIR="${HOME}/.local/bin"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

echo "==> Creating venv at ${VENV} (--without-pip)"
python3 -m venv --without-pip "${VENV}"

echo "==> Bootstrapping pip via get-pip.py"
curl -sSf -o "${TMP}/get-pip.py" https://bootstrap.pypa.io/get-pip.py
"${VENV}/bin/python3" "${TMP}/get-pip.py" -q

echo "==> Installing python-openstackclient + python-glanceclient"
"${VENV}/bin/pip" install -q python-openstackclient python-glanceclient

echo "==> Linking into ${BINDIR}"
mkdir -p "${BINDIR}"
ln -sf "${VENV}/bin/openstack" "${BINDIR}/openstack"

echo "==> Done: $("${BINDIR}/openstack" --version)"
echo
echo "Ensure ${BINDIR} is on PATH, then set credentials:"
echo "  ~/.config/openstack/clouds.yaml  (mode 600, both sjc + sea)"
echo "  export OS_CLOUD=sjc   # or sea"
