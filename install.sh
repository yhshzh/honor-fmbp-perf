#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Please run as root (e.g. sudo $0 $*)." >&2
    exit 1
fi

if [[ "${1:-}" == "--uninstall" ]]; then
    systemctl disable --now honor-perf.service 2>/dev/null || true
    rm -f /etc/systemd/system/honor-perf.service
    rm -f /usr/local/libexec/honor-perfd
    rm -f /usr/local/bin/honor-perf
    systemctl daemon-reload
    echo "Uninstalled honor-perf. (/etc/default/honor-perf was kept if present.)"
    exit 0
fi

vendor="$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || true)"
product="$(cat /sys/class/dmi/id/product_name 2>/dev/null || true)"
if [[ "${vendor}" != "HONOR" || "${product}" != "FMB-P" ]]; then
    echo "Refusing to install: detected '${vendor}' / '${product}', expected 'HONOR' / 'FMB-P'." >&2
    exit 1
fi

install -Dm755 "${SCRIPT_DIR}/honor-perfd.py" /usr/local/libexec/honor-perfd
install -Dm755 "${SCRIPT_DIR}/honor-perf.py" /usr/local/bin/honor-perf
install -Dm644 "${SCRIPT_DIR}/honor-perf.service" /etc/systemd/system/honor-perf.service
if [[ ! -f /etc/default/honor-perf ]]; then
    install -Dm644 "${SCRIPT_DIR}/honor-perf.default" /etc/default/honor-perf
fi

systemctl daemon-reload
if systemctl list-unit-files thermald.service >/dev/null 2>&1; then
    systemctl enable --now thermald.service
else
    echo "Warning: thermald.service not found. Install and enable thermald (--adaptive) for full PL1/TCC/IMOK support." >&2
fi
systemctl enable --now honor-perf.service

echo "Installed and started honor-perf.service."
echo "Edit /etc/default/honor-perf to customize options (e.g. auto-high threshold), then run:"
echo "  sudo systemctl restart honor-perf.service"
echo "Query status anytime with: honor-perf status"
