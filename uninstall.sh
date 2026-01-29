#!/usr/bin/env bash
set -euo pipefail

BIN_NAME="${BIN_NAME:-timibaby}"
rm -f "/usr/local/bin/${BIN_NAME}" /usr/local/bin/my /usr/local/bin/MY
echo "[+] 已卸载 /usr/local/bin/${BIN_NAME} 以及 my/MY"
