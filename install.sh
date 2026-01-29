#!/usr/bin/env bash
set -euo pipefail

# 一键安装（兼容 /dev/fd 不存在的系统）：
#   curl -fsSL https://raw.githubusercontent.com/chinahch/timibaby/main/install.sh -o /tmp/install.sh && sudo bash /tmp/install.sh
# 或：
#   curl -fsSL https://raw.githubusercontent.com/chinahch/timibaby/main/install.sh | sudo bash
# 或：
#   wget -qO /tmp/install.sh https://raw.githubusercontent.com/chinahch/timibaby/main/install.sh && sudo bash /tmp/install.sh

REPO_DEFAULT="chinahch/timibaby"
BRANCH_DEFAULT="main"

BIN_NAME="${BIN_NAME:-timibaby}"
INSTALL_PATH="/usr/local/bin/${BIN_NAME}"
SCRIPT_IN_REPO="timibaby.sh"

say() { echo -e "\033[32m[+]\033[0m $*"; }
err() { echo -e "\033[31m[!]\033[0m $*" >&2; }
die() { err "$*"; exit 1; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "请用 root 运行：sudo bash install.sh  或  curl ... | sudo bash"
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

download() {
  local url="$1" out="$2"
  if have_cmd curl; then
    curl -fsSL "$url" -o "$out"
  elif have_cmd wget; then
    wget -qO "$out" "$url"
  else
    die "缺少下载工具：请先安装 curl 或 wget"
  fi
}

main() {
  need_root

  local repo="${REPO:-$REPO_DEFAULT}"
  local branch="${BRANCH:-$BRANCH_DEFAULT}"
  local raw="https://raw.githubusercontent.com/${repo}/${branch}/${SCRIPT_IN_REPO}"

  say "Repo: ${repo}  Branch: ${branch}"
  say "下载主脚本：${raw}"

  local tmp
  tmp="$(mktemp)"
  download "$raw" "$tmp"

  head -n 1 "$tmp" | grep -Eq 'bash' || die "下载内容看起来不是 bash 脚本（可能 repo/branch/文件名不对）"

  install -m 0755 "$tmp" "$INSTALL_PATH"
  rm -f "$tmp"

  ln -sf "$INSTALL_PATH" /usr/local/bin/my
  ln -sf "$INSTALL_PATH" /usr/local/bin/MY

  say "安装完成：${INSTALL_PATH}"
  say "正在启动：sudo ${BIN_NAME}"
  exec "$INSTALL_PATH"
}

main "$@"
