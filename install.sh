#!/usr/bin/env bash
set -euo pipefail

# 一键安装：curl|bash
# 用法：
#   sudo bash <(curl -fsSL https://raw.githubusercontent.com/<USER>/timibaby/main/install.sh)
#
# 可选环境变量：
#   REPO=<USER>/timibaby
#   BRANCH=main
#   BIN_NAME=timibaby

REPO_DEFAULT="chinahch/timibaby"   # TODO: 改成你的 GitHub 用户名/仓库名（例如 mucis-dark/timibaby）
BRANCH_DEFAULT="main"

BIN_NAME="${BIN_NAME:-timibaby}"
INSTALL_PATH="/usr/local/bin/${BIN_NAME}"
SCRIPT_IN_REPO="timibaby.sh"

say() { echo -e "\033[32m[+]\033[0m $*"; }
err() { echo -e "\033[31m[!]\033[0m $*" >&2; }
die() { err "$*"; exit 1; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "请用 root 运行：sudo bash install.sh  或  sudo bash <(curl -fsSL ...)"
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

  if [[ "$repo" == "CHANGE_ME/CHANGE_ME" ]]; then
    err "你还没把 install.sh 里的 REPO_DEFAULT 改成你的仓库，比如：mucis-dark/timibaby"
    err "临时也可以这样装：REPO=你的用户名/timibaby sudo bash <(curl -fsSL .../install.sh)"
    die "请先修改 REPO_DEFAULT 或设置环境变量 REPO"
  fi

  local raw="https://raw.githubusercontent.com/${repo}/${branch}/${SCRIPT_IN_REPO}"

  say "Repo: $repo  Branch: $branch"
  say "下载主脚本：$raw"

  local tmp
  tmp="$(mktemp)"
  download "$raw" "$tmp"

  head -n 1 "$tmp" | grep -Eq 'bash' || die "下载内容看起来不是 bash 脚本（可能 repo/branch/文件名不对）"

  install -m 0755 "$tmp" "$INSTALL_PATH"
  rm -f "$tmp"

  # 兼容 my/MY 快捷命令（做成软链接）
  ln -sf "$INSTALL_PATH" /usr/local/bin/my
  ln -sf "$INSTALL_PATH" /usr/local/bin/MY

  say "安装完成：$INSTALL_PATH"
  say "运行：sudo $BIN_NAME  （或 sudo my / sudo MY）"
}

main "$@"
