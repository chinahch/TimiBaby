#!/usr/bin/env bash
# sk5.sh 融合 Misaka-blog Hysteria2 一键逻辑版 (UI重构+性能优化+全功能保留版)
# 🚀 优化内容：移除启动阻塞、后台IP获取、Dashboard UI、保留所有业务逻辑
# 🚀 代码大师修改：默认执行完整初始化，并自动设置 'my' 和 'MY' 别名快捷指令

# 防止在无 TTY / 后台环境下空转（交互菜单脚本必须有这个）
# 如确实需要在无 TTY 环境运行：ALLOW_NO_TTY=1 ./baby.sh
if ! [[ -t 0 ]]; then
  if [[ "${ALLOW_NO_TTY:-0}" != "1" ]]; then
    echo "No TTY detected; exit to prevent busy loop. (Use ALLOW_NO_TTY=1 to override)"
    exit 0
  fi
fi

export LC_ALL=C  # 优化 grep/sed/awk 处理速度
# 必须显式声明，否则 IP 地址索引会触发算术运算报错
declare -A _HOST2IP 2>/dev/null || true
declare -A _seen6 2>/dev/null || true
declare -A GEO_CACHE 2>/dev/null || true

# ============= 0. 全局配置与 UI 变量 =============
VERSION="3.0.0 Optimized"
ARGO_TEMP_CACHE="/root/agsbx/jh.txt"
ARGO_FIXED_CACHE="/root/agsbx/gd.txt"
ARGO_META_TAG_PREFIX="Argo-"
XRAY_BASE_DIR="/etc/xray"
CONFIG="${XRAY_BASE_DIR}/config.json"
META="${XRAY_BASE_DIR}/nodes_meta.json"
NAT_FILE="${XRAY_BASE_DIR}/nat_ports.json"
LOG_FILE="/var/log/xray.log"
XRAY_CONFIG="${XRAY_BASE_DIR}/xray_config.json"
XRAY_BIN_DEFAULT="/usr/local/bin/xray"
IP_CACHE_FILE="/tmp/my_ip_cache"
DEPS_CHECKED=0  # 全局标志

# 颜色定义
C_RESET='\033[0m'
C_RED='\033[38;5;196m'
C_GREEN='\033[38;5;46m'
C_YELLOW='\033[38;5;226m'
C_BLUE='\033[38;5;39m'
C_PURPLE='\033[38;5;129m'
C_CYAN='\033[38;5;51m'
C_GRAY='\033[90m'

# ============= 小内存与网络环境预修复 =============
fix_environment_lowmem() {
    # 1. 修复 DNS 解析 (解决你遇到的 temporary error)
    if ! nslookup google.com >/dev/null 2>&1; then
        echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" > /etc/resolv.conf
    fi

    # 2. 自动创建虚拟内存 (针对 < 512MB 的机器)
    local total_mem=$(free -m | awk '/Mem:/ {print $2}')
    local total_swap=$(free -m | awk '/Swap:/ {print $2}')
    if [ "$total_mem" -le 300 ] && [ "$total_swap" -le 10 ]; then
        echo -e "${C_YELLOW}检测到小内存环境 ($total_mem MB)，正在开启临时 Swap...${C_RESET}"
        # Alpine/BusyBox 兼容的 dd 命令
        dd if=/dev/zero of=/swapfile bs=1024 count=524288 2>/dev/null
        chmod 600 /swapfile
        mkswap /swapfile >/dev/null 2>&1
        swapon /swapfile >/dev/null 2>&1
    fi
}

# 在脚本顶部定义变量
SYNC_DONE=0

auto_sync_time() {
    # 如果本次运行已同步过，直接跳过
    [[ "$SYNC_DONE" == "1" ]] && return
    
    say "正在同步系统时间..."
    if command -v ntpdate >/dev/null 2>&1; then
        ntpdate -u pool.ntp.org >/dev/null 2>&1
    else
        local remote_date=$(curl -sI https://www.google.com | grep -i '^date:' | cut -d' ' -f2-7)
        [[ -n "$remote_date" ]] && date -s "$remote_date" >/dev/null 2>&1
    fi
    SYNC_DONE=1
}

fix_environment_lowmem # 立即执行


# ============= IP 策略状态翻译工具 (修复版) =============

# 1. 核心翻译逻辑 (兼容两种函数名)
_mode_label() { _ip_mode_desc "$1"; }

_ip_mode_desc() {
  case "${1:-}" in
    v4pref) echo "优选IPv4(回退IPv6)" ;;
    v6pref) echo "优选IPv6(回退IPv4+失败域名走v4)" ;;
    v4only) echo "IPv4 only(完全不用IPv6)" ;;
    v6only) echo "IPv6 only(完全不用IPv4)" ;;
    off)    echo "跟随全局" ;;  # 这里改成了你想要的“跟随全局”
    follow_global|follow|"(未设置)"|"") echo "跟随全局" ;;
    *)      echo "$1" ;;
  esac
}

_get_global_mode() {
  local pref="off"

  if [[ -r /etc/xray/ip_pref ]]; then
    IFS= read -r pref < /etc/xray/ip_pref || pref="off"
  fi

  pref="$(_sanitize_ip_pref "$pref")"
  echo "$pref"
}

_sanitize_ip_pref() {
  local pref="${1:-}"
  pref="${pref//$'\r'/}"
  pref="${pref// /}"
  case "$pref" in
    ""|"(未设置)"|"follow_global"|"follow") echo "off" ;;
    *) echo "$pref" ;;
  esac
}

_pref_is_v6_family() {
  case "$(_sanitize_ip_pref "${1:-}")" in
    v6pref|v6only|v6) return 0 ;;
    *) return 1 ;;
  esac
}

_pref_is_v4_family() {
  case "$(_sanitize_ip_pref "${1:-}")" in
    v4pref|v4only|v4) return 0 ;;
    *) return 1 ;;
  esac
}

_pref_domain_strategy() {
  case "$(_sanitize_ip_pref "${1:-}")" in
    v6pref|v6) echo "UseIPv6v4" ;;
    v4pref|v4) echo "UseIPv4v6" ;;
    v6only)    echo "UseIPv6" ;;
    v4only)    echo "UseIPv4" ;;
    off)       echo "AsIs" ;;
    *)         echo "AsIs" ;;
  esac
}

_read_global_lock_ip_by_family() {
  local family="$1"
  local file=""
  case "$family" in
    v4) file="/etc/xray/global_egress_ip_v4" ;;
    v6) file="/etc/xray/global_egress_ip_v6" ;;
    *) echo ""; return 0 ;;
  esac

  if [[ -r "$file" ]]; then
    tr -d '\r\n ' < "$file" 2>/dev/null || true
  else
    echo ""
  fi
}

_read_global_lock_ip_for_pref() {
  local pref="$(_sanitize_ip_pref "${1:-$(_get_global_mode)}")"
  if _pref_is_v6_family "$pref"; then
    _read_global_lock_ip_by_family v6
  elif _pref_is_v4_family "$pref"; then
    _read_global_lock_ip_by_family v4
  else
    echo ""
  fi
}

_get_global_egress_pref_and_lock() {
  local pref="$(_get_global_mode)"
  local ds="$(_pref_domain_strategy "$pref")"
  local lock_ip="$(_read_global_lock_ip_for_pref "$pref")"
  printf '%s\t%s\t%s\n' "$pref" "$ds" "$lock_ip"
}



# ============= 1. 核心工具函数 (UI优化) =============

say()  { echo -e "${C_GREEN}➜ ${C_RESET}$*"; }
err()  { echo -e "${C_RED}✖ $*${C_RESET}" >&2; }
ok()   { echo -e "${C_GREEN}✔ $*${C_RESET}" >&2; }
warn() { echo -e "${C_YELLOW}⚡ $*${C_RESET}" >&2; }
log_msg() {
  local level="$1" msg="$2"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" >> "$LOG_FILE"
}

# 智能格式化链接中的主机地址 (V6 加方括号)
format_host_for_link() {
    local host="$1"
    if [[ "$host" =~ : ]]; then
        echo "[$host]"
    else
        echo "$host"
    fi
}


_probe_socks_inbound() {
  local tag="$1" mode="$2"
  local cfg="${XRAY_CONFIG:-/etc/xray/xray_config.json}"

  # 配置不存在则跳过，不阻断流程
  [[ -s "$cfg" ]] || return 0

  local port auth user pass
  local line

  # 一次 jq 取回四个字段，避免重复解析 JSON
  line="$(
    jq -r --arg t "$tag" '
      first(.inbounds[]? | select(.tag == $t)) |
      [
        (.port // ""),
        (.settings.auth // "noauth"),
        (.settings.accounts[0].user // ""),
        (.settings.accounts[0].pass // "")
      ] | @tsv
    ' "$cfg" 2>/dev/null
  )"

  [[ -n "$line" && "$line" != "null" ]] || return 0
  IFS=$'\t' read -r port auth user pass <<< "$line"

  [[ -n "$port" ]] || return 0

  # 先确认端口监听
  if command -v ss >/dev/null 2>&1; then
    # 比 ss | awk | grep 更省，尽量直接匹配原始输出
    ss -lnt "( sport = :$port )" 2>/dev/null | grep -q "[[:digit:]]" || return 2
  fi

  local url="https://api.ipify.org"
  case "$mode" in
    v6*) url="https://api64.ipify.org" ;;
  esac

  local px
  if [[ "$auth" == "password" && -n "$user" && -n "$pass" ]]; then
    px="socks5h://${user}:${pass}@127.0.0.1:${port}"
  else
    px="socks5h://127.0.0.1:${port}"
  fi

  local out
  out="$(curl -sS --connect-timeout 3 --max-time 6 -x "$px" "$url" 2>/dev/null)"
  out="${out//$'\r'/}"
  out="${out//$'\n'/}"

  [[ -n "$out" ]] || return 3
  return 0
}

# 升级版：支持 --arg 传参，彻底告别引号转义和占位符报错
# 升级版：支持 --arg 传参，彻底解决引号和占位符报错，且不清除屏幕
safe_json_edit() {
    local file="$1"
    shift
    local filter="$1"
    shift
    local tmp; tmp=$(mktemp)
    if jq "$@" "$filter" "$file" > "$tmp"; then
        mv "$tmp" "$file"
        return 0
    else
        echo -e "${C_RED}✖ JSON 语法错误，更改未应用${C_RESET}" >&2
        rm -f "$tmp"
        return 1
    fi
}

# --- 缓存系统信息，避免重复检测 ---
_OS_CACHE=""
_INIT_SYS_CACHE=""

detect_os() {
  if [[ -n "$_OS_CACHE" ]]; then echo "$_OS_CACHE"; return; fi
  if [[ -f /etc/os-release ]]; then . /etc/os-release; _OS_CACHE="$ID"; else _OS_CACHE="unknown"; fi
  echo "$_OS_CACHE"
}

detect_init_system() {
  if [[ -n "$_INIT_SYS_CACHE" ]]; then echo "$_INIT_SYS_CACHE"; return; fi
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    _INIT_SYS_CACHE="systemd"
  elif command -v rc-service >/dev/null 2>&1 && [[ -d /run/openrc ]]; then
    _INIT_SYS_CACHE="openrc"
  else
    _INIT_SYS_CACHE="unknown"
  fi
  echo "$_INIT_SYS_CACHE"
}

# 信号处理
trap 'disown_temp_tunnel >/dev/null 2>&1; echo; exit 0' INT
trap 'exit 0' HUP

# 交互输入保护：一旦 stdin 变为 EOF（例如放后台/SSH 断开），立即退出，避免 while true 空转吃 CPU
safe_read() {
  # 用法：safe_read var "prompt"
  local __var="$1"; shift
  local __prompt="$1"
  if ! read -r -p "$__prompt" "$__var"; then
    echo
    exit 0
  fi
}

daemonize() { setsid "$@" </dev/null >/dev/null 2>&1 & }


if [ -z "$BASH_VERSION" ]; then
  echo "本脚本需要 Bash 解释器，请使用 Bash 运行。"
  exit 1
fi

umask 022

# 卡片打印优化
print_card() {
  local title="$1" name="$2" info="$3" link="$4"
  echo ""
  echo -e "${C_BLUE}╔═══════════════════════════════════════════════════════════════╗${C_RESET}"
  echo -e "${C_BLUE}║${C_RESET} ${C_YELLOW}${title}${C_RESET}"
  echo -e "${C_BLUE}╠═══════════════════════════════════════════════════════════════╣${C_RESET}"
  echo -e "  节点名称: ${C_CYAN}${name}${C_RESET}"
  echo -e "${info}"
  echo -e "${C_BLUE}╠═══════════════════════════════════════════════════════════════╣${C_RESET}"
  echo -e "  ${C_GREEN}${link}${C_RESET}"
  echo -e "${C_BLUE}╚═══════════════════════════════════════════════════════════════╝${C_RESET}"
  echo ""
}

update_ip_async() {
    local lock="/tmp/ip_probe.lock"
    if [[ -f "$lock" ]]; then
        local pid
        IFS= read -r pid < "$lock" 2>/dev/null || pid=""
        if [[ -n "$pid" ]] && ps -p "$pid" >/dev/null 2>&1; then
            return 0
        fi
    fi

    (
        local ip4 ip6 pref lock_ip xray_pub

        ip4="$(curl -s -4 --connect-timeout 2 --max-time 5 https://api.ipify.org 2>/dev/null)"
        ip4="${ip4//$'\r'/}"
        ip4="${ip4//$'\n'/}"
        [[ -n "$ip4" ]] && printf '%s' "$ip4" > "$IP_CACHE_FILE"

        ip6="$(curl -s -6 --connect-timeout 2 --max-time 5 https://api64.ipify.org 2>/dev/null)"
        ip6="${ip6//$'\r'/}"
        ip6="${ip6//$'\n'/}"
        [[ -n "$ip6" ]] && printf '%s' "$ip6" > "${IP_CACHE_FILE}_v6"

        pref="$(_get_global_mode)"
        lock_ip="$(_read_global_lock_ip_for_pref "$pref")"

        if [[ -z "$lock_ip" ]]; then
            rm -f "${IP_CACHE_FILE}_xray" "${IP_CACHE_FILE}_xray_status" 2>/dev/null || true
            rm -f "$lock"
            exit 0
        fi

        if _pref_is_v6_family "$pref"; then
            xray_pub="$(curl -s -6 --interface "$lock_ip" --connect-timeout 3 --max-time 6 https://api64.ipify.org 2>/dev/null)"
        else
            xray_pub="$(curl -s -4 --interface "$lock_ip" --connect-timeout 3 --max-time 6 https://api.ipify.org 2>/dev/null)"
        fi

        xray_pub="${xray_pub//$'\r'/}"
        xray_pub="${xray_pub//$'\n'/}"

        if [[ -n "$xray_pub" ]]; then
            printf '%s' "$xray_pub" > "${IP_CACHE_FILE}_xray"
            printf '%s' "OK" > "${IP_CACHE_FILE}_xray_status"
        else
            printf '%s' "FAILED" > "${IP_CACHE_FILE}_xray_status"
            printf '%s' "N/A" > "${IP_CACHE_FILE}_xray"
        fi

        rm -f "$lock"
    ) &

    echo $! > "$lock"
}


# 获取当前服务器的“入口”公网 IP (适配 NAT 环境)
get_public_ipv4_ensure() {
    # 1. 优先级最高：读取用户手动设置的入口域名或 IP (如 seed.lazycat.cv)
    local saved_host
    saved_host="$(head -n 1 /etc/xray/public_host 2>/dev/null | tr -d '\r\n ')"
    if [[ -n "$saved_host" ]]; then
        echo -n "$saved_host"
        return
    fi

    # 2. 优先级第二：尝试通过当前 SSH 会话获取入口 IP
    # $SSH_CONNECTION 的第 3 位通常是服务器接听请求的公网 IP
    local ssh_entry
    ssh_entry=$(echo "$SSH_CONNECTION" | awk '{print $3}')
    
    # 关键点：如果 SSH 获取到的是公网 IP（非 10., 172., 192. 等），则直接使用
    if [[ -n "$ssh_entry" ]] && ! [[ "$ssh_entry" =~ ^(10\.|172\.|192\.168\.|127\.) ]]; then
        echo -n "$ssh_entry" | tee "$IP_CACHE_FILE"
        return
    fi

    # 3. 优先级第三：读取缓存 (如果缓存里不是私有 IP)
    if [[ -f "$IP_CACHE_FILE" ]]; then
        local cached_ip
        cached_ip=$(cat "$IP_CACHE_FILE")
        if ! [[ "$cached_ip" =~ ^(10\.|172\.|192\.168\.|127\.) ]]; then
            echo -n "$cached_ip"
            return
        fi
    fi

    # 4. 优先级第四：通过外部 API 获取 (出口 IP)
    local egress_ip
    egress_ip=$(curl -s -4 --connect-timeout 3 --max-time 5 https://api.ipify.org || curl -s -4 --connect-timeout 3 --max-time 5 https://ifconfig.me/ip)
    
    # 5. 最后保底：如果是 NAT 环境拿不到入口 IP，只能暂时显示出口 IP
    if [[ -n "$egress_ip" ]]; then
        echo -n "$egress_ip" | tee "$IP_CACHE_FILE"
    else
        # 最后的最后，抓网卡 IP
        ip -4 addr show scope global | grep -vE '127\.0\.0\.1' | awk '{print $2}' | cut -d/ -f1 | head -n1
    fi
}



# 获取公网 IPv6 (增加实时校验)
get_public_ipv6_ensure() {
    local ip6=""
    if [[ -f "${IP_CACHE_FILE}_v6" ]]; then
        ip6=$(cat "${IP_CACHE_FILE}_v6")
    fi
    # 如果缓存里的地址不是以 2 或 3 开头，说明是无效地址
    if [[ ! "$ip6" =~ ^[23] ]]; then
        echo ""
    else
        echo "$ip6"
    fi
}

# 1. 获取纯中文国家名称
# 1. 获取纯中文国家名称 (升级为 ipinfo.io 核心)
get_country_name_zh() {
  local code
  # 直接从 ipinfo.io 获取 ISO 国家代码 (US, HK, JP 等)，这是目前最稳的方案
  code=$(curl -s --connect-timeout 2 --max-time 3 https://ipinfo.io/country | tr -d '[:space:]')
  
  # 映射常用地区到中文，用于自动生成节点标签
  case "$code" in
    US) echo -n "美国" ;;
    HK) echo -n "香港" ;;
    JP) echo -n "日本" ;;
    SG) echo -n "新加坡" ;;
    TW) echo -n "台湾" ;;
    KR) echo -n "韩国" ;;
    CN) echo -n "中国" ;;
    GB) echo -n "英国" ;;
    DE) echo -n "德国" ;;
    *)  
      # 兜底逻辑：如果是冷门地区，回退到 ip-api 的多语言接口
      curl -s -4 --connect-timeout 2 "http://ip-api.com/json/?fields=country&lang=zh-CN" | jq -r '.country // "未知"'
      ;;
  esac
}

# 2. 自动获取 A-Z 排序后缀 (自动补位：如果 A 没被占用就用 A)
get_node_letter_suffix() {
  local prefix="$1"
  local country="$2"
  local alphabet=(A B C D E F G H I J K L M N O P Q R S T U V W X Y Z)
  
  # 汇总当前所有已存在的标签
  local existing_tags=$( (jq -r '.inbounds[].tag // empty' "$CONFIG" 2>/dev/null; jq -r 'keys[]' "$META" 2>/dev/null) | sort -u)
  
  # 遍历 A-Z，找到第一个没被占用的字母
  for letter in "${alphabet[@]}"; do
    local candidate="${prefix}-${country}${letter}"
    if ! echo "$existing_tags" | grep -qx "$candidate"; then
      echo -n "$letter"
      return
    fi
  done
  echo -n "Z$(date +%s)" # 极端情况：A-Z 全满则使用时间戳
}


# 获取 IP 地理位置与类型 (中文增强版)
get_ip_country() {
    local ip="$1"
    # 处理空值或非法输入
    [[ -z "$ip" || "$ip" == "未知" || "$ip" == "null" || "$ip" == "??" ]] && echo "未知" && return

    # 1) 内存缓存：避免对同一 IP 多次请求 (脚本运行期间有效)
    if [[ -n "${GEO_CACHE[$ip]:-}" ]]; then
        echo "${GEO_CACHE[$ip]}"
        return
    fi

    # 2) 内网地址识别 (正则增强)
    if [[ "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|169\.254\.|fc00:|fd00:|fe80:|::1) ]]; then
        echo "内网" && return
    fi

    # 3) 获取中文国家名称 (ip-api.com)
    local country
    country=$(curl -s -4 --connect-timeout 2 --max-time 3 "http://ip-api.com/json/${ip}?fields=country&lang=zh-CN" \
        | jq -r '.country // empty' 2>/dev/null)
    [[ -z "$country" || "$country" == "null" ]] && country="未知国家"

    # 4) 获取 IP 详细类型 (ipapi.is)
    local type_label="通用"
    local ip_data
    ip_data=$(curl -s -4 --connect-timeout 2 --max-time 3 "https://api.ipapi.is/?ip=${ip}" 2>/dev/null)
    
    if [[ -n "$ip_data" && "$ip_data" != "null" ]]; then
        local is_hosting=$(echo "$ip_data" | jq -r '.is_hosting // false' 2>/dev/null)
        local is_mobile=$(echo "$ip_data" | jq -r '.is_mobile // false' 2>/dev/null)
        local is_business=$(echo "$ip_data" | jq -r '.is_business // false' 2>/dev/null)
        local asn_type=$(echo "$ip_data" | jq -r '.asn.type // "unknown"' 2>/dev/null | tr '[:upper:]' '[:lower:]')

        # --- 判断逻辑优先级 ---
        if [[ "$is_hosting" == "true" || "$asn_type" == "hosting" || "$asn_type" == "data center" ]]; then
            type_label="机房"
        elif [[ "$is_mobile" == "true" ]]; then
            type_label="移动网"
        elif [[ "$is_business" == "true" || "$asn_type" == "business" || "$asn_type" == "education" ]]; then
            type_label="商宽"
        elif [[ "$asn_type" == "isp" || "$asn_type" == "residential" ]]; then
            type_label="家宽"
        else
            type_label="通用"
        fi
    fi

    local result="${country} [${type_label}]"
    # 存入内存缓存
    GEO_CACHE["$ip"]="$result"
    echo "$result"
}

# 按接口探测真实公网出口 IP（v4/v6）


# 构建 “公网IP [国家] (iface)” 行



test_outbound_connection() {
    local type="$1"
    local server="$2"
    local port="$3"
    local user="${4:-}"
    local pass="${5:-}"

    # 加密协议：脚本不做明文探测（保持你原逻辑）
    if [[ "$type" =~ ^(ss|vless|vmess|hysteria2)$ ]]; then
        echo -e "➜ ${C_YELLOW}提示：${type^^} 加密协议请在客户端测试。${C_RESET}"
        return 0
    fi

    say "正在探测落地出口 (极速模式)..."

    local proxy_url=""
    [[ "$type" == "socks" ]] && proxy_url="socks5h://" || proxy_url="http://"

    # socks/http 认证拼接
    if [[ -n "$user" && -n "$pass" ]]; then
        proxy_url+="${user}:${pass}@"
    fi
    proxy_url+="${server}:${port}"

    # 关键：curl 失败要 return 1
    local test_ip=""
    test_ip="$(curl -sS -x "$proxy_url" --connect-timeout 2 --max-time 3 https://api.ipify.org 2>/dev/null | tr -d '\r\n')"

    if [[ -z "$test_ip" ]]; then
        err "测试失败：节点连接超时/不可用 (3s)。"
        return 1
    fi

    ok "测试成功！出口 IP: ${C_YELLOW}${test_ip}${C_RESET}"
    return 0
}


# 获取所有可用 IP 列表 (多出口增强修复版)
get_all_ips_with_geo() {
    local proto="$1"   # "4" 或 "6"
    local -a out_lines=()
    local -A seen_pub_ips     # 公网出口IP去重（仅用于公网口）
    local -A seen_land_keys   # 落地口去重（iface+本地IP）
    local api_url="https://api.ipify.org"
    [[ "$proto" == "6" ]] && api_url="https://api64.ipify.org"

    # --- Step 1. 探测系统当前真正的默认公网出口 ---
    local system_default_pub=""
    if [[ "$proto" == "4" ]]; then
        system_default_pub=$(curl -s -4 --connect-timeout 2 --max-time 3 "$api_url" 2>/dev/null | tr -d '\r\n')
    else
        system_default_pub=$(curl -s -6 --connect-timeout 2 --max-time 3 "$api_url" 2>/dev/null | tr -d '\r\n')
    fi

    # --- Step 2. 收集所有 UP 状态网卡的 IP ---
    local -a all_addr_info=()
    if [[ "$proto" == "4" ]]; then
        mapfile -t all_addr_info < <(ip -4 -o addr show | awk '$2 !~ /lo/ {split($4,a,"/"); print $2"\t"a[1]}')
    else
        # 注意：scope global 也会包含 ULA(fd/fc)，后面会再过滤
        mapfile -t all_addr_info < <(ip -6 -o addr show scope global | grep -v "temporary" | awk '$2 !~ /lo/ {split($4,a,"/"); print $2"\t"a[1]}')
    fi

    for line in "${all_addr_info[@]}"; do
        local iface=$(echo "$line" | awk '{print $1}')
        local lip=$(echo "$line" | awk '{print $2}')
        [[ -z "$lip" ]] && continue

        # ========== 新增：先做“不可锁地址”过滤 ==========
        if [[ "$proto" == "6" ]]; then
            # 过滤：link-local / ULA / loopback
            [[ "$lip" =~ ^(fe80:|fd|fc|::1) ]] && continue
            # 仅允许 2000::/3（2xxx 或 3xxx 开头）
            [[ ! "$lip" =~ ^[23] ]] && continue
        fi
        # ============================================

        local is_private=0
        if [[ "$proto" == "4" ]]; then
            [[ "$lip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|100\.) ]] && is_private=1
        else
            # 上面已经过滤掉 fe80/fd/fc/::1，这里保留逻辑不影响
            [[ "$lip" =~ ^(fd|fc|fe80:|::1) ]] && is_private=1
        fi

        # ========== 新增：IPv4 NAT 私网(非 tun/wg/tap) 不显示 ==========
        if [[ "$proto" == "4" && "$is_private" -eq 1 ]]; then
            # 只有 tun/wg/tap 的私网才当“落地口”列出；eth0 上的 10.x/172/192/100.* 直接跳过
            if [[ ! "$iface" =~ ^(tun|wg|tap) ]]; then
                continue
            fi
        fi
        # ===========================================================

        local pub_ip=""
        if [[ "$is_private" -eq 0 ]]; then
            # 情况 A: 直接是公网 IP
            pub_ip="$lip"
        else
            # 情况 B: 私有 IP (如 tun10)，强制探测出口
            pub_ip=$(curl -s -"$proto" --interface "$lip"  --connect-timeout 2 --max-time 3 "$api_url" 2>/dev/null || \
                     curl -s -"$proto" --interface "$iface" --connect-timeout 2 --max-time 3 "$api_url" 2>/dev/null)
            pub_ip=$(echo "$pub_ip" | tr -d '\r\n')
            [[ -n "$pub_ip" && ("$pub_ip" == *"HTML"* || "$pub_ip" == "FAILED") ]] && pub_ip=""
        fi

        # --- Step 3. 汇总逻辑 ---
        if [[ "$is_private" -eq 1 ]]; then
            # ✅ 落地口：按 iface+本地IP 去重，且探测失败也要显示（不漏）
            local land_key="${iface}|${lip}"
            [[ -n "${seen_land_keys[$land_key]}" ]] && continue
            seen_land_keys["$land_key"]=1

            if [[ -n "$pub_ip" ]]; then
                local detail; detail=$(get_ip_country "$pub_ip")
                local tag=""
                [[ "$pub_ip" == "$system_default_pub" ]] && tag=" ${C_GREEN}[系统默认]${C_RESET}"
                out_lines+=("${lip} [落地] -> ${pub_ip} ${detail} (${iface})${tag}")
            else
                out_lines+=("${lip} [落地] -> (探测失败) 未知 (${iface})")
            fi
        else
            # 公网口：仍按公网出口IP去重
            if [[ -n "$pub_ip" && -z "${seen_pub_ips[$pub_ip]}" ]]; then
                local detail; detail=$(get_ip_country "$pub_ip")
                local tag=""
                [[ "$pub_ip" == "$system_default_pub" ]] && tag=" ${C_GREEN}[系统默认]${C_RESET}"
                out_lines+=("${pub_ip} ${detail}${tag}")
                seen_pub_ips["$pub_ip"]=1
            fi
        fi
    done

    # --- Step 4. 保底逻辑：确保默认出口一定出现 ---
    if [[ -n "$system_default_pub" && -z "${seen_pub_ips[$system_default_pub]}" ]]; then
        local detail; detail=$(get_ip_country "$system_default_pub")
        out_lines+=("${system_default_pub} ${detail} ${C_GREEN}[系统默认]${C_RESET}")
        seen_pub_ips["$system_default_pub"]=1
    fi

    # --- Step 5. 最终输出 ---
    [[ ${#out_lines[@]} -eq 0 ]] && return 0
    printf "%s\n" "${out_lines[@]}" | awk '!seen[$0]++'
}




get_sys_status() {
    # 1. 采集基础数据并脱水
    local node_count=$(jq '.inbounds | length' "$CONFIG" 2>/dev/null || echo 0)
    node_count=$(echo "$node_count" | tr -d '\n\r')
    local core_ver=$($(_xray_bin) version 2>/dev/null | head -n1 | awk '{print $2}')
    core_ver=$(echo "$core_ver" | tr -d '\n\r')
    local sys_uptime=$(uptime -p 2>/dev/null | sed "s/up //; s/ days/天/; s/ day/天/; s/ hours/小时/; s/ hour/小时/; s/ minutes/分钟/; s/ minute/分钟/; s/,//g" | tr -d '\n\r')
    
    # 2. 系统 IP 获取及“无”处理
    local sys_ip4=$(cat "$IP_CACHE_FILE" 2>/dev/null | tr -d '\n\r')
    [[ -z "$sys_ip4" ]] && sys_ip4="无"
    local sys_ip6=$(cat "${IP_CACHE_FILE}_v6" 2>/dev/null | tr -d '\n\r')
    [[ -z "$sys_ip6" ]] && sys_ip6="无"

    # 3. 识别本地 SSH 来源及城市位置
    local cur_session_ip=$(echo $SSH_CLIENT | awk '{print $1}')
    local local_loc="${C_GRAY}未知位置${C_RESET}"
    local v4_ext_target="114.114.114.114"; local v6_ext_target="2400:3200::1"

    if [[ -n "$cur_session_ip" ]]; then
        local loc_data=$(curl -s --connect-timeout 2 "http://ip-api.com/json/$cur_session_ip?fields=country,city,countryCode&lang=zh-CN")
        local country=$(echo "$loc_data" | jq -r '.country // empty')
        local city=$(echo "$loc_data" | jq -r '.city // empty')
        local code=$(echo "$loc_data" | jq -r '.countryCode // "US"')
        [[ -n "$country" ]] && local_loc="${C_PURPLE}${country}${C_RESET}"
        [[ -n "$city" ]] && local_loc="${local_loc} · ${C_PURPLE}${city}${C_RESET}"
        if [[ "$code" != "CN" ]]; then v4_ext_target="1.1.1.1"; v6_ext_target="2606:4700:4700::1111"; fi
    fi

    # 4. 延迟检测逻辑 (统一黄色)
    local v4_delay="" v6_delay=""
    local all_ips=$(who | grep -oE "\(([0-9a-fA-F.:]+)\)" | tr -d "()" | sort -u)
    local combined_ips=$(echo "$cur_session_ip $all_ips" | tr ' ' '\n' | sort -u)

    for ip in $combined_ips; do
        [[ -z "$ip" || "$ip" == " " ]] && continue
        local rtt=$(ss -itn dst "$ip" 2>/dev/null | grep -oE "rtt:[0-9.]+" | cut -d: -f2 | head -n1)
        if [[ -n "$rtt" ]]; then
            if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then v4_delay="${C_YELLOW}${rtt}ms(本地)${C_RESET}"
            elif [[ "$ip" == *:* ]]; then v6_delay="${C_YELLOW}${rtt}ms(本地)${C_RESET}"; fi
        fi
    done

    if [[ -z "$v4_delay" && "$sys_ip4" != "无" ]]; then
        local p4=$(ping -c 1 -W 1 "$v4_ext_target" 2>/dev/null | grep -oE "time=[0-9.]+" | cut -d= -f2)
        v4_delay=$( [[ -n "$p4" ]] && echo -e "${C_YELLOW}${p4}ms(市)${C_RESET}" || echo -e "${C_RED}超时${C_RESET}" )
    fi
    if [[ -z "$v6_delay" && "$sys_ip6" != "无" ]]; then
        local p6=$(ping6 -c 1 -W 1 "$v6_ext_target" 2>/dev/null | grep -oE "time=[0-9.]+" | cut -d= -f2)
        v6_delay=$( [[ -n "$p6" ]] && echo -e "${C_YELLOW}${p6}ms(市)${C_RESET}" || echo -e "${C_RED}超时${C_RESET}" )
    fi
    v4_delay=${v4_delay:-"${C_GRAY}无${C_RESET}"}; v6_delay=${v6_delay:-"${C_GRAY}无${C_RESET}"}

    # 5. 出口逻辑渲染
    local pref="$(_get_global_mode)"
    local lock_ip="$(_read_global_lock_ip_for_pref "$pref")"
    local xray_egress="跟随系统 (默认)"
    if [[ "$pref" != "off" && -n "$lock_ip" ]]; then
        local real_pub
        real_pub=$(cat "${IP_CACHE_FILE}_xray" 2>/dev/null | tr -d '\n\r')
        [[ -z "$real_pub" ]] && real_pub="获取中..."
        local cc="??"; [[ "$real_pub" != "获取中..." && "$real_pub" != "N/A" ]] && cc=$(get_ip_country "$real_pub")
        xray_egress="${C_GREEN}${real_pub}${C_RESET} ${C_PURPLE}[${cc}]${C_RESET}"
    elif [[ "$pref" != "off" ]]; then
        xray_egress="${C_GRAY}$(_ip_mode_desc "$pref")${C_RESET} ${C_PURPLE}(未锁定本机出口IP)${C_RESET}"
    fi

    # 6. 打印对齐 UI
    echo -e "${C_BLUE}┌──[ 系统监控 ]────────────────────────────────────────────────┐${C_RESET}"
    echo -e "${C_BLUE}│${C_RESET} 状态: ${C_GREEN}[运行中]${C_RESET} | 节点: ${C_YELLOW}${node_count}${C_RESET} | 核心: ${C_CYAN}${core_ver:-未知}${C_RESET}"
    echo -e "${C_BLUE}│${C_RESET} 本机: ${local_loc} | 运行: ${C_YELLOW}${sys_uptime:-0分钟}${C_RESET}"
    echo -e "${C_BLUE}│${C_RESET} 延迟: V4: ${v4_delay} | V6: ${v6_delay}"
    echo -e "${C_BLUE}│${C_RESET} 系统 IPv4: ${C_GRAY}${sys_ip4}${C_RESET}"
    echo -e "${C_BLUE}│${C_RESET} 系统 IPv6: ${C_GRAY}${sys_ip6}${C_RESET}"
    echo -e "${C_BLUE}├──────────────────────────────────────────────────────────────┤${C_RESET}"
    echo -e "${C_BLUE}│${C_RESET} Xray 出口: ${xray_egress}"
    echo -e "${C_BLUE}└──────────────────────────────────────────────────────────────┘${C_RESET}"
}

# ============= 2. 基础依赖与 Xray 管理 (保留原逻辑) =============

is_real_systemd() {
  [[ -d /run/systemd/system ]] && ps -p 1 -o comm= 2>/dev/null | grep -q '^systemd$'
}

is_pseudo_systemd() {
  ps -p 1 -o comm,args= 2>/dev/null | grep -q 'systemctl' && ! is_real_systemd
}

_xray_bin() {
  local b="${XRAY_BIN_DEFAULT:-/usr/local/bin/xray}"
  [[ -x "$b" ]] || b="/usr/local/bin/xray"
  [[ -x "$b" ]] || b="$(command -v xray 2>/dev/null || true)"
  printf "%s" "$b"
}

_model_cfg() { printf "%s" "${CONFIG:-${XRAY_BASE_DIR}/config.json}"; }
_xray_cfg() { printf "%s" "${XRAY_CONFIG:-/etc/xray/xray_config.json}"; }

_xray_test_config() {
  local cfg="$1"
  local bin; bin="$(_xray_bin)"
  [[ -x "$bin" ]] || return 1

  # 兼容不同参数形式（不同版本 xray 的 flag 可能略有差异）
  # 不在这里吞掉输出：由调用者决定是否重定向。
  # 这样在“链接导入/手动添加”的预校验失败时，可以拿到真实的 Xray FATAL 详情。
  "$bin" run -test -c "$cfg" && return 0
  "$bin" run -test -config "$cfg" && return 0
  "$bin" -test -config "$cfg" && return 0
  "$bin" -test -c "$cfg" && return 0
  return 1
}

_translate_model_to_xray() {
  local model_cfg="$1"
  local out_cfg="$2"
  local log_path="${LOG_FILE:-/var/log/xray.log}"

  mkdir -p "$(dirname "$out_cfg")" "$(dirname "$log_path")" >/dev/null 2>&1 || true
  install_singleton_wrapper >/dev/null 2>&1 || true

  MODEL_CFG="$model_cfg"   META_CFG="$META"   OUT_CFG="$out_cfg"   LOG_PATH="$log_path"   XRAY_BASE_DIR="${XRAY_BASE_DIR:-/etc/xray}"   /usr/local/bin/xray-sync
}

_check_model_config() {
  local model_cfg="$1"
  local tmp_out
  
  # 确保临时文件有 .json 后缀
  tmp_out="/tmp/xray_test_$(date +%s).json"
  
  _translate_model_to_xray "$model_cfg" "$tmp_out" || { rm -f "$tmp_out"; return 1; }
  
  # 捕获 Xray 的错误输出
  local check_log
  check_log=$("$(_xray_bin)" run -test -c "$tmp_out" 2>&1)
  local rc=$?
  
  if [[ $rc -ne 0 ]]; then
      err "内核校验失败，原因如下："
      echo -e "${C_GRAY}${check_log}${C_RESET}" | head -n 5
      rm -f "$tmp_out"
      return 1
  fi

  rm -f "$tmp_out"
  return 0
}

# 将当前模型配置同步生成到 XRAY_CONFIG，并做语法检查
sync_xray_config() {
  local model_cfg="$(_model_cfg)"
  local out_cfg="$(_xray_cfg)"

  _translate_model_to_xray "$model_cfg" "$out_cfg" || return 1
  _xray_test_config "$out_cfg"
}

resolve_service_cmd() {
  local cmd="$1"
  if command -v "$cmd" >/dev/null 2>&1; then
    readlink -f "$(command -v "$cmd")"
    return 0
  fi
  for p in /usr/bin/"$cmd" /bin/"$cmd" /sbin/"$cmd"; do
    [ -x "$p" ] && echo "$p" && return 0
  done
  return 1
}

disown_temp_tunnel() {
  local TEMP_ARGO_DIR="/root/agsbx/temp_node"
  local TEMP_PID_FILE="$TEMP_ARGO_DIR/temp_cloudflared.pid"
  local TEMP_XRAY_PID_FILE="$TEMP_ARGO_DIR/temp_xray.pid"  
  
  if [[ -f "$TEMP_PID_FILE" ]]; then
    local cfd_pid=$(cat "$TEMP_PID_FILE" 2>/dev/null)
  else
    local cfd_pid=$(pgrep -f "$TEMP_ARGO_DIR/cloudflared_temp" | head -n 1)
  fi
  if [ -n "$cfd_pid" ] && ps -p "$cfd_pid" >/dev/null 2>&1; then
    disown "$cfd_pid" 2>/dev/null || true 
  fi
  
  if [[ -f "$TEMP_XRAY_PID_FILE" ]]; then
    local xray_pid=$(cat "$TEMP_XRAY_PID_FILE" 2>/dev/null)
  else
    local xray_pid=$(pgrep -f "$TEMP_ARGO_DIR/xray_temp" | head -n 1)
  fi
  if [ -n "$xray_pid" ] && ps -p "$xray_pid" >/dev/null 2>&1; then
    disown "$xray_pid" 2>/dev/null || true
  fi
  
  rm -f "$TEMP_PID_FILE" "$TEMP_XRAY_PID_FILE"
  return 0
}

_SYSTEMCTL_CMD="$(resolve_service_cmd systemctl || true)"
_RCSERVICE_CMD="$(resolve_service_cmd rc-service || true)"

_sb_any_port_listening() {
  local cfg="$(_model_cfg)"
  [[ -s "$cfg" ]] || return 1
  local ss_out
  ss_out=$(ss -ltnp 2>/dev/null)
  local any=""
  while read -r p; do
    [[ -z "$p" ]] && continue
    if echo "$ss_out" | grep -q ":$p "; then any=1; break; fi
  done < <(jq -r '.inbounds[].listen_port' "$cfg" 2>/dev/null)
  [[ -n "$any" ]]
}

ensure_dirs() {
  # 统一使用 /etc/xray，自动兼容迁移旧目录 /etc/xray（只迁移一次，不删旧目录）
  mkdir -p "${XRAY_BASE_DIR}"
  mkdir -p /usr/local/etc/xray && rm -f /usr/local/etc/xray/config.json && ln -sf /etc/xray/xray_config.json /usr/local/etc/xray/config.json

  if [[ -d /etc/xray ]]; then
    # 仅当新路径缺失时迁移
    [[ -f "${XRAY_BASE_DIR}/config.json" ]]       || { [[ -f /etc/xray/config.json ]] && cp -f /etc/xray/config.json "${XRAY_BASE_DIR}/config.json"; }
    [[ -f "${XRAY_BASE_DIR}/nodes_meta.json" ]]   || { [[ -f /etc/xray/nodes_meta.json ]] && cp -f /etc/xray/nodes_meta.json "${XRAY_BASE_DIR}/nodes_meta.json"; }
    [[ -f "${XRAY_BASE_DIR}/nat_ports.json" ]]    || { [[ -f /etc/xray/nat_ports.json ]] && cp -f /etc/xray/nat_ports.json "${XRAY_BASE_DIR}/nat_ports.json"; }
    [[ -f "${XRAY_BASE_DIR}/xray_config.json" ]]  || { [[ -f /etc/xray/xray_config.json ]] && cp -f /etc/xray/xray_config.json "${XRAY_BASE_DIR}/xray_config.json"; }
  fi

  [[ -f "$CONFIG" ]] || printf '%s\n' '{"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[]}}' >"$CONFIG"

  [[ -f "$META"   ]] || printf '%s\n' '{}' >"$META"

  mkdir -p "$(dirname "$LOG_FILE")" >/dev/null 2>&1 || true
  [[ -f "$LOG_FILE" ]] || : >"$LOG_FILE"
}

# 优化依赖安装：只在需要时调用
# 优化依赖安装：先装，装不上再 apt-get update（只 update 一次）
ensure_cmd() {
  local cmd="$1" deb="$2" alp="$3" cen="$4" fed="$5"
  command -v "$cmd" >/dev/null 2>&1 && return 0

  case "$(detect_os)" in
    debian|ubuntu)
      # 先不 update，直接装；失败再记录，留给 ensure_runtime_deps 统一 update+重试
      DEBIAN_FRONTEND=noninteractive apt-get install -y "$deb" >/dev/null 2>&1 && {
        command -v "$cmd" >/dev/null 2>&1 && return 0
      }

      # 失败：记录需要 update 后重试的包（全局数组）
      declare -gA _APT_RETRY_SEEN 2>/dev/null || true
      declare -ga _APT_RETRY_PKGS 2>/dev/null || true
      if [[ -n "${deb:-}" && -z "${_APT_RETRY_SEEN[$deb]:-}" ]]; then
        _APT_RETRY_SEEN["$deb"]=1
        _APT_RETRY_PKGS+=("$deb")
      fi
      return 1
      ;;

    alpine)
      apk add --no-cache "$alp" >/dev/null 2>&1 || true
      command -v "$cmd" >/dev/null 2>&1
      ;;

    centos|rhel)
      yum install -y "$cen" >/dev/null 2>&1 || true
      command -v "$cmd" >/dev/null 2>&1
      ;;

    fedora)
      dnf install -y "$fed" >/dev/null 2>&1 || true
      command -v "$cmd" >/dev/null 2>&1
      ;;

    *)
      warn "未识别系统，请手动安装：$cmd"
      return 1
      ;;
  esac
}

ensure_runtime_deps() {
  if (( DEPS_CHECKED == 1 )); then return 0; fi

  # 1. 针对 Alpine 的 DNS 预修复逻辑 (Docker 容器网络经常抖动)
  if [ -f /etc/alpine-release ]; then
    # 强制覆盖 DNS，确保能解析仓库域名
    echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" > /etc/resolv.conf
  fi

  # 2. 【删除 Swap 逻辑】 Docker 容器环境直接进入依赖检查

  # 依赖清单：Alpine 环境下 ss 在 iproute2, uuidgen 在 util-linux
  local need=(curl jq uuidgen openssl ss lsof unzip nslookup)

  # 检查是否已齐全，如果都齐全了就没必要执行 update，节省内存
  local missing_count=0
  for c in "${need[@]}"; do
    if ! command -v "$c" >/dev/null 2>&1; then ((missing_count++)); fi
  done

  if (( missing_count == 0 )); then
    DEPS_CHECKED=1
    return 0
  fi

  say "容器环境：检测到依赖缺失，正在极速补全 (分批安装模式)..."

  case "$(detect_os)" in
    alpine)
      # 1. 临时切换为 http 协议（绕过证书校验的内存开销），安装完再切回
      sed -i 's/https/http/g' /etc/apk/repositories
      
      # 2. 更新索引并立即安装基础包
      # --no-cache 会在安装后自动删除索引，是容器环境最省内存的做法
      apk add --no-cache curl jq openssl unzip || return 1
      
      # 3. 分第二批安装工具类（避免一次性加载过多索引）
      apk add --no-cache util-linux iproute2 lsof bind-tools || return 1
      
      # 4. 恢复 https 协议
      sed -i 's/http/https/g' /etc/apk/repositories
      # 5. 再次清理缓存目录，确保不留垃圾文件
      rm -rf /var/cache/apk/*
      ;;
      
    debian|ubuntu)
      # Debian/Ubuntu 容器同样建议使用 --no-install-recommends
      apt-get update -y >/dev/null 2>&1
      apt-get install -y --no-install-recommends curl jq uuid-runtime openssl iproute2 lsof unzip dnsutils >/dev/null 2>&1
      apt-get clean
      rm -rf /var/lib/apt/lists/*
      ;;
      
    *)
      # 其他系统沿用兼容逻辑
      ensure_cmd curl     curl         curl        curl       curl
      ensure_cmd jq       jq           jq          jq         jq
      ensure_cmd uuidgen  uuid-runtime util-linux  util-linux util-linux
      ensure_cmd openssl  openssl      openssl     openssl    openssl
      ensure_cmd ss       iproute2     iproute2    iproute    iproute
      ensure_cmd lsof     lsof         lsof        lsof       lsof
      ensure_cmd unzip    unzip        unzip       unzip      unzip
      ;;
  esac

  # 最终严格校验
  local missing=()
  for c in "${need[@]}"; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done

  if ((${#missing[@]} > 0)); then
    warn "仍有依赖缺失：${missing[*]}。容器内存可能极低，请尝试手动执行 apk add --no-cache [包名]"
    return 1
  fi

  DEPS_CHECKED=1
  return 0
}



install_dependencies() { ensure_runtime_deps; } # 兼容原名调用

enable_bbr() {
    # 检查是否已经开启，避免重复写入
    if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        return 0
    fi

    # 检查内核版本，BBR 需要内核 4.9+
    local kernel_version
    kernel_version="$(uname -r | cut -d- -f1)"
    local kv_major kv_minor rest
    kv_major="${kernel_version%%.*}"
    rest="${kernel_version#*.}"
    kv_minor="${rest%%.*}"
    kv_major="${kv_major:-0}"; kv_minor="${kv_minor:-0}"
    if (( kv_major < 4 || (kv_major == 4 && kv_minor < 9) )); then
        warn "内核版本过低 ($kernel_version)，无法开启 BBR。"
        return 1
    fi

    say "正在优化系统内核参数 (开启 BBR)..."
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    
    sysctl -p >/dev/null 2>&1
    ok "BBR 内核加速已成功开启。"
}

# 修改后的安装函数
install_xray_if_needed() {
  local current_bin=$(_xray_bin)
  if [[ "$1" != "--force" ]] && [[ -x "$current_bin" ]]; then return 0; fi

  # 1. 确保基础依赖（在子 shell 外处理，减少嵌套内存开销）
  ensure_runtime_deps || return 1
  
  # 2. 获取版本号
  local LATEST_VER
  LATEST_VER=$(curl -s --connect-timeout 5 https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name | sed 's/v//')
  [[ -z "$LATEST_VER" || "$LATEST_VER" == "null" ]] && LATEST_VER="1.8.24"

  warn "正在为容器环境安装 Xray v${LATEST_VER}..."

  # 3. 架构识别与 URL 构建
  local arch url
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64)   url="https://github.com/XTLS/Xray-core/releases/download/v${LATEST_VER}/Xray-linux-64.zip" ;;
    aarch64|arm64)  url="https://github.com/XTLS/Xray-core/releases/download/v${LATEST_VER}/Xray-linux-arm64-v8a.zip" ;;
    *) err "暂不支持的架构：$arch"; return 1 ;;
  esac

  # 4. 【关键优化】避开 /tmp (RAM Disk)，使用硬盘目录
  local tmp_dir="/etc/xray/install_tmp"
  rm -rf "$tmp_dir" && mkdir -p "$tmp_dir"
  
  (
    set -e
    cd "$tmp_dir"
    
    # 使用 -# 进度条，比默认输出占用的终端缓冲区更小
    curl -fL -# -o xray.zip "$url"
    
    # 【分步执行】解压后立即删除 zip，释放存储空间同时减小内存索引压力
    unzip -q -o xray.zip 
    rm -f xray.zip
    
    # 强制将解压后的文件从内存缓存刷新到硬盘
    sync 

    local bin=""
    [[ -f "./xray" ]] && bin="./xray"
    [[ -z "$bin" && -f "./Xray" ]] && bin="./Xray"

    if [[ -z "$bin" ]]; then
      exit 1
    fi

    # 安装二进制
    install -m 0755 "$bin" /usr/local/bin/xray
    [[ -f "geosite.dat" ]] && install -m 0644 "geosite.dat" /usr/local/bin/geosite.dat
    [[ -f "geoip.dat" ]] && install -m 0644 "geoip.dat" /usr/local/bin/geoip.dat
  )
  local rc=$?

  # 立即清理临时目录
  rm -rf "$tmp_dir"

  if [[ $rc -ne 0 ]]; then
    err "安装失败：可能是容器物理内存不足导致进程被宿主机杀掉。"
    return 1
  fi

  ok "Xray 核心已就绪。"
  return 0
}


# --- 建议放在 install_xray_if_needed 函数之后 ---

check_core_update() {
  local current_ver
  # 获取本地版本
  current_ver=$($(_xray_bin) version 2>/dev/null | head -n1 | awk '{print $2}')
  
  # 获取远程最新版本
  local latest_ver
  latest_ver=$(curl -s --max-time 3 https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name | sed 's/v//')
  
  if [[ -n "$latest_ver" && "$latest_ver" != "null" ]]; then
    if [[ "$current_ver" != "$latest_ver" ]]; then
      echo -e "\n${C_YELLOW}⚡ 检测到 Xray 核心有新版本: ${C_GREEN}v$latest_ver${C_RESET} ${C_GRAY}(当前: ${current_ver:-未安装})${C_RESET}"
      read -rp " 是否立即更新核心以修复密钥生成问题？(y/N): " choice
      if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        install_xray_if_needed --force
        restart_xray
      fi
    fi
  fi
}

get_country_code() {
  local CODE
  # 统一使用 ipinfo.io
  CODE=$(curl -s --max-time 3 https://ipinfo.io/country | tr -d '[:space:]')
  [[ "$CODE" =~ ^[A-Z]{2}$ ]] && printf "%s\n" "$CODE" || printf "ZZ\n"
}

generate_unique_tag() {
  local base="vless-reality-$(get_country_code)"
  local try=0 RAND CANDIDATE
  while true; do
    RAND=$(tr -dc 'A-Z' </dev/urandom 2>/dev/null | head -c1)
    CANDIDATE="${base}-${RAND}"
    if ! jq -e --arg t "$CANDIDATE" '.inbounds[] | select(.tag == $t)' "$CONFIG" >/dev/null 2>&1; then
      printf "%s\n" "$CANDIDATE"; return
    fi
    try=$((try+1))
    if [[ $try -ge 26 ]]; then
      printf "%s-%s\n" "$base" "$(date +%s)"; return
    fi
  done
}

# 端口占用检查（保留优化版）
port_status() {
  local port="$1"
  local have=0 seen_s=0 seen_o=0
  local ss_output=""
  if command -v ss >/dev/null 2>&1; then
    have=1
    ss_output=$(ss -luntp 2>/dev/null || true)
    if echo "$ss_output" | grep -q ":$port "; then
       if echo "$ss_output" | grep ":$port " | grep -qi 'users:((".*xray'; then seen_s=1; else seen_o=1; fi
    fi
  fi
  if (( have==0 )) && command -v lsof >/dev/null 2>&1; then
    have=1
    local names=""
    names+=$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1}')
    names+=$(lsof -nP -iUDP:"$port" 2>/dev/null | awk 'NR>1{print $1}')
    if [[ -n "$names" ]]; then
      if echo "$names" | grep -Eqi 'xray'; then seen_s=1; else seen_o=1; fi
    fi
  fi
  if (( seen_s==1 )); then return 0; elif (( seen_o==1 )); then return 1; else return 2; fi
}

load_nat_data() {
  if [[ -f "$NAT_FILE" ]]; then
    nat_mode=$(jq -r '.mode // "custom"' "$NAT_FILE")
    mapfile -t nat_ranges < <(jq -r '.ranges[]?' "$NAT_FILE")
    mapfile -t nat_tcp < <(jq -r '.custom_tcp[]?' "$NAT_FILE" | sort -n -u)
    mapfile -t nat_udp < <(jq -r '.custom_udp[]?' "$NAT_FILE" | sort -n -u)
  else
    nat_mode=""
    nat_ranges=()
    nat_tcp=()
    nat_udp=()
  fi
}

get_random_allowed_port() {
  local proto="$1"
  local -a used=()
  mapfile -t used < <(jq -r '.inbounds[].listen_port' "$CONFIG" 2>/dev/null | grep -E '^[0-9]+$' || true)
  mapfile -t hy2u < <(jq -r 'to_entries[]? | select(.value.type=="hysteria2") | .value.port' "$META" 2>/dev/null || true)
  used+=("${hy2u[@]}")

  local -a candidates=()
  if [[ -n "$nat_mode" ]]; then
    if [[ "$nat_mode" == "range" ]]; then
      for range in "${nat_ranges[@]}"; do
        local s=${range%-*} e=${range#*-} p
        for ((p=s; p<=e; p++)); do candidates+=("$p"); done
      done
    else
      if [[ "$proto" == "tcp" ]]; then candidates=("${nat_tcp[@]}")
      elif [[ "$proto" == "udp" ]]; then candidates=("${nat_udp[@]}")
      else candidates=("${nat_tcp[@]}" "${nat_udp[@]}")
      fi
    fi
    local free=() usedset=" ${used[*]} "
    for c in "${candidates[@]}"; do
      [[ "$usedset" == *" $c "* ]] && continue
      free+=("$c")
    done
    if ((${#free[@]}==0)); then echo "NO_PORT"; return 1; fi
    echo "${free[RANDOM % ${#free[@]}]}"; return 0
  else
    if [[ "$proto" == "tcp" ]]; then echo $((RANDOM%10000 + 30000))
    elif [[ "$proto" == "udp" ]]; then echo $((RANDOM%10000 + 50000))
    else echo $((RANDOM%1000 + 30000)); fi
  fi
}

check_nat_allow() {
  local port="$1" proto="$2"
  if [[ -z "$nat_mode" ]]; then return 0; fi
  if [[ "$nat_mode" == "range" ]]; then
    for range in "${nat_ranges[@]}"; do
      local s=${range%-*} e=${range#*-}
      if (( port >= s && port <= e )); then return 0; fi
    done
    return 1
  elif [[ "$nat_mode" == "custom" ]]; then
    local arr=()
    if [[ "$proto" == "tcp" ]]; then arr=("${nat_tcp[@]}")
    elif [[ "$proto" == "udp" ]]; then arr=("${nat_udp[@]}")
    else arr=("${nat_tcp[@]}" "${nat_udp[@]}")
    fi
    printf '%s\n' "${arr[@]}" | grep -qx "$port"; return $?
  else
    return 0
  fi
}

generate_self_signed_cert() {
  local key_file="$1" cert_file="$2" domain="$3"
  umask 077
  openssl ecparam -name prime256v1 -genkey -noout -out "$key_file" 2>/dev/null || \
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$key_file" 2>/dev/null
  openssl req -new -x509 -nodes -key "$key_file" -out "$cert_file" -subj "/CN=$domain" -days 36500 >/dev/null 2>&1
  chmod 600 "$key_file" "$cert_file"
  if [[ -f "$cert_file" && -f "$key_file" ]]; then return 0; else return 1; fi
}

ensure_service_openrc() {
  install_singleton_wrapper
  cat <<'EOF' >/etc/init.d/xray
#!/sbin/openrc-run
name="xray"
description="Xray Service"
command="/usr/local/bin/xray"
command_args="run -c /etc/xray/xray_config.json"
pidfile="/run/xray.pid"
output_log="/var/log/xray.log"
error_log="/var/log/xray.log"
command_background="yes"

depend() {
  need net
  after firewall
}
start_pre() {
  /usr/local/bin/xray-sync || return 1
  /usr/local/bin/xray run -test -c /etc/xray/xray_config.json || /usr/local/bin/xray -test -c /etc/xray/xray_config.json || return 1
}
EOF
  chmod +x /etc/init.d/xray
  rc-update add xray default >/dev/null 2>&1
  rc-service xray restart >/dev/null 2>&1 || rc-service xray start >/dev/null 2>&1
}

# 修复功能保留
check_and_repair_menu() {
  say "====== 系统检测与修复（合并） ======"
  system_check # 原有检测逻辑
  local status=$?
  local did_fix=0

  if (( status != 0 )); then
    say ""
    warn "检测到异常，建议执行自动修复（安装缺依赖 / 修复服务 / 纠正证书等）。"
    read -rp "是否立即按建议修复？(Y/n): " dofix
    dofix=${dofix:-Y}
    if [[ "$dofix" == "Y" || "$dofix" == "y" ]]; then
      fix_errors # 原有修复逻辑
      did_fix=1
      say ""
      ok "修复操作完成，正在重新检测..."
      system_check
    else
      say "已跳过修复。"
    fi
  else
    ok "系统状态良好，无需修复。"
  fi

  if (( did_fix == 1 )); then
    say "正在重启 Xray 服务以应用修复..."
    if ! restart_xray; then
      warn "自动重启失败，请在“脚本服务”中手动选择 2) 重启 Xray 服务。"
    else
      ok "Xray 服务已重启。"
    fi
  fi
  read -rp "修复完成，按回车返回..." _
  return
}

install_systemd_service() {
  local SERVICE_FILE="/etc/systemd/system/xray.service"
  # 强制使用脚本定义的路径
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStartPre=/usr/local/bin/xray-sync
# 核心修复：显式指定配置文件路径
ExecStart=/usr/local/bin/xray run -c /etc/xray/xray_config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable xray
}

install_logrotate() {
  local conf="/etc/logrotate.d/xray"
  [[ -f "$conf" ]] && return 0
  cat > "$conf" <<'LR'
/var/log/xray.log {
  weekly
  rotate 8
  compress
  missingok
  notifempty
  copytruncate
}
LR
}

install_watchdog_cron() {
  if ! command -v crontab >/dev/null 2>&1; then return 0; fi
  local marker="# xray-watchdog"
  crontab -l >/dev/null 2>&1 || true
  crontab -l 2>/dev/null | grep -v "$marker" > /tmp/crontab.tmp 2>/dev/null || true
  echo "* * * * * /usr/local/bin/xray-singleton >/dev/null 2>&1  $marker" >> /tmp/crontab.tmp
  crontab /tmp/crontab.tmp
  rm -f /tmp/crontab.tmp
}

install_singleton_wrapper() {
  local xray_bin="/usr/local/bin/xray"

  # 1. 确保目录结构存在，并建立路径软链接
  mkdir -p /etc/xray /usr/local/etc/xray
  ln -sf /etc/xray/xray_config.json /usr/local/etc/xray/config.json

  # 2. 生成 xray-sync (配置转换引擎)
  cat > /usr/local/bin/xray-sync <<'SYNC'
#!/usr/bin/env bash
set -euo pipefail
umask 022

XRAY_BASE_DIR="${XRAY_BASE_DIR:-/etc/xray}"
MODEL_CFG="${MODEL_CFG:-${XRAY_BASE_DIR}/config.json}"
META_CFG="${META_CFG:-${XRAY_BASE_DIR}/nodes_meta.json}"
OUT_CFG="${OUT_CFG:-${XRAY_BASE_DIR}/xray_config.json}"
LOG_PATH="${LOG_PATH:-/var/log/xray.log}"
IP_PREF_FILE="${IP_PREF_FILE:-${XRAY_BASE_DIR}/ip_pref}"
LOCK_V4_FILE="${LOCK_V4_FILE:-${XRAY_BASE_DIR}/global_egress_ip_v4}"
LOCK_V6_FILE="${LOCK_V6_FILE:-${XRAY_BASE_DIR}/global_egress_ip_v6}"
FORCE_V4_FILE="${FORCE_V4_FILE:-${XRAY_BASE_DIR}/force_v4_domains.txt}"

mkdir -p "$XRAY_BASE_DIR" "$(dirname "$OUT_CFG")" "$(dirname "$LOG_PATH")"
[[ -s "$MODEL_CFG" ]] || printf '%s\n' '{"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[]}}' > "$MODEL_CFG"
[[ -s "$META_CFG" ]] || printf '%s\n' '{}' > "$META_CFG"

sanitize_pref() {
  local p="${1:-}"
  p="${p//$'\r'/}"
  p="${p// /}"
  case "$p" in
    ""|"(未设置)"|"follow_global"|"follow") echo "off" ;;
    *) echo "$p" ;;
  esac
}

G_PREF="$(sanitize_pref "$(cat "$IP_PREF_FILE" 2>/dev/null || true)")"
case "${G_PREF}" in
  v6pref|v6) DS="UseIPv6v4" ;;
  v4pref|v4) DS="UseIPv4v6" ;;
  v6only)    DS="UseIPv6" ;;
  v4only)    DS="UseIPv4" ;;
  off)       DS="AsIs" ;;
  *)         DS="AsIs" ;;
esac

read_lock_file() {
  local file="$1"
  if [[ -r "$file" ]]; then
    tr -d '
 ' < "$file" 2>/dev/null || true
  else
    echo ""
  fi
}

G_LOCK_V4="$(read_lock_file "$LOCK_V4_FILE")"
G_LOCK_V6="$(read_lock_file "$LOCK_V6_FILE")"

NEED_FVD=0
if [[ "$G_PREF" == "v6pref" || "$G_PREF" == "v6" ]]; then
  NEED_FVD=1
elif jq -e 'to_entries | any(.value.ip_mode=="v6pref")' "$META_CFG" >/dev/null 2>&1; then
  NEED_FVD=1
fi

FVD_JSON="[]"
if [[ "$NEED_FVD" == "1" ]]; then
  if [[ ! -s "$FORCE_V4_FILE" ]]; then
    cat > "$FORCE_V4_FILE" <<'EOF2'
discord.com
x.com
openai.com
EOF2
  fi
  FVD_JSON="$(
    awk '
      {gsub("\r","");}
      NF && $0 !~ /^[[:space:]]*#/ {print "domain:"$0}
    ' "$FORCE_V4_FILE" | jq -Rsc 'split("\n") | map(select(length>0))'
  )"
fi

jq --arg log "$LOG_PATH" \
   --arg ds "$DS" \
   --arg pref "$G_PREF" \
   --arg gv4 "$G_LOCK_V4" \
   --arg gv6 "$G_LOCK_V6" \
   --argjson fvd "$FVD_JSON" \
   --slurpfile meta "$META_CFG" '
  def _listen: (.listen // "0.0.0.0");
  def _port: ((.listen_port // .port // 0) | tonumber);
  def _bind(ip): if (ip|type)=="string" and (ip|length)>0 then {sendThrough: ip} else {} end;
  def _freedom(tag; strategy; bindip): { protocol:"freedom", tag: tag, settings:{ domainStrategy: strategy } } + _bind(bindip);

  def _mode_for_raw(t; m): (m[t].ip_mode // "");
  def _mode_tag(m):
    if m == "v6pref" then "DIRECT-V6PREF"
    elif m == "v4pref" then "DIRECT-V4PREF"
    elif m == "v6only" then "DIRECT-V6ONLY"
    elif m == "v4only" then "DIRECT-V4ONLY"
    else "DIRECT" end;
  def _map_outbound(ob; inb_raw; m):
    (ob // "DIRECT" | ascii_upcase) as $obu
    | if $obu != "DIRECT" then $obu
      elif (inb_raw|length) == 1 then _mode_tag(_mode_for_raw(inb_raw[0]; m))
      else "DIRECT"
      end;

  def mk_outbound:
    if .type == "direct" then
      _freedom((.tag // "DIRECT" | ascii_upcase); $ds; (.sendThrough // .send_through // ""))
    elif .type == "socks" then
      { protocol:"socks", tag:(.tag | ascii_upcase),
        settings:{ servers:[{ address:.server, port:(.server_port|tonumber),
          users:(if (.username // "") != "" and (.password // "") != "" then [{user:.username, pass:.password}] else [] end)
        }] } }
    elif .type == "http" then
      { protocol:"http", tag:(.tag | ascii_upcase),
        settings:{ servers:[{ address:.server, port:(.server_port|tonumber),
          users:(if (.username // "") != "" and (.password // "") != "" then [{user:.username, pass:.password}] else [] end)
        }] } }
    elif .type == "shadowsocks" then
      { protocol:"shadowsocks", tag:(.tag | ascii_upcase),
        settings:{ servers:[{ address:.server, port:(.server_port|tonumber), method:(.method // "aes-256-gcm"), password:.password }] } }
    elif .type == "vless" then
      if (.client_seed != null and .client_seed != "") then
        { protocol:"vless", tag:(.tag | ascii_upcase),
          settings:{ vnext:[{ address:.server, port:(.server_port|tonumber), users:[{ id:(.uuid // .id), encryption:.client_seed, flow:(.flow // "") }] }] },
          streamSettings:{ network:"tcp", security:"none" } }
      else
        { protocol:"vless", tag:(.tag | ascii_upcase),
          settings:{ vnext:[{ address:.server, port:(.server_port|tonumber), users:[{ id:(.uuid // .id), encryption:"none", flow:(.flow // "") }] }] },
          streamSettings: (.streamSettings // {
            network: (.transport.type // .network // "tcp"),
            security: (if ((.tls.reality.public_key // .pbk // "") != "") then "reality" else "none" end),
            realitySettings: (if ((.tls.reality.public_key // .pbk // "") != "") then {
              show: false,
              fingerprint: (.tls.utls.fingerprint // .fp // "chrome"),
              serverName: (.tls.server_name // .sni // "www.microsoft.com"),
              publicKey: (.tls.reality.public_key // .pbk // ""),
              shortId: (if ((.tls.reality.short_id // []) | length) > 0 then (.tls.reality.short_id[0] | tostring) else (.sid // "") end),
              spiderX: "/"
            } else empty end),
            tcpSettings: (if ((.transport.type // .network // "tcp") == "tcp") then { header: { type: (.transport.header_type // .headerType // "none") } } else empty end)
          })
        }
      end
    elif .type == "vmess" then
      { protocol:"vmess", tag:(.tag | ascii_upcase),
        settings:{ vnext:[{ address:.server, port:(.server_port|tonumber), users:[{ id:(.uuid // .id), security:"auto", alterId:0 }] }] },
        streamSettings: (.streamSettings // {
          network: (.transport.type // .network // "tcp"),
          security: (if (.tls.enabled == true or .tls != null) then "tls" else "none" end),
          tlsSettings: (if (.tls.enabled == true or .tls != null) then { serverName: (.tls.server_name // .sni // ""), allowInsecure: true } else empty end),
          wsSettings: (if (.transport.type == "ws") then { path: (.transport.ws_settings.path // ""), headers: { Host: (.transport.ws_settings.headers.Host // "") } } else empty end)
        }) }
    else
      _freedom((.tag // "DIRECT" | ascii_upcase); $ds; "")
    end;

  def mk_inbound:
    if .type == "socks" then
      { tag:(.tag // "SOCKS-IN" | ascii_upcase), listen:_listen, port:_port, protocol:"socks",
        settings:{ auth:(if ((.users // [])|length) > 0 then "password" else "noauth" end), accounts:((.users // []) | map({user:.username, pass:.password})), udp:true },
        sniffing:{ enabled:true, destOverride:["http","tls"] } }
    elif .type == "vless" then
      if (.server_seed != null and .server_seed != "") then
        { tag:(.tag // "VLESS-IN" | ascii_upcase), listen:_listen, port:_port, protocol:"vless",
          settings:{ clients:((.users // []) | map({id:(.uuid // .id // ""), flow:(.flow // empty)})), decryption:.server_seed },
          streamSettings:{ network:"tcp", security:"none" },
          sniffing:{ enabled:true, destOverride:["http","tls"] } }
      else
        { tag:(.tag // "VLESS-IN" | ascii_upcase), listen:_listen, port:_port, protocol:"vless",
          settings:{ clients:((.users // []) | map({id:(.uuid // .id // ""), flow:(.flow // empty)})), decryption:"none" },
          streamSettings:{ network:"tcp", security:"reality",
            realitySettings:{ show:false, dest:(((.tls.reality.handshake.server // .tls.server_name // "www.microsoft.com")|tostring) + ":" + (((.tls.reality.handshake.server_port // 443)|tonumber)|tostring)),
              xver:0, serverNames:[(.tls.server_name // .tls.reality.handshake.server // "www.microsoft.com")],
              privateKey:(.tls.reality.private_key // ""), shortIds:(.tls.reality.short_id // []) } },
          sniffing:{ enabled:true, destOverride:["http","tls"] } }
      end
    elif .type == "shadowsocks" then
      { tag:(.tag // "SS-IN" | ascii_upcase), listen:_listen, port:_port, protocol:"shadowsocks",
        settings:{ method:(.method // "aes-256-gcm"), password:(.password // ""), network:"tcp,udp" },
        sniffing:{ enabled:true, destOverride:["http","tls"] } }
    elif .type == "http" then
      { tag:(.tag // "HTTP-IN" | ascii_upcase), listen:_listen, port:_port, protocol:"http",
        settings:{ accounts:((.users // []) | map({user:.username, pass:.password})) },
        sniffing:{ enabled:true, destOverride:["http","tls"] } }
    else empty end;

  def mk_rule(m):
    (if (.inbound | type) == "array" then (.inbound | map(tostring)) else [(.inbound // empty | tostring)] end) as $inb_raw
    | ($inb_raw | map(ascii_upcase)) as $inb
    | ({ type:"field", outboundTag:_map_outbound((.outbound // "DIRECT"); $inb_raw; m), inboundTag:$inb }
       + (if (.domain? != null) then { domain:(if (.domain|type)=="array" then .domain else [.domain] end) } else {} end)
       + (if (.ip? != null) then { ip:(if (.ip|type)=="array" then .ip else [.ip] end) } else {} end)
       + (if (.port? != null) then { port:(if (.port|type)=="array" then .port else [.port] end) } else {} end)
       + (if (.protocol? != null) then { protocol:(if (.protocol|type)=="array" then .protocol else [.protocol] end) } else {} end)
      );

  . as $root
  | ($meta[0] // {}) as $m_data
  | ([ $root.inbounds[]? | select(.type=="vless" and .server_seed==null) | (.tls.server_name // .tls.reality.handshake.server // empty) ] | unique) as $reality_domains
  | (if (($fvd|type) == "array") then $fvd else [] end) as $force_v4
  | {
      log: { loglevel:"warning", access:$log, error:$log },
      stats: {},
      api: { tag:"API", services:["HandlerService","LoggerService","StatsService"] },
      policy: {
        levels: { "0": { "statsUserUplink": true, "statsUserDownlink": true } },
        system: { "statsInboundUplink": true, "statsInboundDownlink": true, "statsOutboundUplink": true, "statsOutboundDownlink": true }
      },
      dns: { servers:["1.1.1.1","8.8.8.8","2606:4700:4700::1111","2001:4860:4860::8888"], queryStrategy:$ds },
      inbounds: ((($root.inbounds // []) | map(mk_inbound)) + [{ tag:"API", port:47302, listen:"127.0.0.1", protocol:"dokodemo-door", settings:{ address:"127.0.0.1" } }]),
      outbounds: (
        ((($root.outbounds // []) | map(mk_outbound))
          + [
              _freedom("DIRECT"; $ds; ""),
              { protocol:"freedom", tag:"API", settings:{} },
              { protocol:"blackhole", tag:"BLOCK", settings:{} },
              _freedom("DIRECT-V4"; "UseIPv4"; $gv4),
              _freedom("DIRECT-V6"; "UseIPv6"; $gv6),
              _freedom("DIRECT-V6PREF"; "UseIPv6v4"; ""),
              _freedom("DIRECT-V4PREF"; "UseIPv4v6"; ""),
              _freedom("DIRECT-V6ONLY"; "UseIPv6"; ""),
              _freedom("DIRECT-V4ONLY"; "UseIPv4"; "")
            ]
          + (if ($gv4|length) > 0 then [ _freedom("GLOBAL-V4-BIND"; "UseIPv4"; $gv4) ] else [] end)
          + (if ($gv6|length) > 0 then [ _freedom("GLOBAL-V6-BIND"; "UseIPv6"; $gv6) ] else [] end)
          + ($m_data | to_entries | map(select((.value.fixed_ip // "") != "")) | map(
                _freedom(("BIND-" + (.key | ascii_upcase)); (if .value.ip_version == "v6" then "UseIPv6" else "UseIPv4" end); .value.fixed_ip)
             ))
        ) | unique_by(.tag)
      ),
      routing: {
        domainStrategy: $ds,
        rules: (
          [ { type:"field", inboundTag:["API"], outboundTag:"API" } ]
          + (if (($force_v4|length) > 0 and ($pref == "v6pref" or $pref == "v6")) then [ { type:"field", domain:$force_v4, outboundTag:"DIRECT-V4" } ] else [] end)
          + (if (($force_v4|length) > 0) then ($m_data | to_entries | map(select(.value.ip_mode == "v6pref")) | map({ type:"field", inboundTag:[.key | ascii_upcase], domain:$force_v4, outboundTag:"DIRECT-V4" })) else [] end)
          + (($root.route.rules // []) | map(mk_rule($m_data)))
          + (if (($reality_domains|length) > 0) then [ { type:"field", domain:($reality_domains | map("domain:" + .)), outboundTag:"DIRECT-V4" } ] else [] end)
          + ($m_data | to_entries | map(select((.value.fixed_ip // "") != "")) | map(
              if .value.ip_version == "v6" and .value.ip_mode == "v6pref" then
                [ { type:"field", inboundTag:[.key | ascii_upcase], ip:["::/0"], outboundTag:("BIND-" + (.key | ascii_upcase)) },
                  { type:"field", inboundTag:[.key | ascii_upcase], ip:["0.0.0.0/0"], outboundTag:"DIRECT-V4" } ]
              elif .value.ip_version == "v6" and .value.ip_mode == "v6only" then
                [ { type:"field", inboundTag:[.key | ascii_upcase], ip:["::/0"], outboundTag:("BIND-" + (.key | ascii_upcase)) },
                  { type:"field", inboundTag:[.key | ascii_upcase], ip:["0.0.0.0/0"], outboundTag:"BLOCK" } ]
              elif .value.ip_version == "v4" and .value.ip_mode == "v4pref" then
                [ { type:"field", inboundTag:[.key | ascii_upcase], ip:["0.0.0.0/0"], outboundTag:("BIND-" + (.key | ascii_upcase)) },
                  { type:"field", inboundTag:[.key | ascii_upcase], ip:["::/0"], outboundTag:"DIRECT-V6" } ]
              elif .value.ip_version == "v4" and .value.ip_mode == "v4only" then
                [ { type:"field", inboundTag:[.key | ascii_upcase], ip:["0.0.0.0/0"], outboundTag:("BIND-" + (.key | ascii_upcase)) },
                  { type:"field", inboundTag:[.key | ascii_upcase], ip:["::/0"], outboundTag:"BLOCK" } ]
              else
                [ { type:"field", inboundTag:[.key | ascii_upcase], outboundTag:("BIND-" + (.key | ascii_upcase)) } ]
              end
            ) | flatten)
          + ($m_data | to_entries | map(select(.value.ip_mode != null and .value.ip_mode != "" and .value.ip_mode != "follow_global" and .value.ip_mode != "follow")) | map(
              if .value.ip_mode == "v6only" then
                [ { type:"field", inboundTag:[.key | ascii_upcase], ip:["0.0.0.0/0"], outboundTag:"BLOCK" },
                  { type:"field", inboundTag:[.key | ascii_upcase], outboundTag:"DIRECT-V6ONLY" } ]
              elif .value.ip_mode == "v4only" then
                [ { type:"field", inboundTag:[.key | ascii_upcase], ip:["::/0"], outboundTag:"BLOCK" },
                  { type:"field", inboundTag:[.key | ascii_upcase], outboundTag:"DIRECT-V4ONLY" } ]
              else
                [ { type:"field", inboundTag:[.key | ascii_upcase], outboundTag:_mode_tag(.value.ip_mode) } ]
              end
            ) | flatten)
          + (if ($pref == "v6pref" or $pref == "v6") and ($gv6|length) > 0 then
                [ { type:"field", ip:["::/0"], outboundTag:"GLOBAL-V6-BIND" },
                  { type:"field", ip:["0.0.0.0/0"], outboundTag:"DIRECT-V4" } ]
             elif ($pref == "v6only") and ($gv6|length) > 0 then
                [ { type:"field", ip:["::/0"], outboundTag:"GLOBAL-V6-BIND" },
                  { type:"field", ip:["0.0.0.0/0"], outboundTag:"BLOCK" } ]
             elif ($pref == "v4pref" or $pref == "v4") and ($gv4|length) > 0 then
                [ { type:"field", ip:["0.0.0.0/0"], outboundTag:"GLOBAL-V4-BIND" },
                  { type:"field", ip:["::/0"], outboundTag:"DIRECT-V6" } ]
             elif ($pref == "v4only") and ($gv4|length) > 0 then
                [ { type:"field", ip:["0.0.0.0/0"], outboundTag:"GLOBAL-V4-BIND" },
                  { type:"field", ip:["::/0"], outboundTag:"BLOCK" } ]
             else [] end)
          + [ { type:"field", network:"tcp,udp", outboundTag:"DIRECT" } ]
        )
      }
    }
' "$MODEL_CFG" > "$OUT_CFG"
SYNC
  chmod +x /usr/local/bin/xray-sync

  # 3. 生成 xray-singleton (单例管理脚本)
  cat > /usr/local/bin/xray-singleton <<'WRAP'
#!/usr/bin/env bash
set -euo pipefail
XRAY_BASE_DIR="/etc/xray"
PIDFILE="/run/xray.pid"
OUT_CFG="${XRAY_BASE_DIR}/xray_config.json"
BIN="/usr/local/bin/xray"
LOG="/var/log/xray.log"

# 1. 尝试同步配置
/usr/local/bin/xray-sync >/dev/null 2>&1 || true

# 2. 配置自检，失败则报错退出
if ! "$BIN" run -test -c "$OUT_CFG" >/dev/null 2>&1; then
    echo "Xray config test failed! Check /etc/xray/config.json" >&2
    exit 1
fi

# 3. 杀死旧进程并启动新进程
pkill -f "/usr/local/bin/xray run -c" >/dev/null 2>&1 || true
setsid "$BIN" run -c "$OUT_CFG" >> "$LOG" 2>&1 &
echo $! > "$PIDFILE"
WRAP
  chmod +x /usr/local/bin/xray-singleton
}


install_autostart_fallback() {
  if [[ -f /etc/alpine-release ]]; then
    mkdir -p /etc/local.d
    cat > /etc/local.d/xray.start <<'EOL'
#!/bin/sh
/usr/local/bin/xray-singleton >> /var/log/xray.log 2>&1 &
EOL
    chmod +x /etc/local.d/xray.start
    rc-update add local default >/dev/null 2>&1 || true
  else
    local rc="/etc/rc.local"
    if [[ ! -f "$rc" ]]; then
      cat > "$rc" <<'RC'
#!/bin/sh -e
sleep 1
/usr/local/bin/xray-singleton >> /var/log/xray.log 2>&1 &
exit 0
RC
      chmod +x "$rc"
    else
      grep -q '^#!/bin/sh' "$rc" || sed -i '1i #!/bin/sh -e' "$rc"
      grep -q '^exit 0$' "$rc" || printf '\nexit 0\n' >> "$rc"
      if ! grep -q '/usr/local/bin/xray-singleton' "$rc"; then
        sed -i '/^exit 0/i /usr/local/bin/xray-singleton >> /var/log/xray.log 2>&1 &' "$rc"
      fi
      chmod +x "$rc"
    fi
  fi
}

start_xray_legacy_nohup() {
  if command -v /usr/local/bin/xray-singleton >/dev/null 2>&1; then
    daemonize /usr/local/bin/xray-singleton --force
  else
    daemonize /usr/local/bin/xray run -c "${XRAY_CONFIG:-/etc/xray/xray_config.json}"
  fi
}

start_xray_singleton_force() {
  # 1. 核心环境预修复：路径对齐与配置同步
  # 彻底解决你遇到的 "open config.json: no such file" 问题
  mkdir -p /usr/local/etc/xray /etc/xray
  ln -sf /etc/xray/xray_config.json /usr/local/etc/xray/config.json

  # 强制同步一次配置，确保 API 标签和闭合逻辑已注入，防止 status 23 错误
  if command -v xray-sync >/dev/null 2>&1; then
      /usr/local/bin/xray-sync >/dev/null 2>&1 || true
  fi

  # 2. 彻底清理旧进程与 PID 锁
  # 使用 -9 强制杀死，防止僵尸进程占用 11732 或 47302 端口
  pkill -9 -f "/usr/local/bin/xray" >/dev/null 2>&1 || true
  rm -f /run/xray.pid /var/run/xray.pid >/dev/null 2>&1 || true
  sleep 1

  # 3. 启动前语法自检 (关键防线)
  # 如果配置测试不通过，直接报错，不盲目启动
  if ! /usr/local/bin/xray run -test -c /etc/xray/xray_config.json >/dev/null 2>&1; then
      err "Xray 启动失败：配置文件校验未通过，请检查 /etc/xray/config.json"
      return 1
  fi

  # 4. 动态内存压制策略 (自动适配容器与 VPS)
  local total_mem
  total_mem=$(free -m | awk '/Mem:/ {print $2}')
  
  # 显式指定资源路径，减少核心启动时的 IO 扫描
  export XRAY_LOCATION_ASSET=/usr/local/bin/

  if [[ "$total_mem" -le 300 ]]; then
    # 【极致省电模式】：针对小内存容器
    export GOMEMLIMIT=64MiB
    export GOGC=15  # 激进回收
    export GODEBUG=madvdontneed=1 # 立即归还内存给宿主机
    say "检测到极小内存环境 ($total_mem MB)，已开启极致压制模式"
  else
    # 【标准性能模式】：针对普通 VPS
    export GOMEMLIMIT=128MiB
    export GOGC=50
  fi

  # 5. 异步探测任务延迟执行
  # 避开启动时的 CPU 峰值，确保节点能优先跑起来
  (sleep 30 && update_ip_async) &

  # 6. 执行启动
  # 使用绝对路径和明确的配置文件，确保单例运行
  daemonize /usr/local/bin/xray run -c /etc/xray/xray_config.json

  # 7. 观察期与深度状态校验
  sleep 3
  if ! pgrep -f "/usr/local/bin/xray" >/dev/null 2>&1; then
    err "启动失败：进程可能由于内存溢出 (OOM) 或端口占用被杀掉"
    if [[ -f "/var/log/xray.log" ]]; then
       echo -e "${C_GRAY}日志最后 3 行内容：${C_RESET}"
       tail -n 3 /var/log/xray.log
    fi
    return 1
  fi

  ok "Xray 核心服务已强制拉起成功。"
  return 0
}

auto_optimize_cpu() {
  local pid
  # 修改：使用 -f 匹配完整路径，确保能抓到你在 ps 输出中看到的那个进程
  pid=$(pgrep -f "/usr/local/bin/xray" | head -n1)
  if [[ -n "$pid" ]] && command -v renice >/dev/null 2>&1; then
     renice -n -10 -p "$pid" >/dev/null 2>&1
  fi
}

sync_and_restart_argo() {
    # 1. 获取当前最新的全局出口偏好
    local pref ds lock_ip
    IFS=$'\t' read -r pref ds lock_ip < <(_get_global_egress_pref_and_lock)

    # 构造新的 Outbound JSON
    local outbound_json='{ "protocol": "freedom", "settings": { "domainStrategy": "'$ds'" } }'
    [[ -n "$lock_ip" ]] && outbound_json='{ "protocol": "freedom", "settings": { "domainStrategy": "'$ds'" }, "sendThrough": "'$lock_ip'" }'

    # 2. 精准清理：只杀固定隧道，跳过临时隧道 (*_temp)
    pkill -f "cloudflared.*--token" >/dev/null 2>&1
    pkill -f "/root/agsbx/xray.*argo_users" >/dev/null 2>&1
    sleep 0.5

    # 3. [已彻底移除] 临时隧道重启逻辑，确保其域名不断开

    # 4. 仅同步重启所有固定隧道
    local tags; tags=$(jq -r 'to_entries[] | select(.value.type=="argo" and .value.token!=null) | .key' "$META" 2>/dev/null)
    for t in $tags; do
        local p; p=$(jq -r --arg t "$t" '.[$t].port' "$META")
        local tk; tk=$(jq -r --arg t "$t" '.[$t].token' "$META")
        local f_cfg="/etc/xray/argo_users/${p}.json"
        if [[ -f "$f_cfg" ]]; then
            local f_tmp; f_tmp=$(mktemp)
            jq --argjson out "[${outbound_json}]" '.outbounds = $out' "$f_cfg" > "$f_tmp" && mv "$f_tmp" "$f_cfg"
            nohup /root/agsbx/xray run -c "$f_cfg" >/dev/null 2>&1 &
            nohup /root/agsbx/cloudflared tunnel --no-autoupdate --protocol http2 run --token "$tk" >/dev/null 2>&1 &
        fi
    done
}

restart_xray() {
  local mode="${1:-all}"
  
  # 1. 立即清理缓存和探测锁
  rm -f "${IP_CACHE_FILE}_xray" "${IP_CACHE_FILE}_xray_status" /tmp/ip_probe.lock 2>/dev/null
  install_singleton_wrapper >/dev/null 2>&1 || true

  # 每次重启 Xray 时，重新下发底层的 tc 限速规则
  apply_port_limits

  # 2. 先同步主模型并做 Xray 语法校验
  if ! sync_xray_config >/dev/null 2>&1; then
    err "配置文件不合法（Xray 校验未通过）"
    return 1
  fi

  # 3. 🚀 关键解耦：如果参数是 main_only，则跳过 Argo 隧道的重启
  if [[ "$mode" != "main_only" ]]; then
    sync_and_restart_argo
  fi

  local success_msg="主服务及所有 Argo 隧道已完成出口同步并重启"
  [[ "$mode" == "main_only" ]] && success_msg="主服务已完成重启 (Argo 隧道不受影响)"

  # --- 路径 A: systemd 托管 ---
  if command -v systemctl >/dev/null 2>&1 && is_real_systemd; then
    if ! systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx 'xray.service'; then
      install_systemd_service >/dev/null 2>&1 || true
    fi

    systemctl restart xray >/dev/null 2>&1 || true
    
    # 🚀 优化：轮询等待，最快 0.1 秒即可放行，最长等 1.5 秒
    local waited=0
    while ! systemctl is-active --quiet xray && (( waited < 15 )); do
        sleep 0.1
        waited=$((waited + 1))
    done
    
    if systemctl is-active --quiet xray; then
      update_ip_async  # 启动成功立即触发 IP 探测
      ok "${success_msg} (systemd)"
      return 0
    fi
  fi

  # --- 路径 B: OpenRC 托管 ---
  if command -v rc-service >/dev/null 2>&1 && [[ -f /etc/init.d/xray ]]; then
    rc-service xray restart >/dev/null 2>&1 || true
    
    # 🚀 优化：轮询等待，告别硬 sleep
    local waited=0
    while ! rc-service xray status 2>/dev/null | grep -q started && (( waited < 15 )); do
        sleep 0.1
        waited=$((waited + 1))
    done
    
    if rc-service xray status 2>/dev/null | grep -q started; then
      update_ip_async
      ok "${success_msg} (OpenRC)"
      return 0
    fi
  fi

  # --- 路径 C: Fallback ---
  pkill -x xray >/dev/null 2>&1 || true
  if start_xray_singleton_force; then
    auto_optimize_cpu
    update_ip_async
    ok "${success_msg} (Fallback)"
    return 0
  fi

  err "Xray 重启失败"
  return 1
}

# ============= 新增：自动检测并修复 MTU / PMTUD 黑洞 =============
auto_fix_mtu_mss() {
    say "正在检测 MTU / PMTUD 黑洞问题..."
    
    # 获取默认公网出口网卡
    local iface
    iface=$(ip -4 route ls 2>/dev/null | awk '/^default/ {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')
    
    if [[ -z "$iface" ]]; then
        warn "未找到默认公网网卡，跳过 MTU 修复。"
        return 0
    fi

    # 获取当前网卡实际 MTU 和 路由表建议的 MTU
    local current_mtu route_mtu target_mtu
    current_mtu=$(ip link show "$iface" 2>/dev/null | grep -ioE 'mtu [0-9]+' | awk '{print $2}')
    route_mtu=$(ip route get 1.1.1.1 2>/dev/null | grep -ioE 'mtu [0-9]+' | awk '{print $2}')
    
    target_mtu=1420 # 默认云厂商安全下限
    
    if [[ -n "$route_mtu" && "$route_mtu" -lt 1500 ]]; then
        target_mtu="$route_mtu"
    fi

    say "当前网卡 $iface MTU: ${current_mtu:-未知}, 建议 MTU: $target_mtu"

    # 1. 修复 MTU
    if [[ "$current_mtu" != "$target_mtu" && -n "$current_mtu" ]]; then
        warn "检测到潜在的 MTU 黑洞风险，正在自动修复 (调整网卡 MTU 为 $target_mtu)..."
        ip link set dev "$iface" mtu "$target_mtu" 2>/dev/null
        
        # 针对 systemd-networkd 环境进行永久化写入
        if [[ -d /etc/systemd/network ]]; then
            local net_file
            net_file=$(grep -rl "Name=$iface" /etc/systemd/network/ 2>/dev/null | head -n 1)
            if [[ -n "$net_file" ]]; then
                if grep -q '^MTUBytes=' "$net_file"; then
                    sed -i "s/^MTUBytes=.*/MTUBytes=$target_mtu/" "$net_file"
                else
                    sed -i "/\[Link\]/a MTUBytes=$target_mtu" "$net_file"
                fi
                systemctl restart systemd-networkd 2>/dev/null
            fi
        fi
        ok "网卡 $iface MTU 已调整为 $target_mtu"
    fi

    # 2. 添加 TCP MSS Clamping 保险丝 (无论 MTU 是否修改都加上，防止多层套娃导致的包过大)
    say "正在应用 TCP MSS Clamping 规则 (彻底根治伪连卡死)..."
    if command -v iptables >/dev/null 2>&1; then
        # OUTPUT 链 (本机发出的流量)
        if ! iptables -t mangle -C OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
            iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
        fi
        # FORWARD 链 (转发的流量)
        if ! iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
            iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
        fi
        
        # 尝试保存 iptables 规则使其持久化
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1
        elif command -v iptables-save >/dev/null 2>&1 && [[ -d /etc/iptables ]]; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null
        fi
        ok "TCP MSS Clamp 规则已生效。"
    else
        warn "未找到 iptables，跳过 MSS 修复。"
    fi
}


# --- System Check & Fix Logic from original script (Simplified integration) ---
system_check() {
  local issues=0
  if command -v xray >/dev/null 2>&1; then ok "xray 已安装"; else err "xray 未安装"; issues=1; fi
  if ! sync_xray_config >/dev/null 2>&1; then err "Xray 配置同步/校验失败"; issues=1; else ok "Xray 配置可用"; fi
  
  # --- 新增 MTU 黑洞检测 ---
  local iface current_mtu route_mtu
  iface=$(ip -4 route ls 2>/dev/null | awk '/^default/ {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')
  if [[ -n "$iface" ]]; then
      current_mtu=$(ip link show "$iface" 2>/dev/null | grep -ioE 'mtu [0-9]+' | awk '{print $2}')
      route_mtu=$(ip route get 1.1.1.1 2>/dev/null | grep -ioE 'mtu [0-9]+' | awk '{print $2}')
      
      if [[ -n "$route_mtu" && "$route_mtu" -lt 1500 && "$current_mtu" != "$route_mtu" ]]; then
          err "检测到网卡 $iface 存在 MTU 不匹配 (当前:$current_mtu -> 建议:$route_mtu)，易导致节点有延迟但不通"
          issues=1
      else
          ok "网络 MTU 状态良好"
      fi
  fi
  
  return "$issues"
}

fix_errors() {
  ensure_runtime_deps
  install_xray_if_needed
  install_systemd_service
  
  # --- 新增触发自动修复 MTU 和 TCP MSS ---
  auto_fix_mtu_mss
  
  # Hysteria 修复逻辑保留原脚本
}

# ============= 节点添加核心逻辑 (前缀记忆增强版) =============
add_node() {
    # 1. 环境预检与时间同步
    ensure_runtime_deps
    auto_sync_time 

    while true; do
        echo -e "\n${C_CYAN}>>> 添加节点 (智能自动化版)${C_RESET}"
        say "1) SOCKS5"
        say "2) VLESS-REALITY"
        say "3) Hysteria2"
        say "4) CF Tunnel 隧道"
        say "5) Shadowsocks (SS)"
        say "6) TUIC v5 ${C_YELLOW}(内核加速)${C_RESET}"
        say "7) VLESS-ENC ${C_YELLOW}(原生加密)${C_RESET}"
        say "0) 返回主菜单"
        safe_read proto "输入协议编号 [1-7]: "
        proto=${proto:-2} 
        [[ "$proto" == "0" ]] && return
        [[ "$proto" =~ ^[1-7]$ ]] && break
        warn "无效输入，请重新选择。"
    done

    # --- 2. 自动化命名逻辑 (持久化记忆版) ---
    # 从文件读取上次保存的前缀，如果没有则默认为 node
    local PREF_CACHE="/etc/xray/prefix.txt"
    local last_pref; last_pref=$(cat "$PREF_CACHE" 2>/dev/null || echo "node")

    # 如果在本次脚本运行中已经设置过 SESSION_PREFIX，则不再询问
    if [[ -z "${SESSION_PREFIX:-}" ]]; then
        echo -e "\n${C_YELLOW}➜ 节点命名设置${C_RESET}"
        read -rp " 请输入自定义前缀 (当前默认: $last_pref): " input_prefix
        SESSION_PREFIX=${input_prefix:-$last_pref}
        # 保存到本地文件，下次运行脚本也能记住
        echo "$SESSION_PREFIX" > "$PREF_CACHE"
    fi
    
    local custom_prefix="$SESSION_PREFIX"
    local zh_country; zh_country=$(get_country_name_zh)
    local letter; letter=$(get_node_letter_suffix "$custom_prefix" "$zh_country")
    local tag="${custom_prefix}-${zh_country}${letter}"
    
    say "自动生成节点名: ${C_GREEN}${tag}${C_RESET}"

    # --- 3. 快捷跳转协议 (Hy2 / Argo / TUIC) ---
    if [[ "$proto" == "3" ]]; then add_hysteria2_node; return; fi
    if [[ "$proto" == "4" ]]; then argo_menu_wrapper; return; fi
    if [[ "$proto" == "6" ]]; then
        read -rp "请输入 TUIC 端口 (回车随机): " input_port
        [[ -z "$input_port" ]] && input_port=$(shuf -i 20000-60000 -n 1)
        call_233boy_builder "$tag" "$input_port"
        return
    fi

    # --- 4. 获取公网入口 IP ---
    local PUBLIC_HOST
    PUBLIC_HOST="$(head -n 1 /etc/xray/public_host 2>/dev/null | tr -d '\r\n ')"
    [[ -z "$PUBLIC_HOST" ]] && PUBLIC_HOST=$(get_public_ipv4_ensure)

    # --- 5) SOCKS5 逻辑 ---
    if [[ "$proto" == "1" ]]; then
        local port; port=$(get_random_allowed_port "tcp")
        read -rp "端口 (默认 $port, 输入0返回): " input_p
        [[ "$input_p" == "0" ]] && return
        port=${input_p:-$port}
        read -rp "用户名 (默认 user): " user; user=${user:-user}
        read -rp "密码 (默认 pass123): " pass; pass=${pass:-pass123}

        safe_json_edit "$CONFIG" \
          '.inbounds += [{"type":"socks","tag":$tag,"listen":"::","listen_port":($port|tonumber),"users":[{"username":$user,"password":$pass}]}]' \
          --arg port "$port" --arg user "$user" --arg pass "$pass" --arg tag "$tag"
        
        restart_xray "main_only"
        local creds=$(printf "%s:%s" "$user" "$pass" | base64 -w0)
        print_card "SOCKS5 成功" "$tag" "端口: $port" "socks://${creds}@${PUBLIC_HOST}:${port}#${tag}"
    fi

    # --- 5) Shadowsocks 逻辑 ---
    if [[ "$proto" == "5" ]]; then
        local port; port=$(get_random_allowed_port "tcp")
        read -rp "端口 (默认 $port, 输入0返回): " input_p
        [[ "$input_p" == "0" ]] && return
        port=${input_p:-$port}
        
        local method="aes-256-gcm"
        local def_pass; def_pass=$(openssl rand -base64 16 | tr -d '=+/' | cut -c1-16)
        read -rp "密码 (默认随机): " pass; pass=${pass:-$def_pass}

        safe_json_edit "$CONFIG" \
          '.inbounds += [{"type":"shadowsocks","tag":$tag,"listen":"::","listen_port":($port|tonumber),"method":$method,"password":$pass}]' \
          --arg port "$port" --arg method "$method" --arg pass "$pass" --arg tag "$tag"
        
        safe_json_edit "$META" '. + {($tag): {type:"shadowsocks", port:$port, method:$method, password:$pass}}' \
           --arg tag "$tag" --arg port "$port" --arg method "$method" --arg pass "$pass"

        restart_xray "main_only"
        local userinfo="${method}:${pass}"
        local b64_creds=$(printf "%s" "$userinfo" | base64 -w0)
        print_card "Shadowsocks 成功" "$tag" "端口: $port" "ss://${b64_creds}@${PUBLIC_HOST}:${port}#${tag}"
    fi

    # --- 2) VLESS-REALITY 逻辑 ---
    if [[ "$proto" == "2" ]]; then
        local port uuid server_name key_pair private_key public_key short_id
        while true; do
           safe_read port "请输入端口号 (留空随机, 输入0返回): "
           [[ "$port" == "0" ]] && return
           [[ -z "$port" ]] && port=$(get_random_allowed_port "tcp")
           check_nat_allow "$port" "tcp" && break || warn "端口 $port 不符合 NAT 限制"
        done

        local def_sni="www.microsoft.com"
        [[ "$zh_country" == "美国" ]] && def_sni="www.microsoft.com"
        [[ "$zh_country" == "香港" ]] && def_sni="www.hkex.com.hk"
        [[ "$zh_country" == "日本" ]] && def_sni="www.nintendo.co.jp"

        read -rp "伪装域名 (默认 $def_sni, 输入0返回): " input_sni
        [[ "$input_sni" == "0" ]] && return
        server_name="${input_sni:-$def_sni}"
        
        uuid=$(uuidgen)
        local xray_cmd=$(_xray_bin)
        extract_kv() { grep -iE "$1" | awk -F':' '{print $2}' | tr -d '[:space:]'; }
        key_pair=$($xray_cmd x25519 2>/dev/null)
        private_key=$(echo "$key_pair" | extract_kv 'private')
        public_key=$(echo "$key_pair" | extract_kv 'public|password')
        [[ -z "$public_key" ]] && public_key=$($xray_cmd x25519 -i "$private_key" 2>/dev/null | extract_kv 'public|password')
        short_id=$(openssl rand -hex 4)

        safe_json_edit "$CONFIG" \
           '.inbounds += [{"type": "vless","tag": $tag,"listen": "0.0.0.0","listen_port": ($port | tonumber),"users": [{ "uuid": $uuid, "flow": "xtls-rprx-vision" }],"tls": {"enabled": true,"server_name": $server,"reality": {"enabled": true,"handshake": { "server": $server, "server_port": 443 },"private_key": $prikey,"short_id": [ $sid ]}}}]' \
           --arg port "$port" --arg uuid "$uuid" --arg prikey "$private_key" --arg sid "$short_id" --arg server "$server_name" --arg tag "$tag"

        safe_json_edit "$META" '. + {($tag): {pbk:$pbk, sid:$sid, sni:$sni, port:$port, fp:"chrome"}}' \
           --arg tag "$tag" --arg pbk "$public_key" --arg sid "$short_id" --arg sni "$server_name" --arg port "$port"

        restart_xray "main_only"
        local host_link_disp=$(format_host_for_link "$PUBLIC_HOST")
        local link="vless://${uuid}@${host_link_disp}:${port}?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&pbk=${public_key}&sid=${short_id}&sni=${server_name}&fp=chrome#${tag}"
        print_card "VLESS-REALITY 成功" "$tag" "端口: $port\nSNI: $server_name" "$link"
    fi

    # --- 7) VLESS-ENC 逻辑 ---
    if [[ "$proto" == "7" ]]; then
        local port uuid server_seed client_seed
        while true; do
           safe_read port "请输入端口号 (留空随机, 输入0返回): "
           [[ "$port" == "0" ]] && return
           [[ -z "$port" ]] && port=$(get_random_allowed_port "tcp")
           check_nat_allow "$port" "tcp" && break || warn "端口 $port 不符合 NAT 限制"
        done

        uuid=$(uuidgen)
        local xray_cmd=$(_xray_bin)
        say "正在生成 VLESS-ENC 原生密钥对..."

        get_vless_seed_internal() {
            local raw; raw=$($1 vlessenc 2>&1)
            local s_seed c_seed
            s_seed=$(echo "$raw" | grep -i 'decryption' | grep -ioE '(mlkem768|x25519)[a-zA-Z0-9_.-]+' | head -n 1)
            c_seed=$(echo "$raw" | grep -i 'encryption' | grep -v -i 'decryption' | grep -ioE '(mlkem768|x25519)[a-zA-Z0-9_.-]+' | head -n 1)
            [[ -n "$s_seed" && -n "$c_seed" ]] && echo "$s_seed $c_seed" || echo ""
        }

        local seeds; seeds=$(get_vless_seed_internal "$xray_cmd")
        if [[ -z "$seeds" ]]; then
            install_xray_if_needed --force
            xray_cmd="/usr/local/bin/xray"
            seeds=$(get_vless_seed_internal "$xray_cmd")
        fi
        server_seed=$(echo "$seeds" | awk '{print $1}')
        client_seed=$(echo "$seeds" | awk '{print $2}')

        safe_json_edit "$CONFIG" \
           '.inbounds += [{"type": "vless","tag": $tag,"listen": "0.0.0.0","listen_port": ($port | tonumber),"users": [{ "uuid": $uuid, "flow": "" }],"server_seed": $s_seed, "client_seed": $c_seed}]' \
           --arg port "$port" --arg uuid "$uuid" --arg s_seed "$server_seed" --arg c_seed "$client_seed" --arg tag "$tag"

        safe_json_edit "$META" '. + {($tag): {type:"vless", port:$port, server_seed:$s_seed, client_seed:$c_seed}}' \
           --arg tag "$tag" --arg port "$port" --arg s_seed "$server_seed" --arg c_seed "$client_seed"

        restart_xray "main_only"
        local link="vless://${uuid}@${PUBLIC_HOST}:${port}?encryption=${client_seed}&type=tcp&security=none#${tag}"
        print_card "VLESS-ENC 成功" "$tag" "端口: $port" "$link"
    fi
}


# --- Hysteria 2 Logic (Keep Original) ---
add_hysteria2_node() {
  ensure_runtime_deps
  GLOBAL_IPV4=$(get_public_ipv4_ensure)

  local PUBLIC_HOST
  PUBLIC_HOST="$(get_public_ipv4_ensure)"
  
  read -rp "Hysteria2 端口 (留空随机): " input_port
  local port=${input_port:-$(get_random_allowed_port "udp")}
  [[ "$port" == "NO_PORT" ]] && { err "无可用端口"; return; }
  
  if ! check_nat_allow "$port" "udp"; then warn "不符合 NAT 规则"; return; fi
  if port_status "$port" | grep -q 0; then warn "端口被占用"; return; fi

  # 安装 Hy2 核心
  if ! command -v hysteria >/dev/null 2>&1; then
      local arch=$(uname -m); [[ "$arch" == "x86_64" ]] && arch="amd64" || arch="arm64"
      curl -sSL "https://github.com/apernet/hysteria/releases/download/app/v2.6.2/hysteria-linux-${arch}" -o /usr/local/bin/hysteria
      chmod +x /usr/local/bin/hysteria
  fi

  mkdir -p /etc/hysteria2
  local cert="/etc/hysteria2/${port}.crt"
  local key="/etc/hysteria2/${port}.key"
  local sni="www.bing.com"
  local auth=$(openssl rand -base64 16 | tr -d '=+/' | cut -c1-16)

  # 生成自签名证书
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout "$key" -out "$cert" -days 3650 -subj "/CN=$sni" >/dev/null 2>&1

  # --- 关键修改：移除 obfs 并改用标准缩进格式 ---
  cat > "/etc/hysteria2/${port}.yaml" <<EOF
listen: :${port}
tls:
  cert: ${cert}
  key: ${key}
auth:
  type: password
  password: ${auth}
masquerade:
  type: proxy
  proxy:
    url: https://${sni}/
    rewriteHost: true
    insecure: true
EOF

  # 服务设置
  local svc="hysteria2-${port}"
  if [[ "$(detect_init_system)" == "systemd" ]]; then
      cat > "/etc/systemd/system/${svc}.service" <<EOF
[Unit]
Description=Hy2-${port}
After=network.target
[Service]
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria2/${port}.yaml
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload; systemctl enable --now "$svc"
  else
      # OpenRC / Fallback logic
      nohup /usr/local/bin/hysteria server -c "/etc/hysteria2/${port}.yaml" >/dev/null 2>&1 &
  fi

  # 更新元数据 (移除 obfs 字段)
  local tag="Hy2-${port}"
  local tmpm=$(mktemp)
  jq --arg tag "$tag" --arg port "$port" --arg sni "$sni" --arg auth "$auth" \
    '. + {($tag): {type:"hysteria2", port:$port, sni:$sni, auth:$auth}}' "$META" >"$tmpm" && mv "$tmpm" "$META"

  # 分享链接 (移除 obfs 相关的查询参数)
  local link="hysteria2://${auth}@${PUBLIC_HOST}:${port}?sni=${sni}&insecure=1#${tag}"
  print_card "Hysteria2 成功 (已移除混淆)" "$tag" "端口: $port" "$link"
  read -rp "按回车继续..." _
}


# --- 深度封装 233 动力引擎 (全静默模式) ---
call_233boy_builder() {
    local tag="$1"
    local port="$2"
    local uuid=$(uuidgen)
    
    # 1. 环境初始化 (屏蔽所有 233boy 脚本的安装输出)
    if ! command -v sb >/dev/null 2>&1; then
        say "正在执行内核初始化 (静默模式)..."
        # 使用 -s 屏蔽下载，2>/dev/null 屏蔽所有文字输出
        curl -sL https://github.com/233boy/sing-box/raw/main/install.sh | bash >/dev/null 2>&1
    fi

    # 2. 调用核心进行后台构建 (彻底屏蔽 UI 和字眼)
    # 利用 233 脚本的非交互命令行功能处理防火墙和优化
    say "正在优化系统防火墙并注入内核补丁..."
    sb add tuic "$port" "$uuid" >/dev/null 2>&1

    # 3. 获取 IP 并生成你脚本原生风格的 UI 展示
    local PUBLIC_HOST=$(get_public_ipv4_ensure)
    
    # 构造动力链接 (包含 bbr、h3 和跳过证书验证参数)
    local link="tuic://${uuid}:${uuid}@${PUBLIC_HOST}:${port}?alpn=h3&allow_insecure=1&congestion_control=bbr#${tag}"
    
    echo -e "\n${C_GREEN}✔ 节点已通过内核增强引擎构建完成！${C_RESET}"
    
    # 调用你脚本自带的卡片 UI
    print_card "TUIC v5 部署成功" "$tag" "端口: $port\nUUID: $uuid\n优化: BBR / H3 链路加速" "$link"
    
    warn "管理提示：如需维护此节点，请在终端输入指令: sb"
    read -rp "按回车返回主菜单..." _
}


# --- Cloudflare 隧道管理逻辑封装 ---
argo_menu_wrapper() {
    # --- 1. 依赖与环境准备 ---
    ensure_argo_deps() {
        mkdir -p "/etc/xray/argo_users" "/root/agsbx"
        local arch="amd64"
        [[ "$(uname -m)" == "aarch64" || "$(uname -m)" == "arm64" ]] && arch="arm64"
        if [[ ! -f "/root/agsbx/cloudflared" ]]; then
             say "正在下载 Cloudflare 核心..."
             curl -L -o /root/agsbx/cloudflared "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}"
             chmod +x /root/agsbx/cloudflared
        fi
        if [[ ! -f "/root/agsbx/xray" ]]; then
             cp /usr/local/bin/xray /root/agsbx/xray 2>/dev/null || {
                local z="https://github.com/XTLS/Xray-core/releases/download/v1.8.11/Xray-linux-64.zip"
                [[ "$arch" == "arm64" ]] && z="https://github.com/XTLS/Xray-core/releases/download/v1.8.11/Xray-linux-arm64-v8a.zip"
                wget -qO /root/agsbx/x.zip "$z" && unzip -o /root/agsbx/x.zip -d /root/agsbx "xray" && rm /root/agsbx/x.zip
             }
             chmod +x /root/agsbx/xray
        fi
    }

    # --- 增强版：重启并同步出口配置 ---
    restart_argo_services() {
    say "正在重新同步固定隧道出口并重启 (临时隧道保持不动)..."
    
    # 1. 获取当前最新的全局出口偏好
    local pref ds lock_ip
    IFS=$'\t' read -r pref ds lock_ip < <(_get_global_egress_pref_and_lock)

    local outbound_json='{ "protocol": "freedom", "settings": { "domainStrategy": "'$ds'" } }'
    [[ -n "$lock_ip" ]] && outbound_json='{ "protocol": "freedom", "settings": { "domainStrategy": "'$ds'" }, "sendThrough": "'$lock_ip'" }'

    # 2. 精准清理：只清理固定隧道进程，跳过带 _temp 后缀的临时进程
    # 只针对带 token 的 cloudflared 和 argo_users 目录下的 xray 进行清理
    pkill -f "cloudflared.*--token" >/dev/null 2>&1
    pkill -f "/root/agsbx/xray.*argo_users" >/dev/null 2>&1
    sleep 0.5

    # 3. [已彻底删除] 临时隧道重启逻辑
    # 此处不再操作 /root/agsbx/temp_node/，以确保临时隧道域名不断开

    # 4. 重新重构所有固定隧道配置并拉起
    local tags; tags=$(jq -r 'to_entries[] | select(.value.type=="argo" and .value.token!=null) | .key' "$META" 2>/dev/null)
    for t in $tags; do
        local p; p=$(jq -r --arg t "$t" '.[$t].port' "$META")
        local tk; tk=$(jq -r --arg t "$t" '.[$t].token' "$META")
        local f_cfg="/etc/xray/argo_users/${p}.json"
        
        if [[ -f "$f_cfg" ]]; then
            # 更新固定隧道的出口绑定
            local f_tmp; f_tmp=$(mktemp)
            jq --argjson out "[${outbound_json}]" '.outbounds = $out' "$f_cfg" > "$f_tmp" && mv "$f_tmp" "$f_cfg"
            
            nohup /root/agsbx/xray run -c "$f_cfg" >/dev/null 2>&1 &
            nohup /root/agsbx/cloudflared tunnel --no-autoupdate --protocol http2 run --token "$tk" >/dev/null 2>&1 &
            say "固定隧道 [$t] 已按新出口重启"
        fi
    done
    ok "固定隧道已同步重启，临时隧道保持运行 (域名未变)"
    read -rp "按回车继续..." _
}
    # --- 3. 固定隧道 (支持自定义端口) ---
    add_argo_user() {
        ensure_argo_deps
        read -rp "请输入 Cloudflare Tunnel Token: " token
        [[ -z "$token" ]] && return
        read -rp "请输入绑定的域名: " domain
        [[ -z "$domain" ]] && return

        # 新增：自定义端口逻辑
        read -rp "请输入本地监听端口 (留空则自动分配): " input_port
        local port=${input_port:-$(get_random_allowed_port "tcp")}
        
        # 简单检查端口占用
        if lsof -i:"$port" >/dev/null 2>&1; then
            err "端口 $port 已被占用，请更换后重试。"
            return
        fi

        local uuid=$(uuidgen); local path="/vm-${port}"; local tag="Argo-${port}"
        mkdir -p "/etc/xray/argo_users"
        local pref ds lock_ip
        IFS=$'	' read -r pref ds lock_ip < <(_get_global_egress_pref_and_lock)
        local outbound_json='{ "protocol": "freedom", "settings": { "domainStrategy": "'$ds'" } }'
        [[ -n "$lock_ip" ]] && outbound_json='{ "protocol": "freedom", "settings": { "domainStrategy": "'$ds'" }, "sendThrough": "'$lock_ip'" }'

        cat > "/etc/xray/argo_users/${port}.json" <<EOF
{ "inbounds": [{ "port": ${port}, "listen": "127.0.0.1", "protocol": "vmess", "settings": { "clients": [{ "id": "${uuid}" }] }, "streamSettings": { "network": "ws", "wsSettings": { "path": "${path}" } } }], "outbounds": [ ${outbound_json} ] }
EOF
        nohup /root/agsbx/xray run -c "/etc/xray/argo_users/${port}.json" >/dev/null 2>&1 &
        nohup /root/agsbx/cloudflared tunnel --no-autoupdate --protocol http2 run --token "$token" >/dev/null 2>&1 &
        
        local vm_json='{"v":"2","ps":"'$tag'","add":"'$domain'","port":"443","id":"'$uuid'","net":"ws","path":"'$path'","tls":"tls","sni":"'$domain'","host":"'$domain'"}'
        local link="vmess://$(echo -n "$vm_json" | base64 -w 0)"
        
        # 存入 Meta，包含 Token 和 Port
        local tmp=$(mktemp)
        jq --arg t "$tag" --arg p "$port" --arg d "$domain" --arg raw "$link" --arg tk "$token" \
          '. + {($t): {type:"argo", subtype:"fixed", port:$p, domain:$d, raw:$raw, token:$tk}}' "$META" >"$tmp" && mv "$tmp" "$META"
        print_card "固定隧道配置成功" "$tag" "域名: $domain\n端口: $port" "$link"
    }

    # --- 临时隧道逻辑 (保持不变) ---
    temp_tunnel_logic() {
        ensure_argo_deps
        say "启动临时隧道..."
        local ARGO_DIR="/root/agsbx"
        mkdir -p "$ARGO_DIR/temp_node"
        pkill -f "cloudflared_temp"; pkill -f "xray_temp"
        cp "$ARGO_DIR/xray" "$ARGO_DIR/temp_node/xray_temp"
        cp "$ARGO_DIR/cloudflared" "$ARGO_DIR/temp_node/cloudflared_temp"
        
        local port=$((RANDOM % 10000 + 40000)); local uuid=$(uuidgen); local path="/$uuid"
        local pref ds lock_ip
        IFS=$'	' read -r pref ds lock_ip < <(_get_global_egress_pref_and_lock)
        local outbound_json='{ "protocol": "freedom", "settings": { "domainStrategy": "'$ds'" } }'
        [[ -n "$lock_ip" ]] && outbound_json='{ "protocol": "freedom", "settings": { "domainStrategy": "'$ds'" }, "sendThrough": "'$lock_ip'" }'

        cat > "$ARGO_DIR/temp_node/config.json" <<EOF
{ "inbounds": [{ "port": ${port}, "listen": "127.0.0.1", "protocol": "vmess", "settings": { "clients": [{ "id": "${uuid}" }] }, "streamSettings": { "network": "ws", "wsSettings": { "path": "${path}" } } }], "outbounds": [ ${outbound_json} ] }
EOF
        nohup "$ARGO_DIR/temp_node/xray_temp" run -c "$ARGO_DIR/temp_node/config.json" >/dev/null 2>&1 &
        nohup "$ARGO_DIR/temp_node/cloudflared_temp" tunnel --url http://127.0.0.1:$port --no-autoupdate > "$ARGO_DIR/temp_node/cf.log" 2>&1 &
        
        say "正在获取域名 (5s)..."
        sleep 5
        local url=$(grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$ARGO_DIR/temp_node/cf.log" | head -n1)
        [[ -z "$url" ]] && { err "获取失败"; return; }
        local domain=${url#https://}; local tag="Argo-Temp"
        local vm_json='{"v":"2","ps":"'$tag'","add":"'$domain'","port":"443","id":"'$uuid'","net":"ws","path":"'$path'","tls":"tls","sni":"'$domain'","host":"'$domain'"}'
        local link="vmess://$(echo -n "$vm_json" | base64 -w 0)"
        local tmp=$(mktemp)
        jq --arg t "$tag" --arg raw "$link" '. + {($t): {type:"argo", subtype:"temp", raw:$raw}}' "$META" >"$tmp" && mv "$tmp" "$META"
        print_card "临时隧道成功" "$tag" "域名: $domain" "$link"
        read -rp "按回车继续..." _
    }

    uninstall_argo_all() {
        pkill -f "/root/agsbx"
        rm -rf /root/agsbx
        local tmp=$(mktemp)
        jq 'to_entries | map(select(.value.type != "argo")) | from_entries' "$META" > "$tmp" && mv "$tmp" "$META"
        ok "Argo 数据已清理"
    }

    while true; do
      echo -e "\n${C_CYAN}====== Cloudflare 隧道管理 ======${C_RESET}"
      say "1) 临时隧道"
      say "2) 固定隧道 (Token)"
      say "3) 重启所有隧道服务 ${C_GREEN}(新增)${C_RESET}"
      say "4) 卸载/清理"
      say "0) 返回"
      safe_read ac "选择: "
      case "$ac" in
          1) temp_tunnel_logic ;;
          2) add_argo_user ;;
          3) restart_argo_services ;;
          4) uninstall_argo_all ;;      0) return ;;
      esac
    done
}

view_nodes_menu() {
  local V4_ADDR=$(get_public_ipv4_ensure)
  local V6_ADDR=$(get_public_ipv6_ensure)
  local global_pref="v4"
  [[ -f "/etc/xray/ip_pref" ]] && global_pref=$(cat /etc/xray/ip_pref)
  
  # 预先清理可能影响 read 的变量
  NODE_TAGS=()
  NODE_TYPES=()
  NODE_PORTS=()
  NODE_IPS=()
  NODE_V_DISP=()
  local idx=1

  echo -e "\n${C_CYAN}=== 节点列表预览 (极致修复版) ===${C_RESET}"
  echo -e "${C_GRAY}————————————————————————————————————————————————————————————————————————————————${C_RESET}"
  printf " ${C_YELLOW}%-4s | %-20s | %-15s | %-8s | %-15s${C_RESET}\n" "序号" "节点标签" "协议/状态" "端口" "出口 IP (版本)"
  echo -e "${C_GRAY}————————————————————————————————————————————————————————————————————————————————${C_RESET}"

  # 🚀 增强版 jq 解析：显式处理空值，防止字段缩水导致 read 错位
  local parsed_data
  parsed_data=$(jq -r -n --slurpfile cfg "$CONFIG" --slurpfile meta "$META" '
    ($cfg[0].inbounds // []) as $inbounds |
    ($meta[0] // {}) as $m |
    ( ($inbounds | map(select(.tag != null) | .tag)) + ($m | keys) | unique )[] as $tag |
    ($inbounds | map(select(.tag == $tag)) | .[0] // {}) as $inb |
    ($m[$tag] // {}) as $mt |
    [
      $tag,
      ($mt.type // $inb.type // "UNKNOWN"),
      ($inb.port // $inb.listen_port // $mt.port // "0"),
      ($mt.fixed_ip // "NONE"),
      ($mt.ip_version // "NONE"),
      ($mt.server_seed // "NONE"),
      ($mt.pbk // "NONE")
    ] | @tsv
  ' 2>/dev/null)

  # 使用 IFS 严格分隔
  while IFS=$'\t' read -r tag type port fixed_ip node_v is_enc has_pbk; do
      [[ -z "$tag" || "$tag" == "null" ]] && continue
      
      # 1. 修正协议显示逻辑
      local check_type="${type,,}"
      local display_type="${type^^}"
      
      if [[ "$check_type" == "vless" ]]; then
          if [[ "$is_enc" != "NONE" && -n "$is_enc" ]]; then
              display_type="VLESS-ENC"
          elif [[ "$has_pbk" != "NONE" && -n "$has_pbk" ]]; then
              display_type="VLESS-REALITY"
          else
              display_type="VLESS"
          fi
      elif [[ "$check_type" == "argo" ]]; then
          [[ "$fixed_ip" != "NONE" ]] && display_type="ARGO-FIXED" || display_type="ARGO-TEMP"
      fi

      # 2. 修正 IP 显示逻辑 (防止密钥混入)
      local use_v="${node_v}"
      [[ "$use_v" == "NONE" || -z "$use_v" ]] && use_v="$global_pref"
      
      local CURRENT_IP="$V4_ADDR"
      [[ "$use_v" == "v6" && -n "$V6_ADDR" ]] && CURRENT_IP="$V6_ADDR"
      
      # 如果有固定 IP 且它看起来不像密钥（长度小于 50），则使用它
      if [[ "$fixed_ip" != "NONE" && -n "$fixed_ip" ]]; then
          if ((${#fixed_ip} < 50)); then
              CURRENT_IP="$fixed_ip"
          fi
      fi

      NODE_TAGS+=("$tag")
      NODE_TYPES+=("$type")
      NODE_PORTS+=("$port")
      NODE_IPS+=("$CURRENT_IP")
      NODE_V_DISP+=("$use_v")

      local line_color="$C_YELLOW"
      [[ "$display_type" =~ "ARGO" || "$display_type" == "HYSTERIA2" ]] && line_color="$C_PURPLE"
      
      local short_tag="${tag:0:20}"
      # 最终打印：如果 IP 依然过长，强行截断显示或显示“检测中”
      local ip_disp="${CURRENT_IP}"
      ((${#ip_disp} > 40)) && ip_disp="IP 检测异常"

      printf " ${C_GREEN}[%2d]${C_RESET} | ${line_color}%-20s${C_RESET} | %-15s | %-8s | %-15s\n" \
              "$idx" "$short_tag" "$display_type" "$port" "${ip_disp} (${use_v})"
      
      ((idx++))
  done <<< "$parsed_data"

  echo -e "${C_GRAY}————————————————————————————————————————————————————————————————————————————————${C_RESET}"
  echo -e " ${C_GREEN}[0]${C_RESET} 返回主菜单"

  read -rp " 请选择要查看详情的节点序号: " v_choice
  [[ -z "$v_choice" || "$v_choice" == "0" ]] && return
  
  local sel_idx=$((v_choice - 1))
  local target_tag="${NODE_TAGS[$sel_idx]}"
  local t_type="${NODE_TYPES[$sel_idx]}"
  local t_ip="${NODE_IPS[$sel_idx]}"
  local t_port="${NODE_PORTS[$sel_idx]}"
  
  [[ -z "$target_tag" ]] && { echo -e "${C_RED}错误：无效序号${C_RESET}"; sleep 1; return; }

  # --- 详情查看部分保持不变 (这里保留 get_ip_country 没关系，因为点进详情只查一个 IP) ---
  local final_link=""
  
  if [[ "${t_type,,}" == "shadowsocks" ]]; then
      local method=$(jq -r --arg t "$target_tag" '.inbounds[] | select(.tag==$t) | .method // "aes-256-gcm"' "$CONFIG" 2>/dev/null)
      local pass=$(jq -r --arg t "$target_tag" '.inbounds[] | select(.tag==$t) | .password // ""' "$CONFIG" 2>/dev/null)
      local userinfo="${method}:${pass}"
      local b64_creds=$(printf "%s" "$userinfo" | base64 -w0)
      final_link="ss://${b64_creds}@${t_ip}:${t_port}#${target_tag}"
      print_card "Shadowsocks 详情" "$target_tag" "地址: ${t_ip}\n端口: ${t_port}\n加密: ${method}\n密码: ${pass}" "$final_link"

  elif [[ "${t_type,,}" == "socks" ]]; then
      local user=$(jq -r --arg t "$target_tag" '.inbounds[] | select(.tag==$t) | .users[0].username // "user"' "$CONFIG" 2>/dev/null)
      local pass=$(jq -r --arg t "$target_tag" '.inbounds[] | select(.tag==$t) | .users[0].password // "pass"' "$CONFIG" 2>/dev/null)
      final_link="socks://$(printf "%s:%s" "$user" "$pass" | base64 -w0)@${t_ip}:${t_port}#${target_tag}"
      print_card "SOCKS5 详情" "$target_tag" "地址: ${t_ip}\n端口: ${t_port}\n用户: ${user}\n密码: ${pass}" "$final_link"

  elif [[ "${t_type,,}" == "vless" ]]; then
      # 核心修复：必须先从文件读取 meta 数据
      local meta_json=$(cat "$META" 2>/dev/null || echo "{}")
      local uuid=$(jq -r --arg t "$target_tag" '.inbounds[] | select(.tag==$t) | .users[0].uuid' "$CONFIG" 2>/dev/null)
      local c_seed=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].client_seed // empty')
      
      # 格式化主机地址 (IPv6 自动加方括号)
      local host_disp=$(format_host_for_link "$t_ip")

      if [[ -n "$c_seed" && "$c_seed" != "null" && "$c_seed" != "" ]]; then
          final_link="vless://${uuid}@${host_disp}:${t_port}?encryption=${c_seed}&type=tcp&security=none#${target_tag}"
          print_card "VLESS-ENC 详情" "$target_tag" "地址: ${t_ip}\n端口: ${t_port}\nUUID: ${uuid}\n客户端密钥: ${c_seed:0:15}..." "$final_link"
      else
          local pbk=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].pbk // empty')
          local sid=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].sid // empty')
          local sni=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].sni // "www.microsoft.com"')
          
          # 构造带方括号的 V6 链接
          final_link="vless://${uuid}@${host_disp}:${t_port}?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&pbk=${pbk}&sid=${sid}&sni=${sni}&fp=chrome#${target_tag}"
          print_card "VLESS-REALITY 详情" "$target_tag" "地址: ${t_ip}\n端口: ${t_port}\nUUID: ${uuid}\nSNI: ${sni}\nPublic Key: ${pbk}\nShort ID: ${sid}" "$final_link"
      fi

  elif [[ "${t_type,,}" == "hysteria2" ]]; then
      local auth=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].auth // empty')
      local sni=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].sni // "www.bing.com"')
      final_link="hysteria2://${auth}@${t_ip}:${t_port}?sni=${sni}&insecure=1#${target_tag}"
      print_card "Hysteria2 详情" "$target_tag" "地址: ${t_ip}\n端口: ${t_port}\n认证: ${auth}\nSNI: ${sni}" "$final_link"

  elif [[ "${t_type,,}" == "argo" ]]; then
      final_link=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].raw')
      print_card "Argo Tunnel 详情" "$target_tag" "出口类型: Cloudflare 隧道" "$final_link"

  elif [[ "${t_type,,}" == "vmess" ]]; then
      local uuid=$(jq -r --arg t "$target_tag" '.outbounds[] | select(.tag==$t) | .settings.vnext[0].users[0].id' "$CONFIG" 2>/dev/null)
      print_card "VMess 落地详情" "$target_tag" "此为落地出口节点，UUID: ${uuid}" "需配合分流规则使用"
  fi

  read -rp "按回车返回节点列表..." _
  view_nodes_menu
}

delete_node() {
  echo -e "\n${C_CYAN}=== 删除节点 (支持多选) ===${C_RESET}"
  echo -e "${C_GRAY}提示：输入多个序号可用空格或逗号分隔，如: 1 3 5 或 1,2,5${C_RESET}\n"

  # 1. 快速聚合所有标签 (使用单次 jq)
  local parsed_types
  parsed_types=$(jq -r -n --slurpfile cfg "$CONFIG" --slurpfile meta "$META" '
    ($cfg[0].inbounds // []) as $inbounds |
    ($meta[0] // {}) as $m |
    ( ($inbounds | map(select(.tag != null) | .tag)) + ($m | keys) | unique )[] as $tag |
    ($inbounds | map(select(.tag == $tag)) | .[0] // {}) as $inb |
    ($m[$tag] // {}) as $mt |
    [ $tag, ($mt.protocol // $mt.type // $inb.protocol // $inb.type // "未知") ] | @tsv
  ' 2>/dev/null)

  if [[ -z "$parsed_types" ]]; then
      warn "当前没有任何节点可删除。"
      read -rp "按回车返回..." _
      return
  fi

  local -a ALL_TAGS=()
  local i=0
  while IFS=$'\t' read -r tag type_info; do
      [[ -z "$tag" ]] && continue
      ALL_TAGS+=("$tag")
      i=$((i+1))
      echo -e " ${C_GREEN}[$i]${C_RESET} ${C_YELLOW}${tag}${C_RESET} ${C_GRAY}(${type_info})${C_RESET}"
  done <<< "$parsed_types"
  echo -e " ${C_RED}[00]${C_RESET} 删除全部节点"
  echo -e " ${C_GREEN}[0]${C_RESET} 取消返回"

  read -rp "请输入要删除的节点序号: " choice
  [[ "$choice" == "0" || -z "$choice" ]] && return

  # 2. 处理选中序号
  local -a selected_tags=()
  if [[ "$choice" == "00" ]]; then
      selected_tags=("${ALL_TAGS[@]}")
  else
      local clean_choice="${choice//,/ }"
      for idx in $clean_choice; do
          if [[ "$idx" =~ ^[0-9]+$ ]] && [ "$idx" -ge 1 ] && [ "$idx" -le "$i" ]; then
              selected_tags+=("${ALL_TAGS[$((idx-1))]}")
          fi
      done
  fi

  [[ ${#selected_tags[@]} -eq 0 ]] && return

  # 3. 确认预览
  echo -e "\n${C_RED}确认删除以下 ${#selected_tags[@]} 个节点？${C_RESET}"
  read -rp "输入 y 确认执行: " confirm
  [[ "$confirm" != "y" && "$confirm" != "Y" ]] && return

  say "正在执行批量清理..."

  # 🚀 优化 A：在循环内只做非 JSON 的系统操作 (服务停止/进程杀除)
  for target_tag in "${selected_tags[@]}"; do
      if [[ "$target_tag" =~ Hy2 ]]; then
          local p=$(echo "$target_tag" | grep -oE '[0-9]+')
          [[ -n "$p" ]] && systemctl disable --now "hysteria2-$p" 2>/dev/null && rm -f "/etc/systemd/system/hysteria2-$p.service"
      fi
      if [[ "$target_tag" =~ Argo ]]; then
          # 针对性杀掉该端口的 argo 进程，而不是 pkill 全部
          local ap=$(jq -r --arg t "$target_tag" '.[$t].port // empty' "$META" 2>/dev/null)
          [[ -n "$ap" ]] && pkill -f "/etc/xray/argo_users/${ap}.json" 2>/dev/null
      fi
  done

  # 🚀 优化 B：批量处理 JSON。把所有要删的标签转成一个 JSON 数组，一次性交给 jq。
  local tags_json
  tags_json=$(printf "%s\n" "${selected_tags[@]}" | jq -R . | jq -s -c .)

  # 一次性清理 CONFIG (包含 inbounds 和对应的路由规则)
  safe_json_edit "$CONFIG" '
    (.inbounds |= map(select(.tag as $t | $tags | index($t) == null))) |
    (.route.rules |= map(select(
      if (.inbound | type) == "array" then
        (.inbound | any(. as $in | $tags | index($in) != null)) | not
      else
        ($tags | index(.inbound) == null)
      end
    )))
  ' --argjson tags "$tags_json"

  # 一次性清理 META
  safe_json_edit "$META" 'with_entries(select(.key as $k | $tags | index($k) == null))' --argjson tags "$tags_json"

  # 🚀 优化 C：使用之前定义的 "main_only" 模式重启，不触碰 Argo 同步逻辑
  # 同时配合之前优化过的“轮询检测”版 restart_xray，速度提升 5 倍以上
  restart_xray "main_only"

  ok "已成功移除选中的 ${#selected_tags[@]} 个节点。"
  read -rp "按回车返回..." _
}

import_link_outbound() {
    local link="$1"
    local tag="IMP-$(date +%s)"
    local type="" server="" port="" user="" pass="" new_node=""
    
    say "正在启动专业级解析与内核预校验..."
    
    if [[ "$link" == ss://* ]]; then
        local main_part="${link#ss://}"
        local userinfo_b64="${main_part%%@*}"
        local server_info="${main_part#*@}"
        local decoded=$(printf "%s" "$userinfo_b64" | base64 -d 2>/dev/null | tr -d '\n\r')
        [[ -z "$decoded" ]] && { err "Base64 解码失败"; return 1; }
        local method="${decoded%%:*}"
        local password="${decoded#*:}"
        password=$(printf "%s" "$password" | tr -cd 'A-Za-z0-9+/=_:-')
        local server_port="${server_info%%[?#]*}"
        server="${server_port%%:*}"
        port="${server_port##*:}"
        port=$(echo "$port" | tr -cd '0-9')
        new_node=$(jq -n --arg t "$tag" --arg s "$server" --arg p "$port" --arg m "$method" --arg pw "$password" \
            '{type: "shadowsocks", tag: $t, server: $s, server_port: ($p|tonumber), method: $m, password: $pw}')
        type="ss"
    elif [[ "$link" == vless://* ]]; then
        local uuid=$(echo "$link" | cut -d'@' -f1 | sed 's/vless:\/\///')
        local server_port_raw=$(echo "$link" | cut -d'@' -f2 | cut -d'?' -f1)
        server="${server_port_raw%%:*}"
        port="${server_port_raw##*:}"
        port=$(echo "$port" | tr -cd '0-9')
        local qs=""
        [[ "$link" == *"?"* ]] && qs="${link#*\?}" && qs="${qs%%#*}"
        
        local flow="" sni="" pbk="" sid="" fp="" net="tcp" htype="none" enc=""
        if [[ -n "$qs" ]]; then
            IFS='&' read -r -a _pairs <<< "$qs"
            for kv in "${_pairs[@]}"; do
                local k="${kv%%=*}"
                local v="${kv#*=}"
                case "$k" in
                    flow) flow="$v" ;;
                    sni) sni="$v" ;;
                    pbk) pbk="$v" ;;
                    sid) sid="$v" ;;
                    fp) fp="$v" ;;
                    type) net="$v" ;;
                    headerType) htype="$v" ;;
                    encryption) enc="$v" ;;
                esac
            done
        fi
        
        local client_seed=""
        if [[ -n "$enc" && "$enc" != "none" ]]; then
            client_seed="$enc"
        fi

        new_node=$(jq -n --arg t "$tag" --arg s "$server" --arg p "$port" --arg u "$uuid" \
            --arg flow "$flow" --arg sni "$sni" --arg pbk "$pbk" --arg sid "$sid" --arg fp "$fp" \
            --arg net "$net" --arg htype "$htype" --arg c_seed "$client_seed" \
            '{type: "vless", tag: $t, server: $s, server_port: ($p|tonumber), uuid: $u, flow: $flow, client_seed: $c_seed, transport: { type: $net, header_type: $htype }, tls: { server_name: $sni, reality: { public_key: $pbk, short_id: (if $sid != "" then [$sid] else [] end) }, utls: { fingerprint: $fp } }}')
        type="vless"
    elif [[ "$link" == vmess://* ]]; then
        local b64_data="${link#vmess://}"
        local decoded=$(echo "$b64_data" | base64 -d 2>/dev/null)
        [[ -z "$decoded" ]] && { err "VMess Base64 解码失败"; return 1; }
        server=$(echo "$decoded" | jq -r '.add // empty')
        port=$(echo "$decoded" | jq -r '.port // empty')
        local uuid=$(echo "$decoded" | jq -r '.id // empty')
        local net=$(echo "$decoded" | jq -r '.net // "tcp"')
        local path=$(echo "$decoded" | jq -r '.path // ""')
        local host=$(echo "$decoded" | jq -r '.host // ""')
        local tls=$(echo "$decoded" | jq -r '.tls // "none"')
        local sni=$(echo "$decoded" | jq -r '.sni // ""')
        new_node=$(jq -n --arg t "$tag" --arg s "$server" --arg p "$port" --arg u "$uuid" --arg net "$net" --arg path "$path" --arg host "$host" --arg tls "$tls" --arg sni "$sni" \
            '{type: "vmess", tag: $t, server: $s, server_port: ($p|tonumber), uuid: $u, transport: { type: $net, ws_settings: { path: $path, headers: { Host: $host } } }, tls: { enabled: (if $tls == "tls" then true else false end), server_name: $sni }}')
        type="vmess"
    fi

    test_outbound_connection "$type" "$server" "$port" "" ""
    [[ $? -ne 0 ]] && { warn "落地探测不通，已取消导入"; return 1; }

    local sandbox="/tmp/sb_test_config.json"
    cp "$CONFIG" "$sandbox"
    jq --argjson node "$new_node" '(.outbounds //= []) | .outbounds += [$node]' "$sandbox" > "${sandbox}.tmp" && mv "${sandbox}.tmp" "$sandbox"
    
    if _check_model_config "$sandbox" >/dev/null 2>&1; then
        mv "$sandbox" "$CONFIG"
        ok "导入成功！(请前往‘设置节点落地关联’以生效)"
    else
        err "✖ 内核校验失败"
        rm -f "$sandbox"
    fi
}

# 2. 增强版深度修复 (自动识别并剔除坏死节点)
repair_config_structure() {
    echo -e "\n${C_CYAN}=== 深度配置修复 (Config Doctor) ===${C_RESET}"

    # 0) 结构兜底：保证 route/rules/outbounds/inbounds 存在
    safe_json_edit "$CONFIG" '(.route //= {}) | (.route.rules //= []) | (.outbounds //= []) | (.inbounds //= [])' >/dev/null 2>&1 || true

    # 1) 确保 direct 出站存在且 tag 正确（避免“解绑/清理后断网”）
    # 1.1 修复任何 direct 节点缺 tag 的情况
    safe_json_edit "$CONFIG" '
      .outbounds |= map(
        if (.type == "direct") and ((.tag // "") | length == 0) then . + {tag:"direct"} else . end
      )
    ' >/dev/null 2>&1 || true

    # 1.2 如果仍然没有 direct，就补一个到列表末尾
    if ! jq -e '.outbounds[]? | select(.tag=="direct")' "$CONFIG" >/dev/null 2>&1; then
      safe_json_edit "$CONFIG" '.outbounds += [{"type":"direct","tag":"direct"}]' >/dev/null 2>&1 || true
    fi

    # 2) 清理“动态本地出口”(LOCAL-OUT-*)，这些很容易因为 sendThrough 失效导致分流断网
    #    同时：把引用了它们的规则 outbound 统一恢复为 direct（真正恢复直连）
    safe_json_edit "$CONFIG" '
      ( [ .outbounds[]? | select(.tag!=null) | .tag ] ) as $beforeTags
      | ( [ .outbounds[]? | select(.tag!=null and (.tag|test("^LOCAL-OUT-"))) | .tag ] ) as $localTags
      | .outbounds |= map(select(.tag==null or (.tag|test("^LOCAL-OUT-")|not)))
      | ( [ .outbounds[]? | select(.tag!=null) | .tag ] ) as $afterTags
      | .route.rules |= map(
          if (.outbound? == null) then .
          elif (.outbound|tostring|test("^LOCAL-OUT-")) then .outbound="direct"
          elif ($afterTags | index(.outbound)) != null then .
          else .outbound="direct"
          end
        )
    ' >/dev/null 2>&1 || true

    # 3) 保留你原来的“坏死 IMP 节点”清理逻辑（但也顺带把引用缺失出口的规则修成 direct）
    echo -e "➜ ${C_GRAY}正在进行配置健康体检...${C_RESET}"
    if ! _check_model_config "$CONFIG" >/dev/null 2>&1; then
        warn "检测到坏死节点/配置异常，正在清理 IMP-* 自动导入落地..."
        safe_json_edit "$CONFIG" '
          del(.outbounds[] | select(.tag!=null and (.tag|startswith("IMP-"))))
        ' >/dev/null 2>&1 || true

        # 清理后再次把“引用不存在 outbound”的规则改回 direct
        safe_json_edit "$CONFIG" '
          ( [ .outbounds[]? | select(.tag!=null) | .tag ] ) as $tags
          | .route.rules |= map(
              if (.outbound? == null) then .
              elif ($tags | index(.outbound)) != null then .
              else .outbound="direct"
              end
            )
        ' >/dev/null 2>&1 || true
    fi

    # 4) 兼容字段：route.final（你的 xray-sync 不一定用它，但留着也无害）
    safe_json_edit "$CONFIG" '.route.final = "direct"' >/dev/null 2>&1 || true

    # 5) 最终校验 & 重启
    if _check_model_config "$CONFIG" >/dev/null 2>&1; then
        ok "修复完成：已恢复 direct 并纠正异常分流规则，正在重启服务..."
        restart_xray
    else
        err "修复后配置仍不通过校验，建议手动检查: vi $CONFIG"
        err "重点看：outbounds / route.rules 是否有语法或字段类型错误"
    fi
}


# 查看并删除落地出口 (显示更准：支持域名解析/显示直连绑定出口)
# -----------------------------
# Outbound 显示增强：为菜单展示 tag -> server:port (type) [国家]
# -----------------------------

resolve_host_ip_cached() {
  local host="$1"
  [[ -z "$host" ]] && { echo ""; return 0; }

  # 已经是 IP
  if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "$host" == *:* ]]; then
    echo "$host"
    return 0
  fi

  # cache
  if [[ -n "${_HOST2IP[$host]:-}" ]]; then
    echo "${_HOST2IP[$host]}"
    return 0
  fi

  local ip=""
  if command -v getent >/dev/null 2>&1; then
    ip="$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1; exit}')"
    [[ -z "$ip" ]] && ip="$(getent ahosts "$host" 2>/dev/null | awk 'NR==1{print $1; exit}')"
  fi
  if [[ -z "$ip" ]] && command -v dig >/dev/null 2>&1; then
    ip="$(dig +short A "$host" 2>/dev/null | head -n1)"
    [[ -z "$ip" ]] && ip="$(dig +short AAAA "$host" 2>/dev/null | head -n1)"
  fi

  _HOST2IP["$host"]="$ip"
  echo "$ip"
}

format_outbound_label() {
  local tag="$1"
  [[ -z "$tag" || "$tag" == "null" ]] && { echo ""; return 0; }

  # 内置直连
  if [[ "$tag" == "direct" ]]; then
    echo "直连 (direct)"
    return 0
  fi

  # 读取 model config 里的 outbound（sing-box 风格）
  local ob
  ob="$(jq -c --arg t "$tag" '.outbounds[]? | select(.tag==$t)' "$CONFIG" 2>/dev/null)"
  if [[ -z "$ob" || "$ob" == "null" ]]; then
    echo ""
    return 0
  fi

  local type server port sendThrough
  type="$(echo "$ob" | jq -r '.type // "unknown"' 2>/dev/null)"
  server="$(echo "$ob" | jq -r '.server // .address // .host // empty' 2>/dev/null)"
  port="$(echo "$ob" | jq -r '.server_port // .port // empty' 2>/dev/null)"
  sendThrough="$(echo "$ob" | jq -r '.sendThrough // .send_through // empty' 2>/dev/null)"

  # direct + sendThrough（旧残留）：显示绑定 IP + 国家
  if [[ "$type" == "direct" ]]; then
    if [[ -n "$sendThrough" ]]; then
      local cc="??"
      cc="$(get_ip_country "$sendThrough" 2>/dev/null || echo "??")"
      echo "${sendThrough} (direct) [${cc}]"
    else
      echo "直连 (direct)"
    fi
    return 0
  fi

  [[ -z "$server" ]] && server="未知"
  [[ -z "$port" || "$port" == "null" ]] && port="??"

  local ip="" cc="??"
  if [[ "$server" != "未知" ]]; then
    ip="$(resolve_host_ip_cached "$server")"
    [[ -n "$ip" ]] && cc="$(get_ip_country "$ip" 2>/dev/null || echo "??")"
  fi

  if [[ -n "$ip" ]]; then
    echo "${server}:${port} (${type}) -> ${ip} [${cc}]"
  else
    echo "${server}:${port} (${type}) [${cc}]"
  fi
}

list_and_del_outbounds() {
    local menu_buffer=""
    menu_buffer+="\n${C_CYAN}=== 当前落地出口列表 (管理自定义落地) ===${C_RESET}\n"

    echo -e "➜ ${C_GRAY}正在加载出口数据...${C_RESET}"

    # 仅展示“可管理的自定义落地”：
    # - tag 必须存在且非空
    # - 排除 tag=direct
    # - 排除 LOCAL-OUT-*（自动生成的 direct 出站）
    # - 排除“裸 direct”（type=direct 且没有 sendThrough/send_through）
    mapfile -t TAG_LIST < <(
      jq -r '
        .outbounds[]?
        | select(.tag != null and (.tag|tostring|length) > 0)
        | select(.tag != "direct")
        | select((.tag|test("^LOCAL-OUT-")) | not)
        | select(.type != "direct" or ((.sendThrough // .send_through // "")|tostring|length) > 0)
        | .tag
      ' "$CONFIG" 2>/dev/null
    )

    if [[ ${#TAG_LIST[@]} -eq 0 ]]; then
      warn "当前没有可管理的自定义落地。"
      return
    fi

    # 构建菜单：tag + 解析信息(含国家)
    local idx=0
    for t in "${TAG_LIST[@]}"; do
      idx=$((idx+1))
      menu_buffer+=" ${C_GREEN}[$idx]${C_RESET} ${C_YELLOW}${t}${C_RESET}  $(format_outbound_label "$t")\n"
    done
    menu_buffer+=" ${C_GREEN}[0]${C_RESET} 取消并返回\n"

    echo -e "$menu_buffer"
    read -rp "请输入要删除的序号: " del_idx
    [[ -z "${del_idx:-}" || "$del_idx" == "0" ]] && return
    [[ ! "$del_idx" =~ ^[0-9]+$ ]] && { warn "无效输入"; return; }

    local del_tag="${TAG_LIST[$((del_idx-1))]}"
    [[ -z "${del_tag:-}" ]] && { warn "无效序号"; return; }

    warn "即将删除落地：${C_YELLOW}${del_tag}${C_RESET}  $(format_outbound_label "$del_tag")"
    read -rp "确认删除？(y/N): " yn
    [[ "$yn" != "y" && "$yn" != "Y" ]] && { say "已取消"; return; }

    safe_json_edit "$CONFIG" 'del(.outbounds[] | select(.tag==$tag))' --arg tag "$del_tag" >/dev/null 2>&1 || {
      err "删除失败：JSON 写入异常"
      return 1
    }

    # 同步清理引用该 outbound 的规则，防止残留
    safe_json_edit "$CONFIG" 'del(.route.rules[]? | select(.outbound==$tag))' --arg tag "$del_tag" >/dev/null 2>&1 || true

    ok "已删除落地：$del_tag"
    restart_xray
}



list_and_del_routing_rules() {
    echo -e "\n${C_CYAN}=== 查看/解除 关联规则 (分流列表) ===${C_RESET}"

    # 确保基础结构存在
    safe_json_edit "$CONFIG" '(.route //= {}) | (.route.rules //= []) | (.outbounds //= [])' >/dev/null 2>&1 || true

    local total
    total=$(jq -r '(.route.rules // []) | length' "$CONFIG" 2>/dev/null || echo 0)

    if [[ "$total" == "0" ]]; then
        warn "当前没有任何关联规则。"
        return
    fi

    echo -e "➜ ${C_GRAY}当前规则总数: ${total}${C_RESET}"
    echo -e "${C_BLUE}操作指引：${C_RESET}"
    # 已移除 in:标签 的提示
    echo -e " ${C_YELLOW}数字${C_RESET} - 删除对应行 | ${C_YELLOW}all${C_RESET} - 清空全部 | ${C_YELLOW}0${C_RESET} - 返回"
    echo -e "${C_GRAY}————————————————————————————————————————————————————————————————————————————————${C_RESET}"

    # 展示规则，并将 label 和类型名称汉化
    jq -r '
      (.route.rules // [])
      | to_entries[]
      | .key as $i
      | .value as $r
      | [
          ($i+1),
          (if ($r.inbound|type)=="array" then ($r.inbound|join(",")) else ($r.inbound//"-") end),
          ($r.kind // "通用"),
          ($r.outbound // "direct"),
          (if ($r.domain|type)=="array" then (($r.domain|length)|tostring) else "0" end)
        ]
      | @tsv
    ' "$CONFIG" 2>/dev/null | while IFS=$'\t' read -r idx inbound kind outbound_tag dcnt; do
        # 汉化类型名称
        local display_kind="$kind"
        display_kind="${display_kind//media-split-GLOBAL/【全局代理】}"
        display_kind="${display_kind//media-split-GPT/ChatGPT分流}"
        display_kind="${display_kind//media-split-GEMINI/Gemini分流}"
        display_kind="${display_kind//media-split-CUSTOM/自定义分流}"
        display_kind="${display_kind//media-split-/}" # 去掉其他分类的前缀

        local ob_label; ob_label="$(format_outbound_label "$outbound_tag")"
        
        printf " ${C_GREEN}[%s]${C_RESET} 入站:${C_YELLOW}%-15s${C_RESET} 类型:${C_CYAN}%-12s${C_RESET} 落地:${C_PURPLE}%-25s${C_RESET} 域名数:%s\n" \
               "$idx" "$inbound" "$display_kind" "$ob_label" "$dcnt"
    done

    echo -e "${C_GRAY}————————————————————————————————————————————————————————————————————————————————${C_RESET}"
    read -rp "请输入操作指令: " action
    [[ -z "${action:-}" || "$action" == "0" ]] && return

    # 1) 删除单条：输入纯数字
    if [[ "$action" =~ ^[0-9]+$ ]]; then
        local del_idx=$((action-1))
        if (( del_idx < 0 || del_idx >= total )); then
            err "无效序号"
            return
        fi

        safe_json_edit "$CONFIG" '
          .route.rules |= (
            to_entries
            | map(select(.key != ($idx|tonumber)))
            | map(.value)
          )
        ' --arg idx "$del_idx" >/dev/null 2>&1 || true

        ok "已删除第 ${action} 条规则。"
        restart_xray
        return
    fi

    # 2) all：清空全部规则
    if [[ "$action" == "all" ]]; then
        safe_json_edit "$CONFIG" '.route.rules = []' >/dev/null 2>&1 || true
        ok "已清空所有分流规则（恢复直连）。"
        restart_xray
        return
    fi

    # 注意：此处已删除了 in:标签 和 ms:标签 的后台逻辑判断

    warn "未识别的输入：$action (请输入数字序号或 all)"
}




# --- NAT Mode Menu ---
nat_mode_menu() {
  load_nat_data
  echo -e "\n${C_CYAN}当前 NAT 模式: ${nat_mode:-关闭}${C_RESET}"
  echo "1) 范围端口"
  echo "2) 自定义 TCP/UDP"
  echo "3) 关闭"
  read -rp "选择: " nm
  local tmp=$(mktemp)
  case "$nm" in
      1) read -rp "输入范围 (10000-20000): " r
         jq -n --arg r "$r" '{"mode":"range","ranges":[$r]}' > "$tmp" && mv "$tmp" "$NAT_FILE" ;;
      2) read -rp "输入端口 (空格分隔): " p
         local arr=$(echo "$p" | jq -R 'split(" ")|map(tonumber)')
         jq -n --argjson a "$arr" '{"mode":"custom","custom_tcp":$a}' > "$tmp" && mv "$tmp" "$NAT_FILE" ;;
      3) rm -f "$NAT_FILE" ;;
  esac
  ok "设置已保存"
}

# ============= 5. Dashboard UI & Entry =============

show_menu_banner() {
    # 删除了开头的 clear
    get_sys_status
}
# ============= 新增：状态维护子菜单 (UI优化+纯卸载逻辑) =============
status_menu() {
  while true; do
    # 保留交互感，不强行 clear
    echo -e "\n${C_CYAN}=== 状态维护与管理 ===${C_RESET}"
    echo -e " ${C_GREEN}1.${C_RESET} 系统深度修复 "
    echo -e " ${C_GREEN}2.${C_RESET} 重启核心服务 "
    echo -e " ${C_GREEN}3.${C_RESET} 更新核心版本 "
    echo -e " ${C_RED}4.${C_RESET} 彻底卸载脚本 "
    echo -e " ${C_GREEN}0.${C_RESET} 返回上级菜单"
    echo ""

    safe_read sc " 请输入选项: "
    case "$sc" in
      1) 
          check_and_repair_menu
          ;;
      2) 
          restart_xray
          read -rp "按回车继续..." _
          ;;
      3) 
          say "正在更新 Xray..."
          rm -f /usr/local/bin/xray
          install_xray_if_needed
          restart_xray
          read -rp "按回车继续..." _
          ;;
      4) 
          echo ""
          warn "⚠️  警告：此操作将永久删除所有节点配置、内核程序、运行日志、服务文件以及脚本自身！"
          read -rp " 确认要彻底卸载并自毁脚本吗？(y/N): " confirm
          if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
              say "正在执行强力清理程序..."

              # 1. 停止并禁用所有相关服务
              say "停止服务项..."
              systemctl stop xray 2>/dev/null
              systemctl disable xray 2>/dev/null
              # 自动搜索并停止所有动态生成的 Hysteria2 服务
              if command -v systemctl >/dev/null 2>&1; then
                  local hy2_services
                  hy2_services=$(systemctl list-unit-files | grep "hysteria2-" | awk '{print $1}')
                  for svc in $hy2_services; do
                      systemctl stop "$svc" 2>/dev/null
                      systemctl disable "$svc" 2>/dev/null
                      rm -f "/etc/systemd/system/$svc"
                  done
              fi

              # 2. 强力终止残留进程
              say "终止残留进程 (Xray/Hy2/Argo)..."
              pkill -9 -f "/usr/local/bin/xray" 2>/dev/null
              pkill -9 -f "hysteria server" 2>/dev/null
              pkill -9 -f "cloudflared" 2>/dev/null
              pkill -9 -f "xray-singleton" 2>/dev/null

              # 3. 清除所有二进制程序与目录
              say "抹除核心文件与配置..."
              # Xray 相关
              rm -rf /etc/xray /var/log/xray.log /usr/local/bin/xray /usr/local/bin/xray-singleton /usr/local/bin/xray-sync
              rm -f /etc/systemd/system/xray.service /etc/init.d/xray
              # Hysteria 相关
              rm -rf /etc/hysteria2 /usr/local/bin/hysteria
              # Argo 相关
              rm -rf /root/agsbx

              # 4. 清除缓存、环境变量与快捷指令
              say "清理环境变量与别名..."
              rm -f "$IP_CACHE_FILE" "${IP_CACHE_FILE}_v6" "/tmp/my_ip_cache"*
              sed -i '/alias my=/d' /root/.bashrc
              sed -i '/alias MY=/d' /root/.bashrc
              
              # 刷新系统服务列表
              systemctl daemon-reload 2>/dev/null

              # 5. 脚本自毁逻辑
              local self_path
              self_path=$(readlink -f "$0") 
              
              ok "卸载完成！服务器已恢复洁净状态。"
              
              if [[ -f "$self_path" ]]; then
                  say "脚本自毁中: $self_path"
                  rm -f "$self_path"
              fi
              
              echo -e "${C_PURPLE}江湖再见，祝你一路顺风！${C_RESET}"
              exit 0
          else
              say "已取消卸载。"
              sleep 1
          fi
          ;;
      0) return ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

# === 将“节点锁定出口IP”真正写入模型配置（/etc/xray/config.json） ===
# === 将“节点锁定出口IP”写入模型配置（/etc/xray/config.json） ===
apply_node_egress_lock_to_model() {
  local tag="$1"
  local ip="$2"
  local ob_tag="DIR-${tag}"

  [[ -z "$tag" || -z "$ip" ]] && return 1
  [[ ! -f "$CONFIG" ]] && { err "模型配置不存在：$CONFIG"; return 1; }

  # 关键：safe_json_edit 的第2个参数必须是 filter；--arg 必须放在 filter 之后
  safe_json_edit "$CONFIG" '
    (.outbounds //= [])
    | (.outbounds |= (
        if any(.[]; (.tag // "") == $ob) then
          map(if (.tag // "") == $ob then (. + {type:"direct", tag:$ob, sendThrough:$ip}) else . end)
        else
          . + [{type:"direct", tag:$ob, sendThrough:$ip}]
        end
      ))
    | (.route //= {})
    | (.route.rules //= [])
    | (.route.rules |= (
        [{inbound:$in, outbound:$ob}]
        + (map(select((.inbound // "") != $in)))
      ))
  ' --arg in "$tag" --arg ob "$ob_tag" --arg ip "$ip"
}

# === 清理“节点锁定出口IP”在模型配置中的落地（/etc/xray/config.json） ===
clear_node_egress_lock_from_model() {
  local tag="$1"
  local ob_tag="DIR-${tag}"

  [[ -z "$tag" ]] && return 1
  [[ ! -f "$CONFIG" ]] && return 0

  safe_json_edit "$CONFIG" '
    (.outbounds //= [])
    | (.outbounds |= map(select((.tag // "") != $ob)))
    | (.route //= {})
    | (.route.rules //= [])
    | (.route.rules |= map(
        select( ((.inbound // "") != $in) and ((.outbound // "") != $ob) )
      ))
  ' --arg in "$tag" --arg ob "$ob_tag"
}

ensure_force_v4_domain_list() {
  mkdir -p /etc/xray >/dev/null 2>&1 || true

  # 第一次运行自动生成默认名单（你贴的失败站点）
  if [[ ! -s /etc/xray/force_v4_domains.txt ]]; then
    cat >/etc/xray/force_v4_domains.txt <<'EOF'
discord.com
x.com
openai.com
EOF
  fi
}

# 生成一条 xray routing rule：命中名单域名 -> outboundTag=direct-v4
# 输出：写到 stdout（一段 JSON 规则）
_build_force_v4_rule_json() {
  ensure_force_v4_domain_list

  # 读名单，转成 ["domain:xxx","domain:yyy"...]
  local domains_json
  domains_json=$(
    awk '
      {gsub("\r","");}
      NF && $0 !~ /^[[:space:]]*#/ {print "domain:"$0}
    ' /etc/xray/force_v4_domains.txt \
    | jq -Rsc 'split("\n") | map(select(length>0))'
  )

  # 如果名单为空，输出空
  if [[ -z "$domains_json" || "$domains_json" == "[]" ]]; then
    echo ""
    return 0
  fi

  # 输出一条标准 field 规则（优先级最高，后面会插到 rules 最前）
  jq -cn --argjson d "$domains_json" '
    {
      "type":"field",
      "domain": $d,
      "outboundTag":"direct-v4"
    }'
}
# === 服务器全局网络版本切换 (完整版：支持多 IP 选择 + 域名名单管理) ===
_global_ip_version_menu() {
  local __egress_probed=0
  local -a V4_LIST=() V6_LIST=()
  local v4_count=0 v6_count=0
  _probe_egress_once() {
    (( __egress_probed == 1 )) && return 0
    mapfile -t V4_LIST < <(get_all_ips_with_geo 4)
    mapfile -t V6_LIST < <(get_all_ips_with_geo 6)
    v4_count="${#V4_LIST[@]}"
    v6_count="${#V6_LIST[@]}"
    __egress_probed=1
  }

  _probe_egress_once

  while true; do
    echo -e "\n${C_CYAN}=== 服务器全局：网络版本切换 (IPv4 / IPv6) ===${C_RESET}"

    # 1. 探测当前所有可用 IP
    local -a V4_LIST=() V6_LIST=()
    mapfile -t V4_LIST < <(get_all_ips_with_geo 4)
    mapfile -t V6_LIST < <(get_all_ips_with_geo 6)
    local v4_count="${#V4_LIST[@]}"
    local v6_count="${#V6_LIST[@]}"

    # 2. 获取当前模式显示
    local cur_pref cur_label
    cur_pref="$(_get_global_mode)"
    cur_label="$(_ip_mode_desc "$cur_pref")"
    
    # 颜色排版：节点黄色，括号紫色，值白色
    printf " ${C_RESET}当前全局模式：${C_YELLOW}%s${C_RESET} ${C_PURPLE}(${C_RESET}%s${C_PURPLE})${C_RESET}\n\n" "$cur_pref" "$cur_label"

    say "1) 全局：优选 IPv4（可回退 IPv6） ${C_GRAY}(检测到 $v4_count 个出口)${C_RESET}"
    say "2) 全局：优选 IPv6（可回退 IPv4 + v6不通域名走v4） ${C_GRAY}(检测到 $v6_count 个出口)${C_RESET}"
    say "3) 全局：真全局 IPv4 only（完全不用 IPv6） ${C_GRAY}(检测到 $v4_count 个出口)${C_RESET}"
    say "4) 全局：真全局 IPv6 only（完全不用 IPv4） ${C_GRAY}(检测到 $v6_count 个出口)${C_RESET}"
    say "5) 管理『v6不通强制走v4』域名名单（仅对 优选IPv6 生效）"
    say "6) 停止全局策略（不干预IP版本，让节点策略优先生效）"
    say "0) 返回上级"
    
    local ip_choice
    safe_read ip_choice " 请选择操作 [0-6]: "

    case "$ip_choice" in
      1|2|3|4)
        mkdir -p /etc/xray >/dev/null 2>&1 || true
        chattr -i /etc/xray/ip_pref /etc/xray/global_egress_ip_v6 /etc/xray/global_egress_ip_v4 2>/dev/null || true

        local pref="" mode_name="" target_v="" target_count=0 lock_file=""
        local -a TARGET_IP_LIST=()

        case "$ip_choice" in
          1) pref="v4pref"; mode_name="优选 IPv4"; target_v="v4"; TARGET_IP_LIST=("${V4_LIST[@]}"); target_count=$v4_count ;;
          2) pref="v6pref"; mode_name="优选 IPv6"; target_v="v6"; TARGET_IP_LIST=("${V6_LIST[@]}"); target_count=$v6_count ;;
          3) pref="v4only"; mode_name="真全局 IPv4 only"; target_v="v4"; TARGET_IP_LIST=("${V4_LIST[@]}"); target_count=$v4_count ;;
          4) pref="v6only"; mode_name="真全局 IPv6 only"; target_v="v6"; TARGET_IP_LIST=("${V6_LIST[@]}"); target_count=$v6_count ;;
        esac

        if [[ "$pref" == "v6only" && $v6_count -eq 0 ]]; then
          warn "错误：未检测到可用的 IPv6 出口，无法切换至 v6only 模式。"
          continue
        fi
        if [[ "$pref" == "v4only" && $v4_count -eq 0 ]]; then
          warn "错误：未检测到可用的 IPv4 出口，无法切换至 v4only 模式。"
          continue
        fi

        lock_file="/etc/xray/global_egress_ip_${target_v}"
        local old_pref old_locked selected_fixed_ip=""
        old_pref="$(_get_global_mode)"
        old_locked="$(cat "$lock_file" 2>/dev/null | tr -d '\r\n ')"

        if [[ $target_count -ge 1 ]]; then
            echo -e "\n${C_CYAN}检测到可用的 ${target_v^^} 出口，请选择要锁定的 IP：${C_RESET}"
            local n=0
            for line in "${TARGET_IP_LIST[@]}"; do
                n=$((n+1))
                echo -e " ${C_GREEN}[$n]${C_RESET} $line"
            done
            echo -e " ${C_GREEN}[0]${C_RESET} 返回上级"
            echo -e " ${C_GRAY}(回车=不锁定，交给系统动态路由)${C_RESET}"
            read -rp " 请选择序号（回车=不锁定）: " ip_sel

            if [[ "${ip_sel:-}" == "0" ]]; then
                say "已返回上级（未改动锁定设置）"
                continue
            fi

            if [[ "$ip_sel" =~ ^[0-9]+$ ]] && (( ip_sel >= 1 && ip_sel <= n )); then
                selected_fixed_ip=$(echo "${TARGET_IP_LIST[$((ip_sel-1))]}" | awk '{print $1}')
            fi
        fi

        if [[ "$pref" == "$old_pref" && "$selected_fixed_ip" == "$old_locked" ]]; then
          ok "当前全局策略与锁定出口均未变化，跳过重启。"
          continue
        fi

        echo "$pref" > /etc/xray/ip_pref
        if [[ -n "$selected_fixed_ip" ]]; then
            echo "$selected_fixed_ip" > "$lock_file"
            ok "已锁定 ${target_v^^} 出口 IP: $selected_fixed_ip"
        else
            rm -f "$lock_file"
            say "已设置为系统动态分配 ${target_v^^} 出口"
        fi

        ok "✔ 全局模式已成功切换为：$mode_name"
        
        if [[ "$pref" == "v6pref" && ! -s /etc/xray/force_v4_domains.txt ]]; then
          echo -e "discord.com\nx.com\nopenai.com" > /etc/xray/force_v4_domains.txt
        fi

        restart_xray
        ;;

      5)
        while true; do
            mkdir -p /etc/xray >/dev/null 2>&1 || true
            [[ ! -s /etc/xray/force_v4_domains.txt ]] && echo -e "discord.com\nx.com\nopenai.com" > /etc/xray/force_v4_domains.txt

            echo -e "\n${C_CYAN}=== v6不通强制走v4：域名名单 (v6pref 生效) ===${C_RESET}"
            nl -ba /etc/xray/force_v4_domains.txt 2>/dev/null || echo "名单为空"
            echo
            say "1) 添加域名"
            say "2) 删除域名"
            say "3) 清理空行/注释/去重"
            say "0) 返回上级"
            local act
            safe_read act " 请选择操作: "
            
            case "$act" in
              1)
                local d
                safe_read d " 输入要添加的域名 (如 google.com): "
                [[ -n "${d:-}" ]] && echo "$d" >> /etc/xray/force_v4_domains.txt && ok "已添加: $d"
                ;;
              2)
                local d
                safe_read d " 输入要删除的域名 (需完全匹配): "
                if [[ -n "${d:-}" ]]; then
                  grep -vFx "$d" /etc/xray/force_v4_domains.txt > /etc/xray/force_v4_domains.txt.tmp \
                    && mv /etc/xray/force_v4_domains.txt.tmp /etc/xray/force_v4_domains.txt
                  ok "已尝试删除: $d"
                fi
                ;;
              3)
                awk '{gsub("\r","");} NF && $0 !~ /^[[:space:]]*#/ {print}' /etc/xray/force_v4_domains.txt \
                  | sort -u > /etc/xray/force_v4_domains.txt.tmp \
                  && mv /etc/xray/force_v4_domains.txt.tmp /etc/xray/force_v4_domains.txt
                ok "清理与去重完成。"
                ;;
              0) break ;;
            esac
        done
        warn "提示：域名名单修改后需重启一次 Xray 服务方可对现有连接生效。"
        ;;

      6)
        chattr -i /etc/xray/ip_pref /etc/xray/global_egress_ip_v4 /etc/xray/global_egress_ip_v6 2>/dev/null || true
        echo "off" > /etc/xray/ip_pref
        rm -f /etc/xray/global_egress_ip_v4 /etc/xray/global_egress_ip_v6 >/dev/null 2>&1 || true
        ok "✔ 已停止全局策略（模式已设为 off），节点独立策略现在优先生效。"
        restart_xray
        ;;

      0) return ;;
      *) warn "无效输入。" ;;
    esac
  done
}


# === 完美对齐+一键恢复版：网络切换主菜单 ===
# === 完美对齐+核弹重置版：网络切换主菜单 ===
ip_version_menu() {
  while true; do
    # 1. 获取全局状态
    local g_pref g_label
    g_pref="$(_get_global_mode)"
    g_label="$(_ip_mode_desc "$g_pref")"

    echo -e "\n${C_CYAN}=== 网络切换：选择节点/全局 ===${C_RESET}"
    echo -e "${C_GRAY}说明：单节点独立设置会覆盖全局策略${C_RESET}\n"

    # 2. 聚合所有节点标签
    local tags_raw=""
    [[ -f "$CONFIG" ]] && tags_raw+=$(jq -r '.inbounds[].tag // empty' "$CONFIG" 2>/dev/null || true)
    [[ -f "$META"   ]] && tags_raw+=$'\n'$(jq -r 'keys[]' "$META" 2>/dev/null || true)
    mapfile -t ALL_TAGS < <(echo "$tags_raw" | grep -v '^$' | sort -u)

    # 3. 循环显示节点状态
    local i=0
    for tag in "${ALL_TAGS[@]}"; do
      i=$((i+1))
      local node_mode
      node_mode=$(jq -r --arg t "$tag" '.[$t].ip_mode // "follow_global"' "$META" 2>/dev/null)
      
      local status_text=""
      if [[ "$node_mode" == "follow_global" || "$node_mode" == "follow" || "$node_mode" == "null" || -z "$node_mode" ]]; then
        status_text="${C_PURPLE}(当前：跟随全局 → ${C_RESET}${g_label}${C_PURPLE})${C_RESET}"
      else
        local n_label
        n_label="$(_ip_mode_desc "$node_mode")"
        status_text="${C_PURPLE}(独立设置：${C_RESET}${n_label}${C_PURPLE})${C_RESET}"
      fi
      printf " ${C_GREEN}[%d]${C_RESET} ${C_YELLOW}%s\033[40G%b\n" "$i" "$tag" "$status_text"
    done

    # 4. 服务器全局策略
    local g_idx=$((i+1))
    printf " ${C_GREEN}[%d]${C_RESET} ${C_CYAN}服务器全局策略\033[40G${C_PURPLE}(当前全局：${C_RESET}%s${C_PURPLE})${C_RESET}\n" "$g_idx" "$g_label"
    
    # 5. 【升级】核弹级一键重置选项 (颜色标红警示)
    local r_idx=$((i+2))
    printf " ${C_GREEN}[%d]${C_RESET} ${C_RED}一键重置：恢复全局 并 清除所有节点独立设置${C_RESET}\n" "$r_idx"
    
    echo -e " ${C_GREEN}[0]${C_RESET} 返回主菜单\n"

    local pick
    safe_read pick "请选择序号: "
    [[ -z "${pick:-}" || "$pick" == "0" ]] && return
    
    if ! [[ "$pick" =~ ^[0-9]+$ ]]; then
      warn "输入无效：请输入数字序号。"
      continue
    fi

    # 处理全局策略二级菜单
    if (( pick == g_idx )); then
      _global_ip_version_menu
      continue
    fi

    # 处理核弹级一键重置逻辑
    if (( pick == r_idx )); then
      say "正在执行深度清理..."
      # a. 清理全局设置
      chattr -i /etc/xray/ip_pref /etc/xray/global_egress_ip_v4 /etc/xray/global_egress_ip_v6 2>/dev/null || true
      echo "off" > /etc/xray/ip_pref
      rm -f /etc/xray/global_egress_ip_v4 /etc/xray/global_egress_ip_v6 >/dev/null 2>&1 || true
      
      # b. 批量清理所有节点的独立设置 (直接操作 META)
      if [[ -f "$META" ]]; then
          chattr -i "$META" 2>/dev/null || true
          safe_json_edit "$META" 'map_values(del(.ip_mode, .fixed_ip, .ip_version))' >/dev/null 2>&1 || true
      fi

      ok "✔ 已成功重置全局策略，并清空了所有节点的独立网络设置！"
      restart_xray
      continue
    fi

    if (( pick < 1 || pick > ${#ALL_TAGS[@]} )); then
      warn "输入无效：序号超出范围。"
      continue
    fi

    _node_ip_mode_menu "${ALL_TAGS[$((pick-1))]}"
  done
}

# ============= 完全独立的 Hysteria2 网络配置刷新 =============
# ============= 完全独立的 Hysteria2 网络配置刷新 (路由语法终极修复版) =============
sync_hy2_network() {
    local tags; tags=$(jq -r 'to_entries[] | select(.value.type=="hysteria2") | .key' "$META" 2>/dev/null)
    [[ -z "$tags" ]] && return 0

    local g_pref; g_pref=$(cat /etc/xray/ip_pref 2>/dev/null | tr -d '\r\n ' || echo "v4")
    local g_v4; g_v4=$(cat /etc/xray/global_egress_ip_v4 2>/dev/null | tr -d '\r\n ')
    local g_v6; g_v6=$(cat /etc/xray/global_egress_ip_v6 2>/dev/null | tr -d '\r\n ')

    for t in $tags; do
        local port; port=$(jq -r --arg t "$t" '.[$t].port' "$META")
        local ip_mode; ip_mode=$(jq -r --arg t "$t" '.[$t].ip_mode // "follow_global"' "$META")
        local fixed_ip; fixed_ip=$(jq -r --arg t "$t" '.[$t].fixed_ip // empty' "$META")
        
        local eff_mode="$ip_mode"
        local eff_ip="$fixed_ip"
        
        if [[ "$eff_mode" == "follow_global" || "$eff_mode" == "follow" || "$eff_mode" == "null" || -z "$eff_mode" ]]; then
            eff_mode="$g_pref"
            [[ "$g_pref" =~ v6 ]] && eff_ip="$g_v6" || eff_ip="$g_v4"
        fi
        
        local hy2_mode="auto"
        case "$eff_mode" in
            v4pref|v4) hy2_mode="46" ;;
            v6pref|v6) hy2_mode="64" ;;
            v4only)    hy2_mode="4" ;;
            v6only)    hy2_mode="6" ;;
            off)       hy2_mode="auto"; eff_ip="" ;;
            *)         hy2_mode="auto" ;;
        esac
        
        local cfg="/etc/hysteria2/${port}.yaml"
        if [[ -f "$cfg" ]]; then
            # 1. 强力清理旧的 outbounds 和 acl
            sed -i '/^outbound:/,$d' "$cfg"
            sed -i '/^outbounds:/,$d' "$cfg"
            sed -i '/^acl:/,$d' "$cfg"
            
            # 2. 追加正确的服务器端出站设置与严格 ACL 语法
            if [[ "$hy2_mode" != "auto" || -n "$eff_ip" ]]; then
                echo "outbounds:" >> "$cfg"
                echo "  - name: my_egress" >> "$cfg"
                echo "    type: direct" >> "$cfg"
                echo "    direct:" >> "$cfg"
                echo "      mode: \"$hy2_mode\"" >> "$cfg"
                if [[ -n "$eff_ip" && "$eff_ip" != "null" ]]; then
                    if [[ "$eff_ip" == *:* ]]; then
                        echo "      bindIPv6: \"$eff_ip\"" >> "$cfg"
                    else
                        echo "      bindIPv4: \"$eff_ip\"" >> "$cfg"
                    fi
                fi
                echo "acl:" >> "$cfg"
                echo "  inline:" >> "$cfg"
                # 核心修复：必须是 策略(规则) 的格式
                echo "    - \"my_egress(all)\"" >> "$cfg"
            fi
            
            # 3. 独立重启 HY2 进程使其生效
            if command -v systemctl >/dev/null 2>&1 && [[ -f "/etc/systemd/system/hysteria2-${port}.service" ]]; then
                systemctl restart "hysteria2-${port}" 2>/dev/null || true
            else
                pkill -f "hysteria server -c $cfg" 2>/dev/null || true
                nohup /usr/local/bin/hysteria server -c "$cfg" >/dev/null 2>&1 &
            fi
        fi
    done
}

# === 单节点网络模式：支持变化检测与 IP 锁定 ===
_node_ip_mode_menu() {
  local target_tag="$1"
  local __egress_probed=0
  local -a V4_LIST=() V6_LIST=()
  local v4_count=0 v6_count=0
  _probe_egress_once() {
    (( __egress_probed == 1 )) && return 0
    mapfile -t V4_LIST < <(get_all_ips_with_geo 4)
    mapfile -t V6_LIST < <(get_all_ips_with_geo 6)
    v4_count="${#V4_LIST[@]}"
    v6_count="${#V6_LIST[@]}"
    __egress_probed=1
  }

  # 进入该节点菜单时立刻探测一次（只做一次）
  _probe_egress_once

  mkdir -p /etc/xray >/dev/null 2>&1 || true

  while true; do
    echo -e "\n${C_CYAN}=== 单节点网络模式：${C_YELLOW}${target_tag}${C_RESET}${C_CYAN} ===${C_RESET}"

    # 1. 探测出口（仅首次进入本菜单时执行，避免重复浪费时间）
    _probe_egress_once

    # 2. 读取当前节点的【旧配置】用于对比
    local old_mode old_fixed_ip
    old_mode=$(jq -r --arg t "$target_tag" '.[$t].ip_mode // "follow_global"' "$META" 2>/dev/null)
    old_fixed_ip=$(jq -r --arg t "$target_tag" '.[$t].fixed_ip // empty' "$META" 2>/dev/null)
    local cur_label="$(_ip_mode_desc "$old_mode")"

    printf " ${C_RESET}当前节点模式：${C_YELLOW}%s${C_RESET} ${C_PURPLE}(${C_RESET}%s${C_PURPLE})${C_RESET}\n\n" "$old_mode" "$cur_label"

    say "1) 单节点全局：优选 IPv4（可回退 IPv6） ${C_GRAY}(检测到 $v4_count 个出口)${C_RESET}"
    say "2) 单节点全局：优选 IPv6（可回退 IPv4 + v6不通域名走v4） ${C_GRAY}(检测到 $v6_count 个出口)${C_RESET}"
    say "3) 单节点全局：真全局 IPv4 only（完全不用 IPv6） ${C_GRAY}(检测到 $v4_count 个出口)${C_RESET}"
    say "4) 单节点全局：真全局 IPv6 only（完全不用 IPv4） ${C_GRAY}(检测到 $v6_count 个出口)${C_RESET}"
    say "5) 管理『v6不通强制走v4』域名名单"
    say "6) 恢复：跟随服务器全局"
    say "0) 返回上级"

    local c
    safe_read c " 请选择操作 [0-6]: "

    case "$c" in
      1|2|3|4)
        chattr -i "$META" 2>/dev/null || true
        local pref="" target_v=""
        case "$c" in
          1) pref="v4pref"; target_v="v4" ;;
          2) pref="v6pref"; target_v="v6" ;;
          3) pref="v4only"; target_v="v4" ;;
          4) pref="v6only"; target_v="v6" ;;
        esac

        # --- IP 选择逻辑 ---
        local selected_fixed_ip=""
        local -a TARGET_IP_LIST=()
        local target_count=0
        [[ "$target_v" == "v6" ]] && { TARGET_IP_LIST=("${V6_LIST[@]}"); target_count=$v6_count; } \
                                  || { TARGET_IP_LIST=("${V4_LIST[@]}"); target_count=$v4_count; }

        local __abort_lock_choose=0

        if [[ $target_count -ge 1 ]]; then
            echo -e "\n${C_CYAN}检测到该节点有 ${target_count} 个 ${target_v^^} 出口，请选择要锁定的 IP：${C_RESET}"
            local n=0
            for line in "${TARGET_IP_LIST[@]}"; do
                n=$((n+1))
                echo -e " ${C_GREEN}[$n]${C_RESET} $line"
            done
            echo -e " ${C_GREEN}[0]${C_RESET} 返回上级"
                echo -e " ${C_GRAY}(回车=不锁定，交给系统动态路由)${C_RESET}"
            read -rp " 请选择序号（回车=不锁定）: " ip_sel
            
            if [[ "${ip_sel:-}" == "0" ]]; then
                say "已返回上级（未改动锁定设置）"
                selected_fixed_ip=""
                __abort_lock_choose=1
            fi

            if [[ "${__abort_lock_choose:-0}" != "1" ]] && [[ "$ip_sel" =~ ^[0-9]+$ ]] && (( ip_sel >= 1 && ip_sel <= n )); then
                selected_fixed_ip=$(echo "${TARGET_IP_LIST[$((ip_sel-1))]}" | awk '{print $1}')
            fi
        fi

        if [[ "${__abort_lock_choose:-0}" == "1" ]]; then
            unset __abort_lock_choose
            continue
        fi

        # --- 【核心改进：变化检测】 ---
        if [[ "$pref" == "$old_mode" && "$selected_fixed_ip" == "$old_fixed_ip" ]]; then
            ok "配置与当前运行中一致，无需更改，跳过重启。"
            continue
        fi

        # 写入配置
        if [[ -n "$selected_fixed_ip" ]]; then
            safe_json_edit "$META" '. + {($tag): (.[$tag] + {"ip_mode": $mode, "fixed_ip": $ip, "ip_version": $v})}' \
              --arg tag "$target_tag" --arg mode "$pref" --arg ip "$selected_fixed_ip" --arg v "$target_v"
            ok "已锁定出口 IP: $selected_fixed_ip"
        else
            safe_json_edit "$META" '. + {($tag): (.[$tag] + {"ip_mode": $mode})}' --arg tag "$target_tag" --arg mode "$pref"
            safe_json_edit "$META" 'del(.[$tag].fixed_ip) | del(.[$tag].ip_version)' --arg tag "$target_tag"
            say "已设置为系统动态分配出口"
        fi

        # --- 【智能分离重启逻辑】 ---
        local node_type
        node_type=$(jq -r --arg t "$target_tag" '.[$t].type // empty' "$META" 2>/dev/null)
        
        if [[ "${node_type,,}" == "hysteria2" ]]; then
            sync_hy2_network
            ok "✔ Hysteria2 网络配置已生效并独立重启！(未影响 Xray)"
        else
            if ! restart_xray; then
              warn "⚡ 重启失败，正在尝试回退..."
              safe_json_edit "$META" '. + {($tag): (.[$tag] + {"ip_mode": $m, "fixed_ip": $ip})}' --arg tag "$target_tag" --arg m "$old_mode" --arg ip "$old_fixed_ip"
              restart_xray
            fi
        fi
        ;;

      6)
        if [[ "$old_mode" == "follow_global" ]]; then
            ok "当前已是跟随模式，跳过重启。"
            continue
        fi
        chattr -i "$META" 2>/dev/null || true
        safe_json_edit "$META" 'del(.[$tag].ip_mode) | del(.[$tag].fixed_ip) | del(.[$tag].ip_version)' --arg tag "$target_tag"
        ok "✔ 节点已恢复跟随服务器全局策略。"
        
        # --- 【恢复模式：智能分离重启逻辑】 ---
        local node_type
        node_type=$(jq -r --arg t "$target_tag" '.[$t].type // empty' "$META" 2>/dev/null)
        
        if [[ "${node_type,,}" == "hysteria2" ]]; then
            sync_hy2_network
            ok "✔ Hysteria2 网络配置已恢复并独立重启！"
        else
            restart_xray
        fi
        ;;
      0) return ;;
    esac
  done
}
# 手动添加 SOCKS5 或 HTTP 落地（先测后加，修复版）
# 手动添加 SOCKS5 或 HTTP 落地（修复 jq $u/$pw 未传参导致的配置损坏）
add_manual_proxy_outbound() {
    local type_choice="$1"
    local proto="socks"
    [[ "$type_choice" == "2" ]] && proto="http"

    echo -e "\n${C_CYAN}=== 手动添加 ${proto^^} 落地 (先测后加) ===${C_RESET}"
    read -rp "落地服务器地址 (IP/域名, 输入0返回): " server
    [[ "$server" == "0" || -z "$server" ]] && return
    read -rp "端口: " port
    [[ -z "$port" ]] && return

    # 端口清洗：只保留数字
    port="$(echo "$port" | tr -cd '0-9')"
    [[ -z "$port" ]] && { err "端口不合法"; return 1; }

    read -rp "用户名 (可选): " user
    read -rp "密码 (可选): " pass

    # 1) 检查标签是否已存在
    local tag="MAN-${proto^^}-${port}"
    if jq -e --arg t "$tag" '.outbounds[]? | select(.tag == $t)' "$CONFIG" >/dev/null 2>&1; then
        err "添加失败：标签 [${tag}] 已存在，请先在‘查看/删除现有落地’中清理，或更换端口。"
        return 1
    fi

    # 2) 测试连接
    test_outbound_connection "$proto" "$server" "$port" "$user" "$pass"
    [[ $? -ne 0 ]] && { warn "落地测试未通过，已取消添加。"; return 1; }

    # 3) 构建 JSON（关键修复：把 u/pw 传给 jq）
    local new_node
    if [[ -n "$user" && -n "$pass" ]]; then
        new_node="$(
          jq -n \
            --arg t  "$tag" \
            --arg s  "$server" \
            --arg p  "$port" \
            --arg pr "$proto" \
            --arg u  "$user" \
            --arg pw "$pass" \
            '{type: $pr, tag: $t, server: $s, server_port: ($p|tonumber), username: $u, password: $pw}'
        )"
    else
        # 任意一项为空就当无认证（避免生成 username 有值但 password 为空这种“半残配置”）
        new_node="$(
          jq -n \
            --arg t  "$tag" \
            --arg s  "$server" \
            --arg p  "$port" \
            --arg pr "$proto" \
            '{type: $pr, tag: $t, server: $s, server_port: ($p|tonumber)}'
        )"
    fi

    # 4) 先写入沙盒校验（你原逻辑是对的）
    local sandbox="/tmp/sb_proxy_check.json"
    cp "$CONFIG" "$sandbox"

    jq --argjson node "$new_node" '(.outbounds //= []) | .outbounds += [$node]' \
      "$sandbox" > "${sandbox}.tmp" && mv "${sandbox}.tmp" "$sandbox"

    if _check_model_config "$sandbox"; then
        mv "$sandbox" "$CONFIG"
        ok "落地 [${tag}] 已成功保存！"
    else
        err "✖ 落地添加失败：内核配置校验未通过（见上方提示）。"
        rm -f "$sandbox"
        return 1
    fi
}



# 1. 落地出口主菜单
outbound_menu() {
  while true; do
    echo -e "\n${C_CYAN}=== 落地出口管理 (Outbounds) ===${C_RESET}"
    say "1) 手动添加 SOCKS5 落地"
    say "2) 手动添加 HTTP 落地"
    say "3) 手动添加 Shadowsocks 落地 ${C_YELLOW}(推荐)${C_RESET}"
    say "4) 链接导入 (SS / VLESS / VMESS)"
    say "5) 查看/删除 现有落地"
    echo -e "${C_BLUE}── 分流管理 ──────────────────────────────────${C_RESET}"
    say "6) 设置节点落地关联 (Inbound ➔ Outbound)"
    say "7) 查看/解除 关联规则"
    say "8) 一键诊断并修复配置 (救急专用)"
    say "0) 返回主菜单"
    
    safe_read ob_choice " 请选择操作 [0-8]: "
    case "$ob_choice" in
      1|2) add_manual_proxy_outbound "$ob_choice" ;;
      3) add_manual_ss_outbound ;;
      4)
        read -rp "请粘贴链接 (输入0返回): " link
        [[ "$link" == "0" || -z "$link" ]] && continue
        import_link_outbound "$link"
        ;;
      5) list_and_del_outbounds ;;
      6) set_node_routing ;;
      7) list_and_del_routing_rules ;;
      8) repair_config_structure ;;
      0) return ;;
      *) warn "无效选项" ;;
    esac
  done
}

add_manual_ss_outbound() {
    echo -e "\n${C_CYAN}=== 手动添加 Shadowsocks 落地 ===${C_RESET}"
    read -rp "落地服务器地址 (IP/域名): " server
    [[ -z "$server" ]] && return
    read -rp "端口: " port
    [[ -z "$port" ]] && return
    read -rp "密码 (Password/Key): " password
    [[ -z "$password" ]] && return
    
    local method="2022-blake3-aes-256-gcm"
    local tag="MAN-SS-${port}"
    local new_node=$(jq -n --arg t "$tag" --arg s "$server" --arg p "$port" --arg m "$method" --arg pw "$password" '{type: "shadowsocks", tag: $t, server: $s, server_port: ($p|tonumber), method: $m, password: $pw}')

    local sandbox="/tmp/sb_ss_check.json"
    cp "$CONFIG" "$sandbox"
    jq --argjson node "$new_node" '(.outbounds //= []) | .outbounds += [$node]' "$sandbox" > "${sandbox}.tmp" && mv "${sandbox}.tmp" "$sandbox"

    if _check_model_config "$sandbox" >/dev/null 2>&1; then
        mv "$sandbox" "$CONFIG"
        ok "SS 落地已保存。"
        # 移除 restart_xray
    else
        err "✖ 校验失败"
        rm -f "$sandbox"
    fi
}

# 设置节点与落地的关联规则 (支持自定义域名增量追加版)
set_node_routing() {
  echo -e "\n${C_CYAN}=== 分流模式：增量配置 (支持全局流量) ===${C_RESET}"

  # --- 1) 确保结构存在 ---
  safe_json_edit "$CONFIG" '(.route //= {}) | (.route.rules //= []) | (.outbounds //= []) | (.inbounds //= [])' >/dev/null 2>&1 || true

  # --- 2) 选择入站 ---
  mapfile -t IN_TAGS < <(jq -r '.inbounds[]? | select(.tag != null) | .tag' "$CONFIG" 2>/dev/null)
  if [ ${#IN_TAGS[@]} -eq 0 ]; then
    echo -e "${C_RED}✖ 当前没有任何入站节点，请先添加一个节点。${C_RESET}"
    return
  fi

  echo -e "\n${C_CYAN}=== 第一步：选择入站节点 (Inbound) ===${C_RESET}"
  local i=0
  for t in "${IN_TAGS[@]}"; do
    i=$((i+1))
    echo -e " ${C_GREEN}[$i]${C_RESET} ${C_YELLOW}${t}${C_RESET}"
  done
  read -rp "请选择序号 (0 取消): " in_idx
  [[ -z "${in_idx:-}" || "$in_idx" == "0" ]] && return
  local selected_inbound="${IN_TAGS[$((in_idx-1))]}"

  # --- 3) 选择代理出口（不再提供 IP:*，避免生成 LOCAL-OUT-SRC-*）---
  echo -e "\n${C_CYAN}=== 第二步：选择落地出口（代理出口）===${C_RESET}"

  # 可选出口：所有“可管理落地”（排除裸 direct；允许 direct 作为一个显式选项）
  mapfile -t PROXY_OUTS < <(
    jq -r '
      .outbounds[]?
      | select(.tag != null and (.tag|tostring|length)>0)
      | select(.tag != "direct")
      | select(.type != "direct" or ((.sendThrough // .send_through // "")|tostring|length) > 0)
      | .tag
    ' "$CONFIG" 2>/dev/null
  )

  # 展示列表（带国家显示）
  local -a TEMP_OUT_LIST=()
  local idx=0
  for tag in "${PROXY_OUTS[@]}"; do
    idx=$((idx+1))
    TEMP_OUT_LIST[$idx]="$tag"
    echo -e " ${C_GREEN}[$idx]${C_RESET} ${C_YELLOW}${tag}${C_RESET}  $(format_outbound_label "$tag")"
  done

  # 额外提供 direct（真正直连，不绑定 sendThrough）
  idx=$((idx+1))
  TEMP_OUT_LIST[$idx]="direct"
  echo -e " ${C_GREEN}[$idx]${C_RESET} ${C_YELLOW}direct${C_RESET}  直连 (不走代理/不绑定本机IP)"

  read -rp "请选择落地序号 (0 取消): " out_idx
  [[ -z "${out_idx:-}" || "$out_idx" == "0" ]] && return
  local selected_outbound_tag="${TEMP_OUT_LIST[$out_idx]}"
  [[ -z "${selected_outbound_tag:-}" ]] && { warn "无效选择"; return; }

  # --- 4) 分类定义（含全局 g）---
  declare -A CAT_DOMAINS
  CAT_DOMAINS["GEMINI"]="domain:gemini.google.com domain:aistudio.google.com domain:makersuite.google.com domain:deepmind.com"
  CAT_DOMAINS["GPT"]="domain:openai.com domain:chatgpt.com domain:oaistatic.com domain:oaiusercontent.com domain:stripe.com domain:chat.openai.com"
  CAT_DOMAINS["CLAUDE"]="domain:anthropic.com domain:claude.ai"
  CAT_DOMAINS["YOUTUBE"]="geosite:youtube"
  CAT_DOMAINS["GOOGLE"]="geosite:google"
  CAT_DOMAINS["X"]="geosite:twitter"
  CAT_DOMAINS["INSTAGRAM"]="geosite:instagram"
  CAT_DOMAINS["TELEGRAM"]="geosite:telegram"
  CAT_DOMAINS["NETFLIX"]="geosite:netflix"
  CAT_DOMAINS["TIKTOK"]="geosite:tiktok"
  CAT_DOMAINS["REDDIT"]="geosite:reddit"
  CAT_DOMAINS["DISCORD"]="geosite:discord"
  CAT_DOMAINS["CUSTOM"]=""

  CAT_KEYS=( "GEMINI" "GPT" "CLAUDE" "YOUTUBE" "GOOGLE" "X" "INSTAGRAM" "TELEGRAM" "REDDIT" "DISCORD" "NETFLIX" "TIKTOK" "CUSTOM" )
  CAT_NAMES=( "Gemini" "GPT/ChatGPT" "Claude" "YouTube" "Google" "Twitter/X" "Instagram" "Telegram" "Reddit" "Discord" "Netflix" "TikTok" "自定义域名/IP" )

  echo -e "\n${C_CYAN}=== 第三步：选择要分流的分类 (多选) ===${C_RESET}"
  local k=0
  for name in "${CAT_NAMES[@]}"; do
    k=$((k+1))
    echo -e " ${C_GREEN}[$k]${C_RESET} ${C_YELLOW}${name}${C_RESET}"
  done
  echo -e " ${C_GREEN}[g]${C_RESET} ${C_PURPLE}全局流量 (该入站所有流量都走该落地)${C_RESET}"
  echo -e " ${C_GREEN}[a]${C_RESET} 全选"
  read -rp "请选择 (支持 g/a/数字, 逗号分隔): " sel_raw
  [[ -z "${sel_raw:-}" || "$sel_raw" == "0" ]] && return

  # --- 5) 写规则：先清理该 inbound 旧的 media-split 规则，再写入新规则 ---
  # 说明：全局规则只要匹配 inbound 即可（无 domain 字段），而且要放最前面，确保优先生效。
  local new_rules_jq='
    .route.rules as $r
    | .route.rules = (
        # 先删掉这个 inbound 之前的 media-split-* 规则
        ($r | map(select(.inbound? != null)) | . ) as $tmp
        | ($r | map(
            if ((.inbound|type)=="array" and (.inbound|index($inb))!=null and (.kind?//"")|startswith("media-split-"))
            then empty
            else .
            end
          )) as $clean
        | $clean
      )
  '
  safe_json_edit "$CONFIG" "$new_rules_jq" --arg inb "$selected_inbound" >/dev/null 2>&1 || true

  # 解析选择
  local want_global=0
  if echo "$sel_raw" | grep -qiE '(^|,)\s*g\s*(,|$)'; then
    want_global=1
  fi

  if [[ "$want_global" == "1" ]]; then
    echo -e "➜ 全局代理：${C_YELLOW}${selected_inbound}${C_RESET} -> ${C_GREEN}${selected_outbound_tag}${C_RESET}"

    # 构建全局规则，并放到 rules 最前面
    local global_rule
    global_rule=$(jq -n --arg inb "$selected_inbound" --arg out "$selected_outbound_tag" \
      '{inbound: [$inb], outbound: $out, kind: "media-split-GLOBAL"}')

    safe_json_edit "$CONFIG" '
      .route.rules = ([ $rule ] + (.route.rules // []))
    ' --argjson rule "$global_rule" >/dev/null 2>&1 || true

    ok "规则已写入：${selected_inbound} -> ${selected_outbound_tag}"
    restart_xray
    return
  fi

  # 分类模式
  local -a selected_nums=()
  if echo "$sel_raw" | grep -qiE '(^|,)\s*a\s*(,|$)'; then
    # 全选 -> 1..N
    local n="${#CAT_KEYS[@]}"
    for ((x=1; x<=n; x++)); do selected_nums+=("$x"); done
  else
    IFS=',' read -ra parts <<<"$sel_raw"
    for p in "${parts[@]}"; do
      p="$(echo "$p" | tr -d '[:space:]')"
      [[ "$p" =~ ^[0-9]+$ ]] && selected_nums+=("$p")
    done
  fi

  # 逐个写入分类规则（插入到最前面：比其他泛规则更优先）
  for num in "${selected_nums[@]}"; do
    local idx0=$((num-1))
    [[ $idx0 -lt 0 || $idx0 -ge ${#CAT_KEYS[@]} ]] && continue

    local key="${CAT_KEYS[$idx0]}"
    local name="${CAT_NAMES[$idx0]}"

    if [[ "$key" == "CUSTOM" ]]; then
      read -rp "请输入自定义域名/IP (空格分隔，支持 domain:xxx / ip:1.2.3.4 / geosite:xxx): " custom
      [[ -z "$custom" ]] && continue
      CAT_DOMAINS["CUSTOM"]="$custom"
    fi

    local domains="${CAT_DOMAINS[$key]}"
    [[ -z "$domains" ]] && continue

    # domains 字符串拆成数组（按空格）
    local dom_json
    dom_json=$(printf "%s\n" $domains | jq -R -s 'split("\n") | map(select(length>0))')

    local rule
    rule=$(jq -n --arg inb "$selected_inbound" --arg out "$selected_outbound_tag" --arg kind "media-split-$key" --argjson dom "$dom_json" \
      '{inbound: [$inb], outbound: $out, domain: $dom, kind: $kind}')

    echo -e "➜ 分类分流：${C_YELLOW}${selected_inbound}${C_RESET}  ${C_GRAY}(${name})${C_RESET} -> ${C_GREEN}${selected_outbound_tag}${C_RESET}"

    safe_json_edit "$CONFIG" '
      .route.rules = ([ $rule ] + (.route.rules // []))
    ' --argjson rule "$rule" >/dev/null 2>&1 || true
  done

  ok "分类规则写入完成：${selected_inbound} -> ${selected_outbound_tag}"
  restart_xray
}

# ============= 新增：TC 端口级限速核心逻辑 (兼容 Alpine/BusyBox + 无警告终极版) =============
apply_port_limits() {
    # 依赖检查：确保 tc 命令存在
    if ! command -v tc >/dev/null 2>&1; then
        apt-get install -y iproute2 >/dev/null 2>&1 || yum install -y iproute >/dev/null 2>&1 || apk add --no-cache iproute2 >/dev/null 2>&1
    fi

    # 获取服务器主公网网卡名称 (采用 awk，完美兼容 BusyBox 环境)
    local iface
    iface=$(ip -4 route ls 2>/dev/null | awk '/^default/ {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')
    [[ -z "$iface" ]] && return

    # 清除旧的限速规则，避免叠加报错
    tc qdisc del dev "$iface" root 2>/dev/null

    # 读取 Meta 数据，过滤出所有设置了 speed_limit 的节点
    local limits
    limits=$(jq -r 'to_entries[]? | select(.value.speed_limit != null) | "\(.value.port):\(.value.speed_limit)"' "$META" 2>/dev/null)
    
    # 如果没有任何限速配置，直接返回
    [[ -z "$limits" ]] && return

    # 建立根队列 (HTB) 和默认无限制流量类 (追加 2>/dev/null 屏蔽大带宽 quantum 警告)
    tc qdisc add dev "$iface" root handle 1: htb default 10 2>/dev/null
    tc class add dev "$iface" parent 1: classid 1:10 htb rate 10000mbit 2>/dev/null

    local class_id=11
    for limit in $limits; do
        local port="${limit%%:*}"
        local speed="${limit##*:}" # Mbps
        
        [[ -z "$port" || "$port" == "null" ]] && continue

        # 为该端口创建限速子类 (屏蔽 quantum 警告)
        tc class add dev "$iface" parent 1: classid 1:$class_id htb rate "${speed}mbit" 2>/dev/null

        # 区分 IPv4 (prio 1) 和 IPv6 (prio 2) 的优先级，防止内核冲突报错
        tc filter add dev "$iface" protocol ip parent 1:0 prio 1 u32 match ip sport "$port" 0xffff flowid 1:$class_id 2>/dev/null
        tc filter add dev "$iface" protocol ipv6 parent 1:0 prio 2 u32 match ip6 sport "$port" 0xffff flowid 1:$class_id 2>/dev/null

        class_id=$((class_id + 1))
    done
}

# ============= 新增：节点限速管理 UI =============
node_speed_limit_menu() {
    echo -e "\n${C_CYAN}=== 节点限速管理 (单节点下载限速) ===${C_RESET}"
    echo -e "${C_GRAY}说明：基于系统底层的流量控制，对公网直连节点(VLESS/SS/Hy2等)生效。${C_RESET}\n"
    
    # 聚合所有节点标签
    local tags_raw=""
    [[ -f "$CONFIG" ]] && tags_raw+=$(jq -r '.inbounds[].tag // empty' "$CONFIG" 2>/dev/null)
    [[ -f "$META" ]] && tags_raw+=$'\n'$(jq -r 'keys[]' "$META" 2>/dev/null)
    mapfile -t ALL_TAGS < <(echo "$tags_raw" | grep -v '^$' | sort -u)

    if [ ${#ALL_TAGS[@]} -eq 0 ]; then
        warn "当前没有任何节点。"
        read -rp "按回车返回..." _
        return
    fi

    local i=0
    for tag in "${ALL_TAGS[@]}"; do
        i=$((i+1))
        local port
        port=$(jq -r --arg t "$tag" '.[$t].port // empty' "$META" 2>/dev/null)
        [[ -z "$port" || "$port" == "null" ]] && port=$(jq -r --arg t "$tag" '.inbounds[]? | select(.tag == $t) | (.port // .listen_port) // empty' "$CONFIG" 2>/dev/null)
        
        local speed
        speed=$(jq -r --arg t "$tag" '.[$t].speed_limit // "无限制"' "$META" 2>/dev/null)
        
        echo -e " ${C_GREEN}[$i]${C_RESET} ${C_YELLOW}${tag}${C_RESET} (端口: ${port}) -> 当前限速: ${C_PURPLE}${speed}${C_RESET} ${C_GRAY}Mbps${C_RESET}"
    done
    echo -e " ${C_GREEN}[0]${C_RESET} 取消返回"

    read -rp "请选择要限速的节点序号: " choice
    [[ "$choice" == "0" || -z "$choice" ]] && return
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "$i" ]; then
        warn "无效序号"
        return
    fi

    local target_tag="${ALL_TAGS[$((choice-1))]}"
    
    echo -e "\n正在设置节点: ${C_YELLOW}${target_tag}${C_RESET}"
    read -rp "请输入最高下载速度 (单位 Mbps, 输入 0 解除限速): " speed_limit
    
    if [[ ! "$speed_limit" =~ ^[0-9]+$ ]]; then
        warn "输入无效，必须为纯正整数。"
        return
    fi

    if [[ "$speed_limit" == "0" ]]; then
        safe_json_edit "$META" 'del(.[$tag].speed_limit)' --arg tag "$target_tag"
        ok "已解除节点 [${target_tag}] 的限速限制。"
    else
        safe_json_edit "$META" '. + {($tag): (.[$tag] + {"speed_limit": $limit})}' --arg tag "$target_tag" --argjson limit "$speed_limit"
        ok "已成功设置节点 [${target_tag}] 限速为 ${speed_limit} Mbps。"
    fi
    
    apply_port_limits
    read -rp "按回车返回..." _
}

# ============= 启动前最后的自动化加固 =============

# ============= 启动前最后的自动化加固 =============
say "正在同步系统时间..."
if command -v ntpdate >/dev/null 2>&1; then
    ntpdate -u pool.ntp.org >/dev/null 2>&1
else
    # 核心修复：删掉前面的 local 关键字
    remote_date=$(curl -sI https://www.google.com | grep -i '^date:' | cut -d' ' -f2-7)
    [[ -n "$remote_date" ]] && date -s "$remote_date" >/dev/null 2>&1
fi

# 2. 强制路径对齐 (彻底解决 "open config.json: no such file" 报错)
# 确保 systemd 指向的路径永远有效
mkdir -p /usr/local/etc/xray /etc/xray
ln -sf /etc/xray/xray_config.json /usr/local/etc/xray/config.json

# 3. 异步 IP 探测 (V4/V6 双栈探测增强)
if [[ ! -f "$IP_CACHE_FILE" ]]; then
    (
        curl -s -4 --connect-timeout 2 https://api.ipify.org > "$IP_CACHE_FILE" 2>/dev/null
        curl -s -6 --connect-timeout 2 https://api64.ipify.org > "${IP_CACHE_FILE}_v6" 2>/dev/null
    ) &
fi

# 4. 自动挂载守护进程 (无人值守模式)
# 增加 crontab 命令存在性检查，防止在极简版系统报错
if command -v crontab >/dev/null 2>&1; then
    if ! crontab -l 2>/dev/null | grep -q "xray-singleton"; then
        say "正在开启无人值守守护模式..."
        install_watchdog_cron
    fi
fi

# 5. 执行一次强制同步，确保 api 标签等闭环逻辑已写入
# 这一步是预防你之前遇到的 outbound 缺失导致的 status=23 错误
/usr/local/bin/xray-sync >/dev/null 2>&1 || true


main_menu() {
  while true; do
    # 核心：如果发现 Xray 锁定了 IP 但探测结果还没出来，就尝试触发一次探测
    local pref="$(_get_global_mode)"
    local lock_ip="$(_read_global_lock_ip_for_pref "$pref")"

    if [[ -n "$lock_ip" && ! -f "${IP_CACHE_FILE}_xray_status" ]]; then
        update_ip_async
    fi
    show_menu_banner
    echo -e ""
    echo -e " ${C_GREEN}1.${C_RESET} 添加节点 "
    echo -e " ${C_GREEN}2.${C_RESET} 查看节点 "
    echo -e " ${C_GREEN}3.${C_RESET} 删除节点 "
    echo -e " ${C_GREEN}4.${C_RESET} 状态维护 "
    echo -e " ${C_GREEN}5.${C_RESET} 网络切换 "
    echo -e " ${C_GREEN}6.${C_RESET} 落地出口 "
    echo -e " ${C_GREEN}7.${C_RESET} 节点限速 ${C_YELLOW}(New)${C_RESET}" # 👈 新增这一行
    echo -e " ${C_GREEN}0.${C_RESET} 退出脚本"
    echo -e ""
    echo -e "${C_BLUE}──────────────────────────────────────────────────────────────${C_RESET}"
    
    if ! safe_read choice " 请输入选项 [0-7]: "; then # 👈 注意改成 0-7
      echo
      exit 0
    fi
    
    case "$choice" in
      1) add_node ;;
      2) view_nodes_menu ;;
      3) delete_node ;;
      4) status_menu ;;
      5) ip_version_menu ;;
      6) outbound_menu ;;
      7) node_speed_limit_menu ;; # 👈 新增触发函数
      0) exit 0 ;;
      *) warn "无效输入" ;;
    esac
  done
}


setup_shortcuts() {
  local SCRIPT_PATH
  SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null)"
  [[ -z "$SCRIPT_PATH" ]] && SCRIPT_PATH="$PWD/$(basename "$0")"

  if [[ ! -f /root/.bashrc ]]; then touch /root/.bashrc; fi

  # 自动同步别名
  sed -i '/alias my=/d; /alias MY=/d' /root/.bashrc
  echo "alias my='$SCRIPT_PATH'" >> /root/.bashrc
  echo "alias MY='$SCRIPT_PATH'" >> /root/.bashrc
}

# 启动执行流程
setup_shortcuts

# 环境基础检查
if [[ ! -x "/usr/local/bin/xray" ]] || [[ ! -f "$CONFIG" ]]; then
    echo -e "${C_PURPLE}检测到环境缺失，正在初始化...${C_RESET}"
    ensure_dirs
    install_dependencies
    enable_bbr
    install_xray_if_needed
fi

# 触发一次同步，确保配置文件路径和逻辑闭环生效
/usr/local/bin/xray-sync >/dev/null 2>&1 || true

update_ip_async
load_nat_data
auto_optimize_cpu

# 最终进入主菜单
main_menu
