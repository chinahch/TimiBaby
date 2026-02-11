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

# ============= IP 策略状态翻译工具 (修复版) =============

# 1. 核心翻译逻辑 (兼容两种函数名)
_mode_label() { _ip_mode_desc "$1"; }

_ip_mode_desc() {
  case "${1:-}" in
    v4pref) echo "优选IPv4(回退IPv6)" ;;
    v6pref) echo "优选IPv6(回退IPv4+失败域名走v4)" ;;
    v4only) echo "IPv4 only(完全不用IPv6)" ;;
    v6only) echo "IPv6 only(完全不用IPv4)" ;;
    off)    echo "已停止(不干预IP版本)" ;;
    follow_global|follow|"(未设置)"|"") echo "跟随全局" ;;
    *)      echo "$1" ;;
  esac
}

# 2. 读取全局配置文件
_get_global_mode() {
  local pref
  # 读取 /etc/xray/ip_pref 文件的内容
  pref="$(head -n 1 /etc/xray/ip_pref 2>/dev/null | tr -d '\r\n ' || true)"
  [[ -z "$pref" || "$pref" == "(未设置)" ]] && pref="follow_global"
  echo "$pref"
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


# 节点侧：如果是 SOCKS 入站，做一次最小可用性探测（避免“切到 only 后连节点都不通”）
_probe_socks_inbound() {
  local tag="$1" mode="$2"
  local cfg="${XRAY_CONFIG:-/etc/xray/xray_config.json}"

  # 仅在配置存在时探测
  [[ -s "$cfg" ]] || return 0

  local port auth user pass
  port="$(jq -r --arg t "$tag" '.inbounds[]? | select(.tag==$t) | .port // empty' "$cfg" 2>/dev/null | head -n1)"
  auth="$(jq -r --arg t "$tag" '.inbounds[]? | select(.tag==$t) | .settings.auth // "noauth"' "$cfg" 2>/dev/null | head -n1)"
  user="$(jq -r --arg t "$tag" '.inbounds[]? | select(.tag==$t) | .settings.accounts[0].user // empty' "$cfg" 2>/dev/null | head -n1)"
  pass="$(jq -r --arg t "$tag" '.inbounds[]? | select(.tag==$t) | .settings.accounts[0].pass // empty' "$cfg" 2>/dev/null | head -n1)"

  [[ -n "${port:-}" ]] || return 0

  # 先确认端口在监听（tcp4/tcp6 任一都算）
  if command -v ss >/dev/null 2>&1; then
    ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:\.]${port}\b" || return 2
  fi

  # only 模式最容易翻车：做一次真正代理请求
  local url="https://api.ipify.org"
  case "$mode" in
    v6* ) url="https://api64.ipify.org" ;;
  esac

  local px=""
  if [[ "$auth" == "password" && -n "${user:-}" && -n "${pass:-}" ]]; then
    px="socks5h://${user}:${pass}@127.0.0.1:${port}"
  else
    px="socks5h://127.0.0.1:${port}"
  fi

  # 只要能拿到一个像样的 IP（4 或 6），就算通过
  local out
  out="$(curl -sS --connect-timeout 3 --max-time 6 -x "$px" "$url" 2>/dev/null | tr -d '\r\n')"
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
    # 增加简单的运行锁，防止重复启动探测进程
    local lock="/tmp/ip_probe.lock"
    if [[ -f "$lock" ]]; then
        local pid=$(cat "$lock" 2>/dev/null)
        if [[ -n "$pid" ]] && ps -p "$pid" >/dev/null 2>&1; then return 0; fi
    fi
    echo $$ > "$lock"

    (
        # 1. 系统原生 IP 探测
        local ip4; ip4=$(curl -s -4 --connect-timeout 2 --max-time 5 https://api.ipify.org 2>/dev/null | tr -d '\r\n')
        [[ -n "$ip4" ]] && echo -n "$ip4" > "$IP_CACHE_FILE"
        
        local ip6; ip6=$(curl -s -6 --connect-timeout 2 --max-time 5 https://api64.ipify.org 2>/dev/null | tr -d '\r\n')
        [[ -n "$ip6" ]] && echo -n "$ip6" > "${IP_CACHE_FILE}_v6"

        # 2. Xray 出口探测
        local pref; pref=$(cat /etc/xray/ip_pref 2>/dev/null || echo "v4")
        local lock_ip=""
        [[ "$pref" == "v6" ]] && lock_ip=$(cat /etc/xray/global_egress_ip_v6 2>/dev/null | tr -d '\r\n ')
        [[ "$pref" == "v4" ]] && lock_ip=$(cat /etc/xray/global_egress_ip_v4 2>/dev/null | tr -d '\r\n ')

        if [[ -n "$lock_ip" ]]; then
            local xray_pub=""
            # 探测逻辑：优先尝试绑定 IP 探测
            if [[ "$pref" == "v6" ]]; then
                xray_pub=$(curl -s -6 --interface "$lock_ip" --connect-timeout 3 --max-time 6 https://api64.ipify.org 2>/dev/null | tr -d '\r\n')
            else
                xray_pub=$(curl -s -4 --interface "$lock_ip" --connect-timeout 3 --max-time 6 https://api.ipify.org 2>/dev/null | tr -d '\r\n')
            fi

            if [[ -n "$xray_pub" ]]; then
                echo -n "$xray_pub" > "${IP_CACHE_FILE}_xray"
                echo -n "OK" > "${IP_CACHE_FILE}_xray_status"
            else
                echo -n "FAILED" > "${IP_CACHE_FILE}_xray_status"
                echo -n "N/A" > "${IP_CACHE_FILE}_xray"
            fi
        fi
        rm -f "$lock"
    ) &
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
get_country_name_zh() {
  local ip; ip=$(get_public_ipv4_ensure)
  local country; country=$(curl -s -4 --connect-timeout 2 --max-time 3 "http://ip-api.com/json/${ip}?fields=country&lang=zh-CN" | jq -r '.country // "未知"')
  echo -n "$country"
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




# 系统状态 Dashboard (支持显示网卡名称)
get_sys_status() {
    local cpu_load=$(awk '{print $1}' /proc/loadavg 2>/dev/null)
    local mem_total=$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null)
    local mem_free=$(awk '/MemAvailable/ {printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null)
    local mem_used=$((mem_total - mem_free))
    local mem_rate=0
    [[ $mem_total -gt 0 ]] && mem_rate=$((mem_used * 100 / mem_total))
    
    # 获取原生 IP 缓存
    local sys_ip4="未检测到"; [[ -f "$IP_CACHE_FILE" ]] && sys_ip4=$(cat "$IP_CACHE_FILE")
    local sys_ip6="未检测到"; [[ -f "${IP_CACHE_FILE}_v6" ]] && sys_ip6=$(cat "${IP_CACHE_FILE}_v6")

    # Xray 出口状态逻辑
    local pref; pref=$(cat /etc/xray/ip_pref 2>/dev/null | tr -d '\r\n ' || echo "v4")
    local lock_ip=""; [[ "$pref" == "v6" ]] && lock_ip=$(cat /etc/xray/global_egress_ip_v6 2>/dev/null) || lock_ip=$(cat /etc/xray/global_egress_ip_v4 2>/dev/null)
    
    local xray_egress="跟随系统 (默认)"
    if [[ -n "$lock_ip" ]]; then
        # 核心修改：根据锁定 IP 反查网卡名称
        local iface_name; iface_name=$(ip -o addr show | grep "$lock_ip" | awk '{print $2}' | head -n1)
        [[ -z "$iface_name" ]] && iface_name="未知"

        local real_pub="获取中..."
        [[ -f "${IP_CACHE_FILE}_xray" ]] && real_pub=$(cat "${IP_CACHE_FILE}_xray")
        
        local status="CHECKING"
        [[ -f "${IP_CACHE_FILE}_xray_status" ]] && status=$(cat "${IP_CACHE_FILE}_xray_status")

        # 纠正版本错位显示
        if [[ "$pref" == "v4" && "$real_pub" == *:* ]]; then real_pub="获取中..."; fi
        if [[ "$pref" == "v6" && "$real_pub" == *.* ]]; then real_pub="获取中..."; fi

        local cc="??"
        [[ "$real_pub" != "获取中..." && "$real_pub" != "N/A" ]] && cc=$(get_ip_country "$real_pub")

        local status_disp="${C_YELLOW}[检测中]${C_RESET}"
        if [[ "$status" == "OK" ]]; then
            status_disp="${C_GREEN}[正常]${C_RESET}"
        elif [[ "$status" == "FAILED" ]]; then
            status_disp="${C_RED}[失效]${C_RESET}"
            real_pub="N/A"
        fi

        # 最终显示行：显示网卡名 (iface_name)
        xray_egress="${C_GREEN}${real_pub}${C_RESET} ${C_PURPLE}[${cc}]${C_RESET} ${C_GRAY}(src:${iface_name})${C_RESET} ${status_disp}"
    fi

    local color_cpu="$C_GREEN"
    if awk -v l="$cpu_load" 'BEGIN{exit (l>2.0)?0:1}' >/dev/null 2>&1; then color_cpu="$C_YELLOW"; fi
    local color_mem="$C_GREEN"; [[ $mem_rate -ge 80 ]] && color_mem="$C_YELLOW"

    echo -e "${C_BLUE}┌──[ 系统监控 ]────────────────────────────────────────────────┐${C_RESET}"
    echo -e "${C_BLUE}│${C_RESET} CPU: ${color_cpu}${cpu_load}${C_RESET} | 内存: ${color_mem}${mem_used}MB/${mem_total}MB (${mem_rate}%)${C_RESET}"
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

  # === 全局 IP 偏好 -> freedom.domainStrategy ===
  local pref ds
  pref="$(cat /etc/xray/ip_pref 2>/dev/null | tr -d '
 ' || true)"
  case "$pref" in
    off)       ds="AsIs"      ;;  # 停止全局策略：不干预（让节点策略/默认行为决定）
    v6pref|v6) ds="UseIPv6v4" ;;  # IPv6优选 + 可回退IPv4（不断网）
    v4pref|v4) ds="UseIPv4v6" ;;  # IPv4优选 + 可回退IPv6
    v6only)    ds="UseIPv6" ;;  # 真全局 IPv6 only
    v4only)    ds="UseIPv4" ;;  # 真全局 IPv4 only
    *)         ds="AsIs"      ;;  # 未设置：不强行改策略
  esac

  # === META（用于单节点 ip_mode）===
  local meta_json="{}"
  if [[ -s "$META" ]]; then
    meta_json="$(cat "$META" 2>/dev/null || echo '{}')"
  fi

  # === v6pref：强制 IPv4 域名名单（全局 v6pref 或 任意节点 v6pref 时启用）===
  local fvd_json="[]"
  local need_fvd=0
  if [[ "$pref" == "v6pref" || "$pref" == "v6" ]]; then
    need_fvd=1
  else
    if [[ -s "$META" ]] && jq -e 'to_entries | any(.value.ip_mode=="v6pref")' "$META" >/dev/null 2>&1; then
      need_fvd=1
    fi
  fi

  if [[ "$need_fvd" == "1" ]]; then
    mkdir -p /etc/xray >/dev/null 2>&1 || true
    if [[ ! -s /etc/xray/force_v4_domains.txt ]]; then
      cat >/etc/xray/force_v4_domains.txt <<'EOF'
discord.com
x.com
openai.com
EOF
    fi

    # 生成 ["domain:discord.com","domain:x.com", ...]
    fvd_json="$(
      awk '
        {gsub("
","");}
        NF && $0 !~ /^[[:space:]]*#/ {print "domain:"$0}
      ' /etc/xray/force_v4_domains.txt \
      | jq -Rsc 'split("
") | map(select(length>0))'
    )"
  fi

  jq --arg log "$log_path" \
     --arg ds "$ds" \
     --arg pref "$pref" \
     --argjson fvd "$fvd_json" \
     --argjson meta "$meta_json" '
    def _listen: (.listen // "::");
    def _port: ((.listen_port // .port // 0) | tonumber);

    # ---------------- Inbounds ----------------
    def mk_inbound:
      if .type == "socks" then
        {
          tag: (.tag // "socks-in"),
          listen: _listen,
          port: _port,
          protocol: "socks",
          settings: {
            auth: (if ((.users // []) | length) > 0 then "password" else "noauth" end),
            accounts: ((.users // []) | map({user: .username, pass: .password})),
            udp: true
          },
          sniffing: { enabled: true, destOverride: ["http", "tls"] }
        }
      elif .type == "vless" then
        {
          tag: (.tag // "vless-in"),
          listen: _listen,
          port: _port,
          protocol: "vless",
          settings: {
            clients: ((.users // []) | map({id: (.uuid // .id // ""), flow: (.flow // empty)})),
            decryption: "none"
          },
          streamSettings: {
            network: "tcp",
            security: "reality",
            realitySettings: {
              show: false,
              dest: (((.tls.reality.handshake.server // .tls.server_name // "www.microsoft.com") | tostring)
                     + ":" +
                     (((.tls.reality.handshake.server_port // 443) | tonumber) | tostring)),
              xver: 0,
              serverNames: [(.tls.server_name // .tls.reality.handshake.server // "www.microsoft.com")],
              privateKey: (.tls.reality.private_key // ""),
              shortIds: (.tls.reality.short_id // [])
            }
          },
          sniffing: { enabled: true, destOverride: ["http", "tls"] }
        }
      else
        empty
      end;

    # ---------------- Outbounds ----------------
    def mk_outbound:
      if .type == "direct" then
        (
          { protocol: "freedom", tag: (.tag // "direct"), settings: { domainStrategy: $ds } }
          + (if ((.sendThrough // .send_through // "") | length) > 0
             then { sendThrough: (.sendThrough // .send_through) }
             else {}
            end)
        )
      elif .type == "socks" then
        {
          protocol: "socks",
          tag: (.tag // "socks-out"),
          settings: {
            servers: [{
              address: (.server // ""),
              port: ((.server_port // 0) | tonumber),
              users: (if ((.username // "") != "" and (.password // "") != "")
                      then [{user: .username, pass: .password}]
                      else []
                     end)
            }]
          }
        }
      elif .type == "shadowsocks" then
        {
          protocol: "shadowsocks",
          tag: (.tag // "ss-out"),
          settings: {
            servers: [{
              address: (.server // ""),
              port: ((.server_port // 0) | tonumber),
              method: (.method // "aes-256-gcm"),
              password: (.password // "")
            }]
          }
        }
      elif .type == "vless" then
        {
          protocol: "vless",
          tag: (.tag // "vless-out"),
          settings: {
            vnext: [{
              address: (.server // ""),
              port: ((.server_port // 0) | tonumber),
              users: [{
                id: (.uuid // .id // ""),
                encryption: "none",
                flow: (.flow // empty)
              }]
            }]
          },
          streamSettings: {
            network: (.transport.type // .network // "tcp"),
            security: (if ((.tls.reality.public_key // .pbk // "") != "") then "reality" else "none" end),
            realitySettings: (if ((.tls.reality.public_key // .pbk // "") != "") then {
              show: false,
              fingerprint: (.tls.utls.fingerprint // .fp // "chrome"),
              serverName: (.tls.server_name // .sni // "www.microsoft.com"),
              publicKey: (.tls.reality.public_key // .pbk // ""),
              shortId: (if ((.tls.reality.short_id // []) | length) > 0
                        then (.tls.reality.short_id[0] | tostring)
                        else (.sid // "")
                       end),
              spiderX: "/"
            } else empty end),
            tcpSettings: (if ((.transport.type // .network // "tcp") == "tcp")
                          then { header: { type: (.transport.header_type // .headerType // "none") } }
                          else empty
                         end)
          }
        }
      elif .type == "vmess" then
        {
          protocol: "vmess",
          tag: (.tag // "vmess-out"),
          settings: {
            vnext: [{
              address: (.server // ""),
              port: ((.server_port // 0) | tonumber),
              users: [{
                id: (.uuid // .id // ""),
                security: "auto",
                alterId: 0
              }]
            }]
          },
          streamSettings: {
            network: (.transport.type // .network // "tcp"),
            security: (if (.tls.enabled == true or .tls != null) then "tls" else "none" end),
            tlsSettings: (if (.tls.enabled == true or .tls != null)
                          then { serverName: (.tls.server_name // .sni // ""), allowInsecure: true }
                          else empty
                         end),
            wsSettings: (if (.transport.type == "ws")
                         then { path: (.transport.ws_settings.path // ""), headers: { Host: (.transport.ws_settings.headers.Host // "") } }
                         else empty
                        end)
          }
        }
      else
        { protocol: "freedom", tag: (.tag // "direct"), settings: { domainStrategy: $ds } }
      end;

    # --- 单节点 ip_mode：把「规则里 outboundTag=direct」按 inboundTag 映射到不同 direct-* ---
    def _mode_for(t): ($meta[t].ip_mode // empty);
    def _direct_tag(m):
      if m=="v6pref" then "direct-v6pref"
      elif m=="v4pref" then "direct-v4pref"
      elif m=="v6only" then "direct-v6only"
      elif m=="v4only" then "direct-v4only"
      else "direct" end;
    def _map_outbound(ob; inb):
      if ob!="direct" then ob
      elif (inb|length)==1 then _direct_tag(_mode_for(inb[0]))
      else ob end;

    # ---------------- Routing rules (支持 domain 分流) ----------------
    def mk_rule:
      (
        (if (.inbound | type) == "array" then .inbound else [(.inbound // empty)] end) as $inb
        | (
          {
            type: "field",
            outboundTag: _map_outbound((.outbound // "direct"); $inb),
            inboundTag: $inb
          }
          +
          (if (.domain? != null)
            then { domain: (if (.domain|type)=="array" then .domain else [(.domain|tostring)] end) }
            else {}
           end)
          +
          (if (.ip? != null)
            then { ip: (if (.ip|type)=="array" then .ip else [(.ip|tostring)] end) }
            else {}
           end)
          +
          (if (.port? != null)
            then { port: (if (.port|type)=="array" then .port else [(.port|tostring)] end) }
            else {}
           end)
          +
          (if (.protocol? != null)
            then { protocol: (if (.protocol|type)=="array" then .protocol else [(.protocol|tostring)] end) }
            else {}
           end)
        )
      );

    . as $root
    | (
        {
          log: { loglevel: "warning", access: $log, error: $log },
          inbounds: ((($root.inbounds // []) | map(mk_inbound)) // []),
          outbounds:
            (
              (($root.outbounds // []) | map(mk_outbound))
              | (if (map(select(.tag=="direct")) | length) == 0
                 then . + [{protocol:"freedom", tag:"direct", settings:{domainStrategy:$ds}}]
                 else .
                end)
              | (if (map(select(.tag=="block")) | length) == 0 then . + [{protocol:"blackhole", tag:"block", settings:{}}] else . end)
              | (if (map(select(.tag=="direct-v6pref")) | length) == 0
                 then . + [{protocol:"freedom", tag:"direct-v6pref", settings:{domainStrategy:"UseIPv6v4"}}]
                 else .
                end)
              | (if (map(select(.tag=="direct-v4pref")) | length) == 0
                 then . + [{protocol:"freedom", tag:"direct-v4pref", settings:{domainStrategy:"UseIPv4v6"}}]
                 else .
                end)
              | (if (map(select(.tag=="direct-v6only")) | length) == 0
                 then . + [{protocol:"freedom", tag:"direct-v6only", settings:{domainStrategy:"UseIPv6"}}]
                 else .
                end)
              | (if (map(select(.tag=="direct-v4only")) | length) == 0
                 then . + [{protocol:"freedom", tag:"direct-v4only", settings:{domainStrategy:"UseIPv4"}}]
                 else .
                end)
              | (if (map(select(.tag=="direct-v4")) | length) == 0
                 then . + [{protocol:"freedom", tag:"direct-v4", settings:{domainStrategy:"UseIPv4"}}]
                 else .
                end)
            ),
          routing: {
            domainStrategy: $ds,
            rules: (
              (($root.route.rules // []) | map(mk_rule))
              + (
                  ($root.inbounds // [])
                  | map(.tag // empty) | map(select(length>0)) | unique
                  | map((.) as $t | (_mode_for($t)) as $m
                        | if $m=="v6only" then {type:"field", inboundTag:[$t], ip:["0.0.0.0/0"], outboundTag:"block"}
                          elif $m=="v4only" then {type:"field", inboundTag:[$t], ip:["::/0"], outboundTag:"block"}
                          else empty end)
                  | map(select(. != null))
                )
              + (
                  ($root.inbounds // [])
                  | map(.tag // empty) | map(select(length>0)) | unique
                  | map({type:"field", inboundTag:[.], outboundTag:_direct_tag(_mode_for(.))})
                )
            )
          }
        }
        # --- v6pref：强制v4域名规则（全局 v6pref 或 单节点 v6pref 生效）---
        | if (($fvd|type=="array") and (($fvd|length) > 0)) then
            .routing.rules = (
              (if ($pref=="v6pref" or $pref=="v6")
                then [ {type:"field", domain:$fvd, outboundTag:"direct-v4"} ]
                else []
               end)
              + (
                ($meta | to_entries
                  | map(select(.value.ip_mode=="v6pref"))
                  | map({type:"field", inboundTag:[.key], domain:$fvd, outboundTag:"direct-v4"})
                )
              )
              + (.routing.rules // [])
            )
          else .
          end
      )
  ' "$model_cfg" > "$out_cfg"
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

  # 依赖清单：补上 unzip（Xray zip 解压必须）
  local need=(curl jq uuidgen openssl ss lsof unzip)

  # 已齐全则不做任何 update/install
  local all_exist=1
  for c in "${need[@]}"; do
    if ! command -v "$c" >/dev/null 2>&1; then all_exist=0; break; fi
  done
  if (( all_exist == 1 )); then
    DEPS_CHECKED=1
    return 0
  fi

  say "首次运行，正在补全依赖..."

  ensure_cmd curl     curl         curl        curl       curl
  ensure_cmd jq       jq           jq          jq         jq
  ensure_cmd uuidgen  uuid-runtime util-linux  util-linux util-linux
  ensure_cmd openssl  openssl      openssl     openssl    openssl
  ensure_cmd ss       iproute2     iproute2    iproute    iproute
  ensure_cmd lsof     lsof         lsof        lsof       lsof
  ensure_cmd unzip    unzip        unzip       unzip      unzip

  # 如果 Debian/Ubuntu 上因为「apt 缺 update」导致安装失败，这里统一补一次 update 并重试缺包
  if [[ "${OS_ID:-}" =~ ^(debian|ubuntu)$ ]] && ((${#_APT_RETRY_PKGS[@]} > 0)); then
    warn "检测到 apt 安装可能因未 update 失败：补一次 apt-get update 后重试安装：${_APT_RETRY_PKGS[*]}"
    apt-get update -y >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${_APT_RETRY_PKGS[@]}" >/dev/null 2>&1 || true
    _APT_RETRY_PKGS=()
  fi

  # 最终严格校验：缺哪个就报哪个（不再假成功）
  local missing=()
  for c in "${need[@]}"; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done

  if ((${#missing[@]} > 0)); then
    warn "仍有依赖缺失：${missing[*]}（请检查软件源/DNS/网络后重试）"
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
  local current_bin
  current_bin=$(_xray_bin)

  # 非强制且已存在则跳过
  if [[ "$1" != "--force" ]] && [[ -x "$current_bin" ]]; then
    return 0
  fi

  # 先确保 unzip/curl/jq 等依赖在（否则解压必炸）
  ensure_runtime_deps || { err "依赖未就绪，无法安装 Xray"; return 1; }

  # 获取最新版本（失败则保底）
  local LATEST_VER
  LATEST_VER=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name | sed 's/v//')
  [[ -z "$LATEST_VER" || "$LATEST_VER" == "null" ]] && LATEST_VER="1.8.24"

  warn "正在安装/更新 Xray 核心 v${LATEST_VER}..."

  local arch url
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64)   url="https://github.com/XTLS/Xray-core/releases/download/v${LATEST_VER}/Xray-linux-64.zip" ;;
    aarch64|arm64)  url="https://github.com/XTLS/Xray-core/releases/download/v${LATEST_VER}/Xray-linux-arm64-v8a.zip" ;;
    *) err "暂不支持的架构：$arch"; return 1 ;;
  esac

  local tmp; tmp="$(mktemp -d)"
  (
    set -e
    cd "$tmp"

    curl -fL -o xray.zip "$url"

    # 解压必须成功
    unzip -o xray.zip >/dev/null

    # 某些 zip 里可能是 ./xray 或 ./Xray，做个兼容探测
    local bin=""
    [[ -f "./xray" ]] && bin="./xray"
    [[ -z "$bin" && -f "./Xray" ]] && bin="./Xray"

    if [[ -z "$bin" ]]; then
      echo "zip 内容："
      ls -la
      exit 2
    fi

    # 1. 安装二进制主程序
    install -m 0755 "$bin" /usr/local/bin/xray

    # 2. 【新增】安装资源文件 (geosite.dat 和 geoip.dat)
    # 这样分流规则（如 geosite:tiktok）才能被内核正确解析
    if [[ -f "geosite.dat" ]]; then
      install -m 0644 "geosite.dat" /usr/local/bin/geosite.dat
    fi
    if [[ -f "geoip.dat" ]]; then
      install -m 0644 "geoip.dat" /usr/local/bin/geoip.dat
    fi
  )
  local rc=$?
  rm -rf "$tmp"

  if [[ $rc -ne 0 ]] || ! /usr/local/bin/xray version >/dev/null 2>&1; then
    err "Xray 安装失败（rc=$rc），请检查 unzip/网络/磁盘权限"
    return 1
  fi

  ok "Xray 核心及资源文件已就绪"
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
  CODE=$(curl -s --max-time 3 https://ipinfo.io | jq -r '.country // empty')
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

  # ========================================================
  # 1. 生成 xray-sync (修复版：支持 SS + 单节点 IP 模式 + IP 绑定)
  # ========================================================
  cat > /usr/local/bin/xray-sync <<'SYNC'
#!/usr/bin/env bash
set -euo pipefail
umask 022

XRAY_BASE_DIR="/etc/xray"
MODEL_CFG="${XRAY_BASE_DIR}/config.json"
META_CFG="${XRAY_BASE_DIR}/nodes_meta.json"
OUT_CFG="${XRAY_BASE_DIR}/xray_config.json"
LOG_PATH="/var/log/xray.log"

mkdir -p "$(dirname "$OUT_CFG")" "$(dirname "$LOG_PATH")" >/dev/null 2>&1 || true
[[ -f "$META_CFG" ]] || echo "{}" > "$META_CFG"

# --- 全局 IP 偏好设置 ---
PREF="$(cat "${XRAY_BASE_DIR}/ip_pref" 2>/dev/null | tr -d '\r\n ' || true)"
case "$PREF" in
  v6pref|v6) DS="UseIPv6v4" ;;
  v4pref|v4) DS="UseIPv4v6" ;;
  v6only)    DS="ForceIPv6" ;;
  v4only)    DS="ForceIPv4" ;;
  *)         DS="UseIPv6v4" ;;
esac

# --- 全局默认出口 IP ---
GLOBAL_IP=""
[[ "$PREF" == "v6only" ]] && GLOBAL_IP="$(cat "${XRAY_BASE_DIR}/global_egress_ip_v6" 2>/dev/null | tr -d '\r\n ' || true)"
[[ "$PREF" == "v4only" ]] && GLOBAL_IP="$(cat "${XRAY_BASE_DIR}/global_egress_ip_v4" 2>/dev/null | tr -d '\r\n ' || true)"

jq --arg log "$LOG_PATH" --arg ds "$DS" --arg gip "$GLOBAL_IP" --slurpfile meta "$META_CFG" '
  def _listen: (.listen // "::");
  def _port: ((.listen_port // .port // 0) | tonumber);

  # --- 映射模式到 Outbound Tag ---
  def _mode_tag(m):
    if m == "v6pref" then "direct-v6pref"
    elif m == "v4pref" then "direct-v4pref"
    elif m == "v6only" then "direct-v6only"
    elif m == "v4only" then "direct-v4only"
    else "direct" end;

  # --- Inbound 翻译 (新增 Shadowsocks 支持) ---
  def mk_inbound:
    if .type == "socks" then
      { tag: (.tag // "socks-in"), listen: _listen, port: _port, protocol: "socks",
        settings: { auth: (if ((.users // []) | length) > 0 then "password" else "noauth" end),
        accounts: ((.users // []) | map({user: .username, pass: .password})), udp: true },
        sniffing: { enabled: true, destOverride: ["http","tls"] } }
    elif .type == "shadowsocks" then
      { tag: (.tag // "ss-in"), listen: _listen, port: _port, protocol: "shadowsocks",
        settings: { method: (.method // "aes-256-gcm"), password: (.password // ""), network: "tcp,udp" },
        sniffing: { enabled: true, destOverride: ["http","tls"] } }
    elif .type == "vless" then
      { tag: (.tag // "vless-in"), listen: _listen, port: _port, protocol: "vless",
        settings: { clients: ((.users // []) | map({id: (.uuid // .id // ""), flow: (.flow // empty)})), decryption: "none" },
        streamSettings: { network: "tcp", security: "reality",
        realitySettings: { show: false, dest: (((.tls.reality.handshake.server // .tls.server_name // "www.microsoft.com") | tostring) + ":" + (((.tls.reality.handshake.server_port // 443) | tonumber) | tostring)),
        xver: 0, serverNames: [(.tls.server_name // .tls.reality.handshake.server // "www.microsoft.com")],
        privateKey: (.tls.reality.private_key // ""), shortIds: (.tls.reality.short_id // []) } },
        sniffing: { enabled: true, destOverride: ["http","tls"] } }
    else empty end;

  # --- Outbound 翻译 ---
  def mk_outbound:
    if .type == "direct" then
      { protocol: "freedom", tag: (.tag // "direct"), settings: { domainStrategy: $ds } }
      + (if ((.sendThrough // .send_through // "") | length) > 0 then { sendThrough: (.sendThrough // .send_through) } else {} end)
    elif .type == "socks" then
      { protocol: "socks", tag: (.tag // "socks-out"), settings: { servers: [{ address: (.server // ""), port: ((.server_port // 0) | tonumber),
        users: (if ((.username // "") != "" and (.password // "") != "") then [{user: .username, pass: .password}] else [] end) }] } }
    elif .type == "shadowsocks" then
      { protocol: "shadowsocks", tag: (.tag // "ss-out"), settings: { servers: [{ address: (.server // ""), port: ((.server_port // 0) | tonumber), method: (.method // "aes-256-gcm"), password: (.password // "") }] } }
    elif .type == "vless" then
      { protocol: "vless", tag: (.tag // "vless-out"), settings: { vnext: [{ address: (.server // ""), port: ((.server_port // 0) | tonumber), users: [{ id: (.uuid // .id // ""), encryption: "none", flow: (.flow // empty) }] }] },
        streamSettings: { network: (.transport.type // .network // "tcp"), security: (if ((.tls.reality.public_key // .pbk // "") != "") then "reality" else "none" end),
        realitySettings: (if ((.tls.reality.public_key // .pbk // "") != "") then { show: false, fingerprint: (.tls.utls.fingerprint // .fp // "chrome"), serverName: (.tls.server_name // .sni // "www.microsoft.com"), publicKey: (.tls.reality.public_key // .pbk // ""), shortId: (if ((.tls.reality.short_id // []) | length) > 0 then (.tls.reality.short_id[0] | tostring) else (.sid // "") end), spiderX: "/" } else empty end) } }
    else empty end;

  . as $root |
  ($meta[0]) as $m_data |

  # 1. 基础出站
  (($root.outbounds // []) | map(mk_outbound) | map(select(. != null))) as $base_outbounds |

  # 2. 注入特定 IP 策略的出站
  ([
    { tag: "direct-v6pref", ds: "UseIPv6v4" },
    { tag: "direct-v4pref", ds: "UseIPv4v6" },
    { tag: "direct-v6only", ds: "ForceIPv6" },
    { tag: "direct-v4only", ds: "ForceIPv4" },
    { tag: "direct-v4",     ds: "ForceIPv4" }
  ] | map({ protocol: "freedom", tag: .tag, settings: { domainStrategy: .ds } })) as $spec_outbounds |

  # 3. 注入 fixed_ip 出站
  ($m_data | to_entries | map(select(.value.fixed_ip != null)) | map(
    . as $e | { protocol: "freedom", tag: ("bind-" + $e.key), settings: { domainStrategy: $ds }, sendThrough: $e.value.fixed_ip }
  )) as $bind_outbounds |

  {
    log: { loglevel: "warning", access: $log, error: $log },
    inbounds: ((($root.inbounds // []) | map(mk_inbound)) | map(select(. != null))),
    outbounds: ($base_outbounds + $spec_outbounds + $bind_outbounds) | 
               map(if .tag == "direct" and ($gip|length > 0) and (.sendThrough == null) then . + {sendThrough: $gip} else . end),
    routing: {
      domainStrategy: $ds,
      rules: (
        # 优先权 1: fixed_ip 绑定
        ($m_data | to_entries | map(select(.value.fixed_ip != null)) | map({ type: "field", inboundTag: [.key], outboundTag: ("bind-" + .key) })) +
        # 优先权 2: 单节点 ip_mode (v6only/v4only 等)
        ($m_data | to_entries | map(select(.value.ip_mode != null)) | map({ type: "field", inboundTag: [.key], outboundTag: _mode_tag(.value.ip_mode) })) +
        # 优先权 3: 自定义路由规则
        (($root.route.rules // []) | map(select(.outbound != null) | { type: "field", outboundTag: .outbound, inboundTag: (if .inbound then (if (.inbound|type)=="array" then .inbound else [.inbound] end) else null end), domain: .domain, ip: .ip } | with_entries(select(.value != null))))
      )
    }
  }
' "$MODEL_CFG" > "$OUT_CFG"
SYNC
  chmod +x /usr/local/bin/xray-sync

  # ========================================================
  # 2. 生成 xray-singleton (单例守护程序)
  # ========================================================
  cat > /usr/local/bin/xray-singleton <<'WRAP'
#!/usr/bin/env bash
set -euo pipefail
XRAY_BASE_DIR="/etc/xray"
PIDFILE="/run/xray.pid"
OUT_CFG="${XRAY_BASE_DIR}/xray_config.json"
BIN="/usr/local/bin/xray"
LOG="/var/log/xray.log"

/usr/local/bin/xray-sync >/dev/null 2>&1 || true

if ! "$BIN" run -test -c "$OUT_CFG" >/dev/null 2>&1; then
  echo "[$(date)] [xray-singleton] Config Error" >> "$LOG"
  exit 1
fi

if [[ "${1:-}" != "--force" ]]; then
  if [[ -f "$PIDFILE" ]] && ps -p "$(cat "$PIDFILE")" -o comm= | grep -q 'xray'; then exit 0; fi
fi

pkill -x xray >/dev/null 2>&1 || true
setsid "$BIN" run -c "$OUT_CFG" >> "$LOG" 2>&1 &
echo $! > "$PIDFILE"
exit 0
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
  pkill -x xray >/dev/null 2>&1 || true
  rm -f /var/run/xray.pid /run/xray.pid >/dev/null 2>&1 || true
  sleep 1

  daemonize /usr/local/bin/xray-singleton --force
  sleep 1

  # ✅ 关键：别再“假成功”
  if ! pgrep -x xray >/dev/null 2>&1; then
    err "Fallback 启动失败：xray 进程未运行（请检查 /var/log/xray.log）"
    return 1
  fi
  return 0
}



auto_optimize_cpu() {
  local pid
  pid=$(pgrep -x xray | head -n1)
  if [[ -n "$pid" ]] && command -v renice >/dev/null 2>&1; then
     renice -n -10 -p "$pid" >/dev/null 2>&1
  fi
}

sync_and_restart_argo() {
    # 1. 获取当前最新的全局出口偏好
    local pref; pref=$(cat /etc/xray/ip_pref 2>/dev/null || echo "v4")
    local lock_ip=""
    local ds="AsIs"
    if [[ "$pref" == "v6" ]]; then
        lock_ip=$(cat /etc/xray/global_egress_ip_v6 2>/dev/null | tr -d '\r\n ')
        ds="UseIPv6"
    else
        lock_ip=$(cat /etc/xray/global_egress_ip_v4 2>/dev/null | tr -d '\r\n ')
        ds="UseIPv4"
    fi

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
  # 1. 立即清理缓存和探测锁
  rm -f "${IP_CACHE_FILE}_xray" "${IP_CACHE_FILE}_xray_status" /tmp/ip_probe.lock 2>/dev/null
  install_singleton_wrapper >/dev/null 2>&1 || true

  # 2. 先同步主模型并做 Xray 语法校验
  if ! sync_xray_config >/dev/null 2>&1; then
    err "配置文件不合法（Xray 校验未通过）"
    return 1
  fi

  # 3. 🚀 关键：同步重启所有 Argo 隧道出口配置
  sync_and_restart_argo

  # --- 路径 A: systemd 托管 ---
  if command -v systemctl >/dev/null 2>&1 && is_real_systemd; then
    if ! systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx 'xray.service'; then
      install_systemd_service >/dev/null 2>&1 || true
    fi

    systemctl restart xray >/dev/null 2>&1 || true
    sleep 1
    if systemctl is-active --quiet xray; then
      update_ip_async  # 启动成功立即触发 IP 探测
      ok "主服务及所有 Argo 隧道已完成出口同步并重启 (systemd)"
      return 0
    fi
  fi

  # --- 路径 B: OpenRC 托管 ---
  if command -v rc-service >/dev/null 2>&1 && [[ -f /etc/init.d/xray ]]; then
    rc-service xray restart >/dev/null 2>&1 || true
    sleep 1
    if rc-service xray status 2>/dev/null | grep -q started; then
      update_ip_async
      ok "主服务及所有 Argo 隧道已完成出口同步并重启 (OpenRC)"
      return 0
    fi
  fi

  # --- 路径 C: Fallback ---
  pkill -x xray >/dev/null 2>&1 || true
  if start_xray_singleton_force; then
    auto_optimize_cpu
    update_ip_async
    ok "主服务及所有 Argo 隧道已完成出口同步并重启 (Fallback)"
    return 0
  fi

  err "Xray 重启失败"
  return 1
}


# --- System Check & Fix Logic from original script (Simplified integration) ---
system_check() {
  local issues=0
  if command -v xray >/dev/null 2>&1; then ok "xray 已安装"; else err "xray 未安装"; issues=1; fi
  if ! sync_xray_config >/dev/null 2>&1; then err "Xray 配置同步/校验失败"; issues=1; else ok "Xray 配置可用"; fi
  # hy2 检测逻辑保持原样（函数内部自己处理）
  return "$issues"
}

fix_errors() {
  ensure_runtime_deps
  install_xray_if_needed
  install_systemd_service
  # Hysteria 修复逻辑保留原脚本
}

# ============= 4. 业务逻辑 (Add/Del Node) =============

add_node() {
  ensure_runtime_deps
  ensure_dirs
  install_singleton_wrapper >/dev/null 2>&1 || true
  if command -v systemctl >/dev/null 2>&1 && is_real_systemd; then
    systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx 'xray.service' || install_systemd_service >/dev/null 2>&1 || true
  fi

  while true; do
    echo -e "\n${C_CYAN}>>> 添加节点${C_RESET}"
    say "1) SOCKS5"
    say "2) VLESS-REALITY"
    say "3) Hysteria2"
    say "4) CF Tunnel 隧道"
    say "5) Shadowsocks (SS)"
    say "0) 返回主菜单"
    safe_read proto "输入协议编号: "
    proto=${proto:-1}
    [[ "$proto" == "0" ]] && return
    [[ "$proto" =~ ^[1-5]$ ]] && break
    warn "无效输入"
  done

  # --- 自定义命名逻辑 ---
  echo -e "\n${C_YELLOW}➜ 节点命名设置${C_RESET}"
  read -rp " 请输入自定义前缀 (例如 lazycat): " custom_prefix
  custom_prefix=${custom_prefix:-"node"}
  
  local zh_country; zh_country=$(get_country_name_zh)
  local letter; letter=$(get_node_letter_suffix "$custom_prefix" "$zh_country")
  
  # 构造最终标签名：自定义-国家字母 (例如: lazycat-香港A)
  local tag="${custom_prefix}-${zh_country}${letter}"
  say "自动生成节点名: ${C_GREEN}${tag}${C_RESET}"
  # --------------------

  if [[ "$proto" == "3" ]]; then add_hysteria2_node; return; fi
  if [[ "$proto" == "4" ]]; then argo_menu_wrapper; return; fi

  GLOBAL_IPV4=$(get_public_ipv4_ensure)
  local PUBLIC_HOST
  PUBLIC_HOST="$(head -n 1 /etc/xray/public_host 2>/dev/null | tr -d '\r\n ')"
  [[ -z "$PUBLIC_HOST" ]] && PUBLIC_HOST="$(get_public_ipv4_ensure)"

  # === SOCKS5 逻辑 ===
  if [[ "$proto" == "1" ]]; then
      read -rp "端口 (留空随机, 输入0返回): " port
      [[ "$port" == "0" ]] && return
      [[ -z "$port" ]] && port=$(get_random_allowed_port "tcp")
      read -rp "用户名 (默认 user, 输入0返回): " user
      [[ "$user" == "0" ]] && return
      user=${user:-user}
      read -rp "密码 (默认 pass123, 输入0返回): " pass
      [[ "$pass" == "0" ]] && return
      pass=${pass:-pass123}

      safe_json_edit "$CONFIG" \
        '.inbounds += [{"type":"socks","tag":$tag,"listen":"::","listen_port":($port|tonumber),"users":[{"username":$user,"password":$pass}]}]' \
        --arg port "$port" --arg user "$user" --arg pass "$pass" --arg tag "$tag"
      restart_xray
      local creds=$(printf "%s:%s" "$user" "$pass" | base64 -w0)
      print_card "SOCKS5 成功" "$tag" "端口: $port" "socks://${creds}@${PUBLIC_HOST}:${port}#${tag}"
  fi

  # === Shadowsocks 逻辑 (新增) ===
  if [[ "$proto" == "5" ]]; then
      read -rp "端口 (留空随机, 输入0返回): " port
      [[ "$port" == "0" ]] && return
      [[ -z "$port" ]] && port=$(get_random_allowed_port "tcp")
      
      # SS 加密方式 (默认 aes-256-gcm)
      local method="aes-256-gcm"
      # read -rp "加密方式 (默认 aes-256-gcm): " input_method
      # [[ -n "$input_method" ]] && method="$input_method"

      # SS 密码 (默认随机)
      local def_pass
      def_pass=$(openssl rand -base64 16 | tr -d '=+/' | cut -c1-16)
      read -rp "密码 (默认随机, 输入0返回): " pass
      [[ "$pass" == "0" ]] && return
      pass=${pass:-$def_pass}

      # 1. 写入 config.json
      safe_json_edit "$CONFIG" \
        '.inbounds += [{"type":"shadowsocks","tag":$tag,"listen":"::","listen_port":($port|tonumber),"method":$method,"password":$pass}]' \
        --arg port "$port" --arg method "$method" --arg pass "$pass" --arg tag "$tag"
      
      # 2. 写入 Meta (方便查看详情)
      safe_json_edit "$META" '. + {($tag): {type:"shadowsocks", port:$port, method:$method, password:$pass}}' \
         --arg tag "$tag" --arg port "$port" --arg method "$method" --arg pass "$pass"

      restart_xray
      
      # 3. 生成链接 (ss://base64(method:password)@ip:port#tag)
      local userinfo="${method}:${pass}"
      local b64_creds=$(printf "%s" "$userinfo" | base64 -w0)
      local link="ss://${b64_creds}@${PUBLIC_HOST}:${port}#${tag}"
      
      print_card "Shadowsocks 成功" "$tag" "端口: $port\n加密: $method\n密码: $pass" "$link"
  fi

  # === VLESS-REALITY 逻辑 ===
  if [[ "$proto" == "2" ]]; then
    local port uuid server_name key_pair private_key public_key short_id
    while true; do
       safe_read port "请输入端口号 (留空随机, 输入0返回): "
       [[ "$port" == "0" ]] && return
       [[ -z "$port" ]] && port=$(get_random_allowed_port "tcp")
       if ! check_nat_allow "$port" "tcp"; then
           warn "端口 $port 不符合 NAT 限制"
           continue
       fi
       break
    done

    read -rp "伪装域名 (默认 www.microsoft.com, 输入0返回): " input_sni
    [[ "$input_sni" == "0" ]] && return
    server_name="${input_sni:-www.microsoft.com}"
    
    uuid=$(uuidgen)
    local xray_cmd=$(_xray_bin)
    [[ ! -x "$xray_cmd" ]] && xray_cmd=$(command -v xray)
    
    if [[ -z "$xray_cmd" ]]; then
        err "未发现 Xray 核心，正在尝试安装..."
        install_xray_if_needed
        xray_cmd="/usr/local/bin/xray"
    fi

    # 提取密钥函数
    extract_kv() {
      local pat="$1"
      grep -iE "$pat" | awk -F':' '{print $2}' | tr -d '[:space:]'
    }

    key_pair=$($xray_cmd x25519 2>/dev/null)
    private_key=$(echo "$key_pair" | extract_kv 'private')
    public_key=$(echo "$key_pair" | extract_kv 'public|password')

    if [[ -z "$public_key" && -n "$private_key" ]]; then
      public_key=$($xray_cmd x25519 -i "$private_key" 2>/dev/null | extract_kv 'public|password')
    fi

    if [[ -z "$private_key" || -z "$public_key" ]]; then
        err "致命错误：无法通过 Xray 核心生成有效的 x25519 密钥对"
        return 1
    fi

    short_id=$(openssl rand -hex 4)

    safe_json_edit "$CONFIG" \
       '.inbounds += [{"type": "vless","tag": $tag,"listen": "::","listen_port": ($port | tonumber),"users": [{ "uuid": $uuid, "flow": "xtls-rprx-vision" }],"tls": {"enabled": true,"server_name": $server,"reality": {"enabled": true,"handshake": { "server": $server, "server_port": 443 },"private_key": $prikey,"short_id": [ $sid ]}}}]' \
       --arg port "$port" --arg uuid "$uuid" --arg prikey "$private_key" --arg sid "$short_id" --arg server "$server_name" --arg tag "$tag"

    safe_json_edit "$META" '. + {($tag): {pbk:$pbk, sid:$sid, sni:$sni, port:$port, fp:"chrome"}}' \
       --arg tag "$tag" --arg pbk "$public_key" --arg sid "$short_id" --arg sni "$server_name" --arg port "$port"

    if ! restart_xray; then
      err "Xray 重启失败：已回滚"
      safe_json_edit "$CONFIG" '(.inbounds |= map(select(.tag != $tag)))' --arg tag "$tag" >/dev/null 2>&1 || true
      safe_json_edit "$META" 'del(.[$tag])' --arg tag "$tag" >/dev/null 2>&1 || true
      return
    fi

    port_status "$port"
    case $? in
      0) ;; 
      1)
        err "端口 $port 被占用：已回滚"
        safe_json_edit "$CONFIG" '(.inbounds |= map(select(.tag != $tag)))' --arg tag "$tag" >/dev/null 2>&1 || true
        safe_json_edit "$META" 'del(.[$tag])' --arg tag "$tag" >/dev/null 2>&1 || true
        restart_xray >/dev/null 2>&1 || true
        return ;;
      2)
        err "Xray 未监听 $port：已回滚"
        safe_json_edit "$CONFIG" '(.inbounds |= map(select(.tag != $tag)))' --arg tag "$tag" >/dev/null 2>&1 || true
        safe_json_edit "$META" 'del(.[$tag])' --arg tag "$tag" >/dev/null 2>&1 || true
        restart_xray >/dev/null 2>&1 || true
        return ;;
    esac

    local link="vless://${uuid}@${PUBLIC_HOST}:${port}?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&pbk=${public_key}&sid=${short_id}&sni=${server_name}&fp=chrome#${tag}"
    print_card "VLESS-REALITY 成功" "$tag" "端口: $port\nSNI: $server_name" "$link"
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

  # Install Hy2 (Simplified check)
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
  local obfs=$(openssl rand -base64 8 | tr -d '=+/' | cut -c1-8)

  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout "$key" -out "$cert" -days 3650 -subj "/CN=$sni" >/dev/null 2>&1

  cat > "/etc/hysteria2/${port}.yaml" <<EOF
listen: :${port}
tls: { cert: ${cert}, key: ${key} }
auth: { type: password, password: ${auth} }
obfs: { type: salamander, salamander: { password: ${obfs} } }
masquerade: { type: proxy, proxy: { url: https://${sni}/, rewriteHost: true, insecure: true } }
EOF

  # Service setup
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
      # OpenRC / Fallback logic from original script
      nohup /usr/local/bin/hysteria server -c "/etc/hysteria2/${port}.yaml" >/dev/null 2>&1 &
  fi

  local tag="Hy2-${port}"
  local tmpm=$(mktemp)
  jq --arg tag "$tag" --arg port "$port" --arg sni "$sni" --arg obfs "$obfs" --arg auth "$auth" \
    '. + {($tag): {type:"hysteria2", port:$port, sni:$sni, obfs:$obfs, auth:$auth}}' "$META" >"$tmpm" && mv "$tmpm" "$META"

  local link="hysteria2://${auth}@${PUBLIC_HOST}:${port}?obfs=salamander&obfs-password=${obfs}&sni=${sni}&insecure=1#${tag}"
  print_card "Hysteria2 成功" "$tag" "端口: $port" "$link"
  read -rp "按回车继续..." _
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
    local pref; pref=$(cat /etc/xray/ip_pref 2>/dev/null || echo "v4")
    local lock_ip=""
    local ds="AsIs"
    if [[ "$pref" == "v6" ]]; then
        lock_ip=$(cat /etc/xray/global_egress_ip_v6 2>/dev/null | tr -d '\r\n ')
        ds="UseIPv6"
    else
        lock_ip=$(cat /etc/xray/global_egress_ip_v4 2>/dev/null | tr -d '\r\n ')
        ds="UseIPv4"
    fi

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
        
        local pref; pref=$(cat /etc/xray/ip_pref 2>/dev/null || echo "v4")
        local lock_ip=""; local ds="AsIs"
        if [[ "$pref" == "v6" ]]; then
            lock_ip=$(cat /etc/xray/global_egress_ip_v6 2>/dev/null | tr -d '\r\n '); ds="UseIPv6"
        else
            lock_ip=$(cat /etc/xray/global_egress_ip_v4 2>/dev/null | tr -d '\r\n '); ds="UseIPv4"
        fi
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
        local pref; pref=$(cat /etc/xray/ip_pref 2>/dev/null || echo "v4")
        local lock_ip=""; local ds="AsIs"
        if [[ "$pref" == "v6" ]]; then
            lock_ip=$(cat /etc/xray/global_egress_ip_v6 2>/dev/null | tr -d '\r\n '); ds="UseIPv6"
        else
            lock_ip=$(cat /etc/xray/global_egress_ip_v4 2>/dev/null | tr -d '\r\n '); ds="UseIPv4"
        fi
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
  # 1. 基础环境与显示优化准备
  local V4_ADDR=$(get_public_ipv4_ensure)
  local V6_ADDR=$(get_public_ipv6_ensure)
  local global_pref="v4"
  [[ -f "/etc/xray/ip_pref" ]] && global_pref=$(cat /etc/xray/ip_pref)
  local meta_json="{}"
  [[ -f "$META" ]] && meta_json=$(cat "$META")

  # 存储用于详情跳转的索引数据
  NODE_TAGS=()
  NODE_TYPES=()
  NODE_PORTS=()
  NODE_IPS=()
  NODE_V_DISP=()
  local idx=1

  # 汇总并去重所有标签 (从运行配置和元数据文件中聚合)
  local all_tags
  all_tags=$( (jq -r '.inbounds[].tag // empty' "$CONFIG" 2>/dev/null; jq -r 'keys[]' "$META" 2>/dev/null) | sort -u)

  echo -e "\n${C_CYAN}=== 节点列表预览 (严格单行对齐) ===${C_RESET}"
  echo -e "➜ ${C_GRAY}正在聚合节点出口状态...${C_RESET}"

  # 打印表头，确保视觉对齐
  echo -e "${C_GRAY}————————————————————————————————————————————————————————————————————————————————${C_RESET}"
  printf " ${C_YELLOW}%-4s | %-20s | %-15s | %-8s | %-15s${C_RESET}\n" "序号" "节点标签" "协议/状态" "端口" "出口地址"
  echo -e "${C_GRAY}————————————————————————————————————————————————————————————————————————————————${C_RESET}"

  while read -r tag; do
      [[ -z "$tag" || "$tag" == "null" ]] && continue
      
      # 2. 获取节点基础信息 (修复端口显示 0 问题)
      local type=$(jq -r --arg t "$tag" '.inbounds[] | select(.tag == $t) | .type // empty' "$CONFIG" 2>/dev/null)
      [[ -z "$type" ]] && type=$(jq -r --arg t "$tag" '.[$t].type // "UNKNOWN"' "$META" 2>/dev/null)
      
      local port=$(jq -r --arg t "$tag" '.inbounds[] | select(.tag == $t) | (.port // .listen_port // empty)' "$CONFIG" 2>/dev/null)
      [[ -z "$port" || "$port" == "null" ]] && port=$(jq -r --arg t "$tag" '.[$t].port // "0"' "$META" 2>/dev/null)

      # 3. 判定 IP 版本与出口显示
      local fixed_ip=$(echo "$meta_json" | jq -r --arg t "$tag" '.[$t].fixed_ip // empty')
      local node_v=$(echo "$meta_json" | jq -r --arg t "$tag" '.[$t].ip_version // empty')
      local use_v=${node_v:-$global_pref} 
      
      local CURRENT_IP="$V4_ADDR"
      [[ "$use_v" == "v6" && -n "$V6_ADDR" ]] && CURRENT_IP="$V6_ADDR"
      [[ -n "$fixed_ip" && "$fixed_ip" != "null" && "$fixed_ip" != "" ]] && CURRENT_IP="$fixed_ip"

      # 4. 规范化协议名称与 Argo 状态识别
      local check_type="${type,,}" # 转为小写判断
      local display_type="${type^^}"
      
      if [[ "$check_type" == "vless" ]]; then
          display_type="VLESS-REALITY"
      elif [[ "$check_type" == "argo" ]]; then
          # 核心修复点：通过 fixed_ip 判定 Argo 类型
          if [[ -n "$fixed_ip" && "$fixed_ip" != "null" && "$fixed_ip" != "" ]]; then
              display_type="ARGO-FIXED"
          else
              display_type="ARGO-TEMP"
          fi
      fi

      # 存储数据
      NODE_TAGS+=("$tag")
      NODE_TYPES+=("$type")
      NODE_PORTS+=("$port")
      NODE_IPS+=("$CURRENT_IP")
      NODE_V_DISP+=("$use_v")

      local geo=$(get_ip_country "$CURRENT_IP")
      
      # 5. 严格垂直对齐打印
      local line_color="$C_YELLOW"
      [[ "$check_type" != "vless" && "$check_type" != "socks" ]] && line_color="$C_PURPLE"
      
      # 限制标签显示长度并执行单行打印
      local short_tag="${tag:0:20}"
      printf " ${C_GREEN}[%2d]${C_RESET} | ${line_color}%-20s${C_RESET} | %-15s | %-8s | %-15s\n" \
              "$idx" "$short_tag" "$display_type" "$port" "$use_v [$geo]"
      
      ((idx++))
  done <<< "$all_tags"

  echo -e "${C_GRAY}————————————————————————————————————————————————————————————————————————————————${C_RESET}"
  echo -e " ${C_GREEN}[0]${C_RESET} 返回主菜单"

  # 6. 二级详情查看逻辑 (完整版)
  read -rp " 请选择要查看详情的节点序号: " v_choice
  [[ -z "$v_choice" || "$v_choice" == "0" ]] && return

  local sel_idx=$((v_choice - 1))
  local target_tag="${NODE_TAGS[$sel_idx]}"
  local t_type="${NODE_TYPES[$sel_idx]}"
  local t_ip="${NODE_IPS[$sel_idx]}"
  local t_port="${NODE_PORTS[$sel_idx]}"
  
  [[ -z "$target_tag" ]] && { echo -e "${C_RED}错误：无效序号${C_RESET}"; sleep 1; return; }

  # 展示详情卡片
  local final_link=""
  if [[ "${t_type,,}" == "socks" ]]; then
      local user=$(jq -r --arg t "$target_tag" '.inbounds[] | select(.tag==$t) | .users[0].username // "user"' "$CONFIG" 2>/dev/null)
      local pass=$(jq -r --arg t "$target_tag" '.inbounds[] | select(.tag==$t) | .users[0].password // "pass"' "$CONFIG" 2>/dev/null)
      final_link="socks://$(printf "%s:%s" "$user" "$pass" | base64 -w0)@${t_ip}:${t_port}#${target_tag}"
      print_card "SOCKS5 详情" "$target_tag" "地址: ${t_ip}\n端口: ${t_port}\n用户: ${user}\n密码: ${pass}" "$final_link"

  elif [[ "${t_type,,}" == "vless" ]]; then
      local uuid=$(jq -r --arg t "$target_tag" '.inbounds[] | select(.tag==$t) | .users[0].uuid' "$CONFIG" 2>/dev/null)
      local pbk=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].pbk // empty')
      local sid=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].sid // empty')
      local sni=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].sni // "www.microsoft.com"')
      final_link="vless://${uuid}@${t_ip}:${t_port}?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&pbk=${pbk}&sid=${sid}&sni=${sni}&fp=chrome#${target_tag}"
      print_card "VLESS-REALITY 详情" "$target_tag" "地址: ${t_ip}\n端口: ${t_port}\nUUID: ${uuid}\nSNI: ${sni}\nPublic Key: ${pbk}\nShort ID: ${sid}" "$final_link"

  elif [[ "${t_type,,}" == "hysteria2" ]]; then
      local auth=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].auth')
      local obfs=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].obfs')
      local sni=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].sni')
      final_link="hysteria2://${auth}@${t_ip}:${t_port}?obfs=salamander&obfs-password=${obfs}&sni=${sni}&insecure=1#${target_tag}"
      print_card "Hysteria2 详情" "$target_tag" "地址: ${t_ip}\n端口: ${t_port}\n认证: ${auth}\n混淆: ${obfs}\nSNI: ${sni}" "$final_link"

  elif [[ "${t_type,,}" == "argo" ]]; then
      final_link=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].raw')
      print_card "Argo Tunnel 详情" "$target_tag" "出口类型: Cloudflare 隧道" "$final_link"

  elif [[ "${t_type,,}" == "vmess" ]]; then
      local uuid=$(jq -r --arg t "$target_tag" '.outbounds[] | select(.tag==$t) | .settings.vnext[0].users[0].id' "$CONFIG" 2>/dev/null)
      print_card "VMess 落地详情" "$target_tag" "此为落地出口节点，UUID: ${uuid}" "需配合分流规则使用"
  fi

  read -rp "按回车返回节点列表..." _
  view_nodes_menu # 递归返回列表
}

delete_node() {
  echo -e "\n${C_CYAN}=== 删除节点 (支持多选) ===${C_RESET}"
  echo -e "${C_GRAY}提示：输入多个序号可用空格或逗号分隔，如: 1 3 5 或 1,2,5${C_RESET}\n"

  local tags_raw=""
  # 1. 汇总所有配置中的标签 (Config + Meta)
  [[ -f "$CONFIG" ]] && tags_raw+=$(jq -r '.inbounds[].tag // empty' "$CONFIG" 2>/dev/null)
  [[ -f "$META" ]] && tags_raw+=$'\n'$(jq -r 'keys[]' "$META" 2>/dev/null)
  
  # 2. 去重并存入数组
  mapfile -t ALL_TAGS < <(echo "$tags_raw" | grep -v '^$' | sort -u)

  if [ ${#ALL_TAGS[@]} -eq 0 ]; then
      warn "当前没有任何节点可删除。"
      read -rp "按回车返回..." _
      return
  fi

  # 3. 显示列表 (精准识别协议类型)
  local i=0
  for tag in "${ALL_TAGS[@]}"; do
      i=$((i+1))  # 修正：算术运算必须使用 $(( ))
      
      # --- 精准获取协议类型逻辑 ---
      # 优先从 Meta 数据获取，Meta 里的 protocol 优先级最高
      local type_info=$(jq -r --arg t "$tag" '.[$t].protocol // .[$t].type // empty' "$META" 2>/dev/null)
      
      # 如果 Meta 没存，则去 Config 的 inbounds 里精准查找 protocol 字段
      if [[ -z "$type_info" || "$type_info" == "null" ]]; then
          type_info=$(jq -r --arg t "$tag" '.inbounds[]? | select(.tag == $t) | .protocol // .type // empty' "$CONFIG" 2>/dev/null)
      fi
      
      # 格式化显示名称 (统一转为小写后判断)
      local display_type="未知"
      case "${type_info,,}" in
          vless)     display_type="VLESS" ;;
          socks)     display_type="SOCKS5" ;;
          hysteria2) display_type="Hysteria2" ;;
          argo)      display_type="Argo" ;;
          vmess)     display_type="VMess" ;;
          trojan)    display_type="Trojan" ;;
          *)         display_type="未知" ;;
      esac
      
      echo -e " ${C_GREEN}[$i]${C_RESET} ${C_YELLOW}${tag}${C_RESET} ${C_GRAY}(${display_type})${C_RESET}"
  done
  echo -e " ${C_RED}[00]${C_RESET} 删除全部节点"
  echo -e " ${C_GREEN}[0]${C_RESET} 取消返回"
  echo ""

  read -rp "请输入要删除的节点序号: " choice
  [[ "$choice" == "0" || -z "$choice" ]] && return

  # --- 逻辑 A: 全量删除 (00) ---
  if [[ "$choice" == "00" ]]; then
      echo -e ""
      warn "⚠️  确定要删除所有 ${#ALL_TAGS[@]} 个节点及相关的所有分流规则吗？"
      read -rp "请输入 y 确认: " confirm
      if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
          say "正在执行全量清理..."
          # 停止并删除所有 Hysteria2 服务
          for target_tag in "${ALL_TAGS[@]}"; do
              if [[ "$target_tag" =~ Hy2 ]]; then
                  local port=$(jq -r --arg t "$target_tag" '.[$t].port // empty' "$META" 2>/dev/null)
                  [[ -z "$port" || "$port" == "null" ]] && port=$(echo "$target_tag" | grep -oE '[0-9]+')
                  [[ -n "$port" ]] && systemctl disable --now "hysteria2-${port}" 2>/dev/null && rm -f "/etc/systemd/system/hysteria2-${port}.service"
              fi
          done
          safe_json_edit "$CONFIG" '.inbounds = [] | .route.rules = []'
          safe_json_edit "$META" '{}'
          pkill -f "cloudflared" 2>/dev/null
          restart_xray
          ok "已清理全部节点及规则。"
      fi
      read -rp "按回车继续..." _
      return
  fi

  # --- 逻辑 B: 多选删除处理 ---
  local -a selected_tags=()
  local clean_choice="${choice//,/ }" # 将逗号换成空格统一处理
  
  for idx in $clean_choice; do
      if [[ "$idx" =~ ^[0-9]+$ ]] && [ "$idx" -ge 1 ] && [ "$idx" -le "$i" ]; then
          selected_tags+=("${ALL_TAGS[$((idx-1))]}")
      fi
  done

  # 数组去重
  mapfile -t selected_tags < <(printf "%s\n" "${selected_tags[@]}" | sort -u)

  if [ ${#selected_tags[@]} -eq 0 ]; then
      warn "未选择任何有效序号。"
      return
  fi

  # 确认预览
  echo -e "\n${C_RED}确认删除以下节点？${C_RESET}"
  for t in "${selected_tags[@]}"; do echo -e " - ${C_YELLOW}$t${C_RESET}"; done
  read -rp "输入 y 确认执行: " confirm
  [[ "$confirm" != "y" && "$confirm" != "Y" ]] && return

  # 开始循环删除
  for target_tag in "${selected_tags[@]}"; do
      say "清理中: $target_tag ..."
      
      # 1. 从 config.json 和 nodes_meta.json 移除
      safe_json_edit "$CONFIG" "del(.inbounds[] | select(.tag==\$t))" --arg t "$target_tag"
      safe_json_edit "$META" "del(.[\$t])" --arg t "$target_tag"

      # 2. 自动清理路由规则 (同时处理字符串和数组格式的入站)
      safe_json_edit "$CONFIG" '
        (.route.rules //= []) | 
        del(.route.rules[] | select(
          if (.inbound|type)=="array" then (.inbound | index($t) != null) else (.inbound == $t) end
        ))
      ' --arg t "$target_tag"

      # 3. 特殊服务级联清理
      if [[ "$target_tag" =~ Hy2 ]]; then
          local p=$(echo "$target_tag" | grep -oE '[0-9]+')
          [[ -n "$p" ]] && systemctl disable --now "hysteria2-$p" 2>/dev/null && rm -f "/etc/systemd/system/hysteria2-$p.service"
      fi
      [[ "$target_tag" =~ Argo ]] && pkill -f "cloudflared" 2>/dev/null
  done

  restart_xray
  ok "所选节点已成功移除。"
  read -rp "按回车返回..." _
}

import_link_outbound() {
    local link="$1"
    local tag="IMP-$(date +%s)"
    local type="" server="" port="" user="" pass="" new_node=""
    
    say "正在启动专业级解析与内核预校验..."
    
    if [[ "$link" == ss://* ]]; then
        # Shadowsocks 解析逻辑
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
        # VLESS 完整解析逻辑
        local uuid=$(echo "$link" | cut -d'@' -f1 | sed 's/vless:\/\///')
        local server_port_raw=$(echo "$link" | cut -d'@' -f2 | cut -d'?' -f1)
        server="${server_port_raw%%:*}"
        port="${server_port_raw##*:}"
        port=$(echo "$port" | tr -cd '0-9')
        local qs=""
        [[ "$link" == *"?"* ]] && qs="${link#*\?}" && qs="${qs%%#*}"
        local flow="" sni="" pbk="" sid="" fp="" net="tcp" htype="none"
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
                esac
            done
        fi
        new_node=$(jq -n --arg t "$tag" --arg s "$server" --arg p "$port" --arg u "$uuid" \
            --arg flow "$flow" --arg sni "$sni" --arg pbk "$pbk" --arg sid "$sid" --arg fp "$fp" \
            --arg net "$net" --arg htype "$htype" \
            '{type: "vless", tag: $t, server: $s, server_port: ($p|tonumber), uuid: $u, flow: $flow, transport: { type: $net, header_type: $htype }, tls: { server_name: $sni, reality: { public_key: $pbk, short_id: (if $sid != "" then [$sid] else [] end) }, utls: { fingerprint: $fp } }}')
        type="vless"
    elif [[ "$link" == vmess://* ]]; then
        # VMess 解析逻辑
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

    # 先测后加：仅探测服务器端口是否连通
    test_outbound_connection "$type" "$server" "$port" "" ""
    [[ $? -ne 0 ]] && { warn "落地探测不通，已取消导入"; return 1; }

    local sandbox="/tmp/sb_test_config.json"
    cp "$CONFIG" "$sandbox"
    jq --argjson node "$new_node" '(.outbounds //= []) | .outbounds += [$node]' "$sandbox" > "${sandbox}.tmp" && mv "${sandbox}.tmp" "$sandbox"
    
    if _check_model_config "$sandbox" >/dev/null 2>&1; then
        mv "$sandbox" "$CONFIG"
        ok "导入成功！(请前往‘设置节点落地关联’以生效)"
        # 移除 restart_xray
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
    echo -e "${C_PURPLE}"
    echo "   _____ _                 __               "
    echo "  / ___/(_)___  ____ _    / /_  ____  _  __"
    echo "  \__ \/ / __ \/ __ \`/   / __ \/ __ \| |/_/"
    echo " ___/ / / / / / /_/ /   / /_/ / /_/ />  <  "
    echo "/____/_/_/ /_/\__, /   /_.___/\____/_/|_|  v${VERSION}"
    echo "             /____/                        "
    echo -e "${C_RESET}"
    get_sys_status
}
# ============= 新增：状态维护子菜单 (UI优化+纯卸载逻辑) =============
status_menu() {
  while true; do
    # 已移除 clear，保留历史记录
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
          warn "⚠️  警告：此操作将删除所有节点配置、日志、服务文件以及脚本自身！"
          read -rp "确认彻底卸载？(y/N): " confirm
          if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
              say "正在停止服务..."
              systemctl stop xray 2>/dev/null
              pkill -f xray 2>/dev/null
              pkill -f hysteria 2>/dev/null
              
              say "正在清除文件..."
              # 清除 Xray 相关
              rm -rf /etc/xray /var/log/xray.log /usr/local/bin/xray /usr/local/bin/xray-singleton /usr/local/bin/xray-sync
              rm -f /etc/systemd/system/xray.service /etc/init.d/xray
              
              # 清除 Hysteria 相关
              rm -rf /etc/hysteria2 /usr/local/bin/hysteria
              rm -f /etc/systemd/system/hysteria2-*.service
              
              # 清除 Argo 相关
              rm -rf /root/agsbx
              
              # 清除缓存与快捷指令
              rm -f "$IP_CACHE_FILE" "${IP_CACHE_FILE}_v6" "/tmp/my_ip_cache"
              sed -i '/alias my=/d' /root/.bashrc
              sed -i '/alias MY=/d' /root/.bashrc
              
              systemctl daemon-reload 2>/dev/null
              
              # === 脚本自毁逻辑 ===
              local self_path
              self_path=$(readlink -f "$0") 
              if [[ -f "$self_path" ]]; then
                  rm -f "$self_path"
                  say "已删除脚本文件: $self_path"
              fi
              
              ok "卸载完成，江湖再见！"
              exit 0
          else
              say "已取消卸载。"
              sleep 1
          fi
          ;;      0) return ;;
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
        # 预防性解锁关键文件，防止由于之前的 chattr +i 导致写入失败
        chattr -i /etc/xray/ip_pref /etc/xray/global_egress_ip_v6 /etc/xray/global_egress_ip_v4 2>/dev/null || true

        local pref="" mode_name=""
        case "$ip_choice" in
          1) pref="v4pref"; mode_name="优选 IPv4" ;;
          2) pref="v6pref"; mode_name="优选 IPv6" ;;
          3) pref="v4only"; mode_name="真全局 IPv4 only" ;;
          4) pref="v6only"; mode_name="真全局 IPv6 only" ;;
        esac

        # 针对 v6only 的断网保护
        if [[ "$pref" == "v6only" && $v6_count -eq 0 ]]; then
          warn "错误：未检测到可用的 IPv6 出口，无法切换至 v6only 模式。"
          continue
        fi

        # --- 多 IPv6 选择逻辑 ---
        if [[ "$pref" == "v6pref" || "$pref" == "v6only" ]]; then
            if [[ $v6_count -gt 1 ]]; then
                echo -e "\n${C_CYAN}检测到多个 IPv6 出口，请选择要锁定的 IP：${C_RESET}"
                local n=0
                for line in "${V6_LIST[@]}"; do
                    n=$((n+1))
                    echo -e " ${C_GREEN}[$n]${C_RESET} $line"
                done
                echo -e " ${C_GREEN}[0]${C_RESET} 返回上级"
                echo -e " ${C_GRAY}(回车=不锁定，交给系统动态路由)${C_RESET}"
                read -rp " 请输入序号（回车=不锁定）: " ip_sel
                
                if [[ "${ip_sel:-}" == "0" ]]; then
                    say "已返回上级（未改动锁定设置）"
                    continue
                fi

                if [[ "$ip_sel" =~ ^[1-9]$ ]] && [[ "$ip_sel" -le $n ]]; then
                    local selected_ip=$(echo "${V6_LIST[$((ip_sel-1))]}" | awk '{print $1}')
                    echo "$selected_ip" > /etc/xray/global_egress_ip_v6
                    ok "已锁定出口 IP: $selected_ip"
                else
                    rm -f /etc/xray/global_egress_ip_v6
                    say "已设置为系统动态分配"
                fi
            else
                rm -f /etc/xray/global_egress_ip_v6
            fi
        fi

        # 优选模式通常不强制锁定 v4 IP
        [[ "$pref" == "v4pref" ]] && rm -f /etc/xray/global_egress_ip_v4

        # 写入配置并重启
        echo "$pref" > /etc/xray/ip_pref
        ok "✔ 全局模式已成功切换为：$mode_name"
        
        # 针对 v6pref 模式自动补全默认黑名单
        if [[ "$pref" == "v6pref" && ! -s /etc/xray/force_v4_domains.txt ]]; then
          echo -e "discord.com\nx.com\nopenai.com" > /etc/xray/force_v4_domains.txt
        fi

        restart_xray
        ;;

      5)
        # 域名名单管理 (完整逻辑，不省略)
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
                # 清理并去重
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
        # 停止策略：解除文件锁定并写入 off
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

# === 完美对齐+精准调色版：网络切换主菜单 ===
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
      # 从元数据 nodes_meta.json 读取模式
      local node_mode
      node_mode=$(jq -r --arg t "$tag" '.[$t].ip_mode // "follow_global"' "$META" 2>/dev/null)
      
      local status_text=""
      if [[ "$node_mode" == "follow_global" || "$node_mode" == "follow" || "$node_mode" == "null" || -z "$node_mode" ]]; then
        # 括号与提示文字设为紫色 (${C_PURPLE})，具体的策略值设为白色 (${C_RESET})
        status_text="${C_PURPLE}(当前：跟随全局 → ${C_RESET}${g_label}${C_PURPLE})${C_RESET}"
      else
        local n_label
        n_label="$(_ip_mode_desc "$node_mode")"
        # 括号与提示文字设为紫色 (${C_PURPLE})，具体的策略值设为白色 (${C_RESET})
        status_text="${C_PURPLE}(独立设置：${C_RESET}${n_label}${C_PURPLE})${C_RESET}"
      fi

      # 核心修复：\033[40G 会强制将光标移至第 40 列，无论前面的节点名是中文还是英文，后面的括号都会在同一列对齐
      printf " ${C_GREEN}[%d]${C_RESET} ${C_YELLOW}%s\033[40G%b\n" "$i" "$tag" "$status_text"
    done

    # 4. 服务器全局策略行同样使用 \033[40G 强制对齐
    local g_idx=$((i+1))
    printf " ${C_GREEN}[%d]${C_RESET} ${C_CYAN}服务器全局策略\033[40G${C_PURPLE}(当前全局：${C_RESET}%s${C_PURPLE})${C_RESET}\n" "$g_idx" "$g_label"
    
    echo -e " ${C_GREEN}[0]${C_RESET} 返回主菜单\n"

    local pick
    safe_read pick "请选择序号: "
    [[ -z "${pick:-}" || "$pick" == "0" ]] && return
    
    if ! [[ "$pick" =~ ^[0-9]+$ ]]; then
      warn "输入无效：请输入数字序号。"
      continue
    fi

    if (( pick == g_idx )); then
      _global_ip_version_menu
      continue
    fi

    if (( pick < 1 || pick > ${#ALL_TAGS[@]} )); then
      warn "输入无效：序号超出范围。"
      continue
    fi

    _node_ip_mode_menu "${ALL_TAGS[$((pick-1))]}"
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

        # 只有在真正发生变化时才重启
        if ! restart_xray; then
          warn "⚡ 重启失败，正在尝试回退..."
          safe_json_edit "$META" '. + {($tag): (.[$tag] + {"ip_mode": $m, "fixed_ip": $ip})}' --arg tag "$target_tag" --arg m "$old_mode" --arg ip "$old_fixed_ip"
          restart_xray
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
        restart_xray
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
      6)
        mkdir -p /etc/xray >/dev/null 2>&1 || true
        echo "off" > /etc/xray/ip_pref
        rm -f /etc/xray/global_egress_ip_v4 /etc/xray/global_egress_ip_v6 >/dev/null 2>&1 || true
        ok "已停止全局策略：off（不干预 IP 版本；节点策略可优先生效）"
        restart_xray
        ;;
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





main_menu() {
  while true; do
    # 核心：如果发现 Xray 锁定了 IP 但探测结果还没出来，就尝试触发一次探测
    local pref; pref=$(cat /etc/xray/ip_pref 2>/dev/null || echo "v4")
    local lock_ip=""; [[ "$pref" == "v6" ]] && lock_ip=$(cat /etc/xray/global_egress_ip_v6 2>/dev/null) || lock_ip=$(cat /etc/xray/global_egress_ip_v4 2>/dev/null)

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
    echo -e " ${C_GREEN}0.${C_RESET} 退出脚本"
    echo -e ""
    echo -e "${C_BLUE}──────────────────────────────────────────────────────────────${C_RESET}"
    
    if ! safe_read choice " 请输入选项 [0-6]: "; then
  echo
  exit 0
fi
    case "$choice" in
      1) add_node ;;
      2) view_nodes_menu ;;
      3) delete_node ;;
      4) status_menu ;;
      5) ip_version_menu ;;
      6) outbound_menu ;; # 新功能入口
      0) exit 0 ;;
      *) warn "无效输入" ;;
    esac
  done
}
# ============= 6. 极速启动逻辑 (脚本执行入口) =============

setup_shortcuts() {
  local SCRIPT_PATH
  # 1. 获取脚本的绝对路径
  SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null)"
  
  # 2. 如果获取失败（极少数情况），则使用当前执行命令时的路径
  [[ -z "$SCRIPT_PATH" ]] && SCRIPT_PATH="$PWD/$(basename "$0")"

  if [[ ! -f /root/.bashrc ]]; then touch /root/.bashrc; fi

  # 3. 改进逻辑：先删除旧的（无论对错），再写入最新的
  # 这样无论你脚本叫什么、放哪里，每次运行都会自动校准别名
  sed -i '/alias my=/d; /alias MY=/d' /root/.bashrc
  echo "alias my='$SCRIPT_PATH'" >> /root/.bashrc
  echo "alias MY='$SCRIPT_PATH'" >> /root/.bashrc
  
  # 只有在第一次设置或路径变动时才提示，避免每次运行都刷屏
  # ok "快捷指令 'my' 已同步至最新路径: $SCRIPT_PATH"
}

# --- 2. 启动执行流程 ---
setup_shortcuts

# 环境基础检查
if [[ ! -x "/usr/local/bin/xray" ]] || [[ ! -f "$CONFIG" ]]; then
    echo -e "${C_PURPLE}检测到环境缺失，正在初始化...${C_RESET}"
    ensure_dirs
    install_dependencies
    enable_bbr
    install_xray_if_needed
fi

# 直接进入主菜单，不再进行 check_core_update，避免启动卡顿
update_ip_async
load_nat_data
auto_optimize_cpu
main_menu
