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

# GEO 缓存（Bash 4+ 才支持关联数组；旧环境自动降级不报错）
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

# ============= 1. 核心工具函数 (UI优化) =============

say()  { echo -e "${C_GREEN}➜ ${C_RESET}$*"; }
err()  { echo -e "${C_RED}✖ $*${C_RESET}" >&2; }
ok()   { echo -e "${C_GREEN}✔ $*${C_RESET}" >&2; }
warn() { echo -e "${C_YELLOW}⚡ $*${C_RESET}" >&2; }
log_msg() {
  local level="$1" msg="$2"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" >> "$LOG_FILE"
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

# 异步后台更新 IP (兼容 BusyBox / Alpine / GNU)
update_ip_async() {
    (
        # IPv4 获取
        local ip4=$(curl -s --max-time 3 https://api.ipify.org || curl -s --max-time 3 https://ifconfig.me/ip)
        [[ -n "$ip4" ]] && echo "$ip4" > "$IP_CACHE_FILE"
        
        # IPv6 获取：优先使用 API，兜底使用本地指令
        local ip6=$(curl -s -6 --max-time 3 https://api64.ipify.org || curl -s -6 --max-time 3 https://6.ipw.cn)
        if [[ -z "$ip6" ]]; then
            # 放弃使用 grep -oP，改用 awk 提取 inet6 后面以 2 或 3 开头的地址
            # 并使用 cut 去掉 CIDR 前缀 (如 /64)
            ip6=$(ip -6 addr show scope global | grep -v "temporary" | awk '/inet6 [23]/ {print $2}' | cut -d/ -f1 | head -n 1)
        fi
        [[ -n "$ip6" ]] && echo "$ip6" > "${IP_CACHE_FILE}_v6"
    ) &
}

# 获取当前 IP (如果缓存有就读缓存，没有就强制获取)
get_public_ipv4_ensure() {
    if [[ -f "$IP_CACHE_FILE" ]]; then
        cat "$IP_CACHE_FILE"
    else
        local ip
        ip=$(curl -s --max-time 3 https://api.ipify.org || curl -s --max-time 3 https://ifconfig.me/ip)
        if [[ -n "$ip" ]]; then
            echo "$ip" | tee "$IP_CACHE_FILE"
        else
            # 最后的 fallback
            ip -4 addr | grep -v '127.0.0.1' | grep -v 'docker' | awk '{print $2}' | cut -d/ -f1 | head -n1
        fi
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

get_ip_country() {
    local ip="$1"
    [[ -z "$ip" || "$ip" == "未知" || "$ip" == "null" ]] && echo "??" && return

    # 1) 内存缓存
    if [[ -n "${GEO_CACHE[$ip]:-}" ]]; then
        echo "${GEO_CACHE[$ip]}"
        return
    fi

    # 2) 内网/保留地址快速返回
    if [[ "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|169\.254\.|fc00:|fd00:|fe80:|::1) ]]; then
        GEO_CACHE["$ip"]="LAN"
        echo "LAN"
        return
    fi

    local code="??"

    # 修复核心：增加 -4 参数强制使用 IPv4 访问地理位置接口
    code=$(curl -s -4 --max-time 2 "https://ip-api.com/json/${ip}?fields=countryCode" \
        | jq -r '.countryCode // empty' 2>/dev/null)
        
    # 如果还是失败，切换到备用接口
    if [[ -z "$code" || "$code" == "null" ]]; then
        code=$(curl -s -4 --max-time 2 "https://api.country.is/${ip}" | jq -r '.country // empty' 2>/dev/null)
    fi

    [[ -z "$code" || "$code" == "null" ]] && code="??"

    GEO_CACHE["$ip"]="$code"
    echo "$code"
}

# 按接口探测真实公网出口 IP（v4/v6）


# 构建 “公网IP [国家] (iface)” 行



test_outbound_connection() {
    local type="$1"
    local server="$2"
    local port="$3"
    local user="$4"
    local pass="$5"

    # 1. 加密协议直接跳过，节省等待时间
    if [[ "$type" =~ ^(ss|vless|vmess|hysteria2)$ ]]; then
        echo -e "➜ ${C_YELLOW}提示：${type^^} 加密协议请在客户端测试。${C_RESET}"
        return 0
    fi

    say "正在探测落地出口 (极速模式)..."
    # 移除原有的 sleep 2 以实现秒开测试

    local proxy_url=""
    [[ "$type" == "socks" ]] && proxy_url="socks5://" || proxy_url="http://"
    if [[ -n "$user" && -n "$pass" ]]; then
        proxy_url+="${user}:${pass}@"
    fi
    proxy_url+="${server}:${port}"

    # 2. 优化：将 --max-time 从 8s 降低至 3s，增加连接超时限制 --connect-timeout 2
    local test_ip
    test_ip=$(curl -s -x "$proxy_url" --connect-timeout 2 --max-time 3 https://api.ipify.org 2>/dev/null || echo "FAILED")

    if [[ "$test_ip" == "FAILED" || -z "$test_ip" ]]; then
        err "测试失败：节点连接超时 (3s)。"
    else
        ok "测试成功！出口 IP: ${C_YELLOW}${test_ip}${C_RESET}"
    fi
}


# 实时获取所有可用公网 IP 列表 (优化过滤版)
get_all_ips_with_geo() {
    local proto="$1"   # "4" 或 "6"
    local -a out_lines=()

    # --- 小工具：判断 IP 是否形似 ---
    _is_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
    _is_ipv6() { [[ "$1" == *:* ]]; }

    # --- 小工具：从接口探测真实公网 IP ---
    _iface_pub_ip() {
        local iface="$1" p="$2"
        if [[ "$p" == "4" ]]; then
            curl -s -4 --interface "$iface" --connect-timeout 1.5 --max-time 2 https://api.ipify.org 2>/dev/null | tr -d '\r\n'
        else
            curl -s -6 --interface "$iface" --connect-timeout 1.5 --max-time 2 https://api64.ipify.org 2>/dev/null | tr -d '\r\n'
        fi
    }

    # --- A) 先列出本机“真实公网地址”(scope global) ---
    if [[ "$proto" == "4" ]]; then
        mapfile -t _pubs < <(
            ip -4 addr show scope global 2>/dev/null \
            | awk '/inet /{print $2}' | cut -d/ -f1 \
            | grep -vE '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|169\.254\.)' \
            | sort -u
        )
        for ip in "${_pubs[@]}"; do
            local cc
            cc="$(get_ip_country "$ip")"
            out_lines+=("${ip} [${cc}]")
        done
    else
        mapfile -t _pubs < <(
            ip -6 addr show scope global 2>/dev/null \
            | grep -v "temporary" \
            | awk '/inet6 [23]/{print $2}' | cut -d/ -f1 \
            | sort -u
        )
        for ip in "${_pubs[@]}"; do
            local cc
            cc="$(get_ip_country "$ip")"
            out_lines+=("${ip} [${cc}]")
        done
    fi

    # --- B) 再列出“落地出口”(10.x / fd00) 并探测真实公网IP+国家 ---
    # 只抓常见“隧道/出口类接口”，避免把 docker/lo 之类乱入
    local iface_re='^(wg|tun|tap|ppp|tailscale|warp|wgcf|utun)'

    if [[ "$proto" == "4" ]]; then
        mapfile -t _lands < <(
            ip -4 -o addr show 2>/dev/null \
            | awk -v re="$iface_re" '
                $2 ~ re && $4 ~ /^10\./ {split($4,a,"/"); print a[1]"\t"$2}
            ' | sort -u
        )

        for row in "${_lands[@]}"; do
            local lip iface pub cc
            lip="$(echo "$row" | awk '{print $1}')"
            iface="$(echo "$row" | awk '{print $2}')"

            pub="$(_iface_pub_ip "$iface" "4")"
            if _is_ipv4 "$pub"; then
                cc="$(get_ip_country "$pub")"
                out_lines+=("${lip} [落地] -> ${pub} [${cc}] (${iface})")
            else
                out_lines+=("${lip} [落地] -> 探测失败 (${iface})")
            fi
        done

    else
        mapfile -t _lands < <(
            ip -6 -o addr show 2>/dev/null \
            | awk -v re="$iface_re" '
                $2 ~ re && $4 ~ /^fd00/ {split($4,a,"/"); print a[1]"\t"$2}
            ' | sort -u
        )

        for row in "${_lands[@]}"; do
            local lip iface pub cc
            lip="$(echo "$row" | awk '{print $1}')"
            iface="$(echo "$row" | awk '{print $2}')"

            pub="$(_iface_pub_ip "$iface" "6")"
            if _is_ipv6 "$pub"; then
                cc="$(get_ip_country "$pub")"
                out_lines+=("${lip} [落地] -> ${pub} [${cc}] (${iface})")
            else
                out_lines+=("${lip} [落地] -> 探测失败 (${iface})")
            fi
        done
    fi

    # --- 去重输出 ---
    if [ ${#out_lines[@]} -eq 0 ]; then
        return
    fi

    printf "%s\n" "${out_lines[@]}" | awk '!seen[$0]++'
}


# 系统状态 Dashboard
get_sys_status() {
    local cpu_load=$(awk '{print $1}' /proc/loadavg 2>/dev/null)
    local mem_total=$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null)
    local mem_free=$(awk '/MemAvailable/ {printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null)
    local mem_used=$((mem_total - mem_free))
    local mem_rate=0
    [[ $mem_total -gt 0 ]] && mem_rate=$((mem_used * 100 / mem_total))
    
    local ip_addr="获取中..."
    [[ -f "$IP_CACHE_FILE" ]] && ip_addr=$(cat "$IP_CACHE_FILE")

    local color_cpu="$C_GREEN"
    [[ $(echo "$cpu_load > 2.0" | bc -l 2>/dev/null) -eq 1 ]] && color_cpu="$C_YELLOW"
    
    local color_mem="$C_GREEN"
    [[ $mem_rate -ge 80 ]] && color_mem="$C_YELLOW"

    echo -e "${C_BLUE}┌──[ 系统监控 ]────────────────────────────────────────────────┐${C_RESET}"
    echo -e "${C_BLUE}│${C_RESET} CPU: ${color_cpu}${cpu_load}${C_RESET} | 内存: ${color_mem}${mem_used}MB/${mem_total}MB (${mem_rate}%)${C_RESET}"
    echo -e "${C_BLUE}│${C_RESET} IP : ${C_YELLOW}${ip_addr}${C_RESET}"
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

  # === 全局 IP 偏好 -> domainStrategy ===
  local pref ds
  pref="$(cat /etc/xray/ip_pref 2>/dev/null | tr -d '\r\n ' || true)"
  case "$pref" in
    v4) ds="UseIPv4" ;;
    v6) ds="UseIPv6" ;;
    *)  ds="AsIs" ;;
  esac

  jq --arg log "$log_path" --arg ds "$ds" '
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
          # ✅ 新增：开启 sniffing，才能按域名分流
          sniffing: {
            enabled: true,
            destOverride: ["http", "tls"]
          }
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
          # ✅ 新增：开启 sniffing，才能按域名分流
          sniffing: {
            enabled: true,
            destOverride: ["http", "tls"]
          }
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

    # ---------------- Routing rules (支持 domain 分流) ----------------
    def mk_rule:
      (
        {
          type: "field",
          outboundTag: (.outbound // "direct"),
          inboundTag: (if (.inbound | type) == "array" then .inbound else [(.inbound // empty)] end)
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
      );

    . as $root
    | {
        log: { loglevel: "warning", access: $log, error: $log },
        inbounds: ((($root.inbounds // []) | map(mk_inbound)) // []),
        outbounds:
          (
            (($root.outbounds // []) | map(mk_outbound))
            | (if (map(select(.tag=="direct")) | length) == 0
               then . + [{protocol:"freedom", tag:"direct", settings:{domainStrategy:$ds}}]
               else .
              end)
          ),
        routing: {
          domainStrategy: $ds,
          rules: (
            ($root.route.rules // [])
            | map(mk_rule)
          )
        }
      }
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
    local kernel_version=$(uname -r | cut -d- -f1)
    if [[ $(echo "$kernel_version < 4.9" | bc -l 2>/dev/null) -eq 1 ]]; then
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

    install -m 0755 "$bin" /usr/local/bin/xray
  )
  local rc=$?
  rm -rf "$tmp"

  if [[ $rc -ne 0 ]] || ! /usr/local/bin/xray version >/dev/null 2>&1; then
    err "Xray 安装失败（rc=$rc），请检查 unzip/网络/磁盘权限"
    return 1
  fi

  ok "Xray 核心已就绪"
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
  # 1. 生成 xray-sync (增强版：支持 IP 绑定 + 全局 v4/v6 偏好 + 全局默认出口IP + VLESS落地 + 域名分流)
  # ========================================================
  cat > /usr/local/bin/xray-sync <<'SYNC'
#!/usr/bin/env bash
set -euo pipefail
umask 022

XRAY_BASE_DIR="${XRAY_BASE_DIR:-/etc/xray}"
MODEL_CFG="${XRAY_BASE_DIR}/config.json"
META_CFG="${XRAY_BASE_DIR}/nodes_meta.json"
OUT_CFG="${XRAY_BASE_DIR}/xray_config.json"
LOG_PATH="${LOG_FILE:-/var/log/xray.log}"

mkdir -p "$(dirname "$OUT_CFG")" "$(dirname "$LOG_PATH")" >/dev/null 2>&1 || true
[[ -f "$META_CFG" ]] || echo "{}" > "$META_CFG"

# === 读取全局 IP 偏好：ip_pref -> domainStrategy ===
PREF="$(cat "${XRAY_BASE_DIR}/ip_pref" 2>/dev/null | tr -d '\r\n ' || true)"
case "$PREF" in
  v4) DS="UseIPv4" ;;
  v6) DS="UseIPv6" ;;
  *)  DS="AsIs" ;;
esac

# === 读取“全局默认出口 IP”（可为空）===
GLOBAL_IP=""
if [[ "$PREF" == "v6" ]]; then
  GLOBAL_IP="$(cat "${XRAY_BASE_DIR}/global_egress_ip_v6" 2>/dev/null | tr -d '\r\n ' || true)"
elif [[ "$PREF" == "v4" ]]; then
  GLOBAL_IP="$(cat "${XRAY_BASE_DIR}/global_egress_ip_v4" 2>/dev/null | tr -d '\r\n ' || true)"
fi

jq --arg log "$LOG_PATH" --arg ds "$DS" --arg gip "$GLOBAL_IP" --slurpfile meta "$META_CFG" '
  def _listen: (.listen // "::");
  def _port: ((.listen_port // .port // 0) | tonumber);

  # ================= Inbound 翻译（加 sniffing 才能域名分流） =================
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
        sniffing: { enabled: true, destOverride: ["http","tls"] }
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
                  + ":" + (((.tls.reality.handshake.server_port // 443) | tonumber) | tostring)),
            xver: 0,
            serverNames: [(.tls.server_name // .tls.reality.handshake.server // "www.microsoft.com")],
            privateKey: (.tls.reality.private_key // ""),
            shortIds: (.tls.reality.short_id // [])
          }
        },
        sniffing: { enabled: true, destOverride: ["http","tls"] }
      }
    else empty end;

  # ================= Outbound 翻译 =================
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
        protocol: "socks", tag: (.tag // "socks-out"),
        settings: { servers: [{
          address: (.server // ""),
          port: ((.server_port // 0) | tonumber),
          users: (if ((.username // "") != "" and (.password // "") != "")
                 then [{user: .username, pass: .password}] else [] end)
        }] }
      }
    elif .type == "shadowsocks" then
      {
        protocol: "shadowsocks", tag: (.tag // "ss-out"),
        settings: { servers: [{
          address: (.server // ""),
          port: ((.server_port // 0) | tonumber),
          method: (.method // "aes-256-gcm"),
          password: (.password // "")
        }] }
      }
    elif .type == "vmess" then
      {
        protocol: "vmess", tag: (.tag // "vmess-out"),
        settings: { vnext: [{
          address: (.server // ""),
          port: ((.server_port // 0) | tonumber),
          users: [{ id: (.uuid // .id // ""), security: "auto" }]
        }] },
        streamSettings: {
          network: (.transport.type // .network // "tcp"),
          security: (if (.tls.enabled == true or .tls != null) then "tls" else "none" end),
          tlsSettings: (if (.tls.enabled == true or .tls != null)
                        then { serverName: (.tls.server_name // .sni // ""), allowInsecure: true }
                        else empty end),
          wsSettings: (if (.transport.type == "ws" or .network == "ws")
                       then { path: (.transport.ws_settings.path // .path // ""),
                              headers: { Host: (.transport.ws_settings.headers.Host // .host // "") } }
                       else empty end)
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
                        else empty end)
        }
      }
    else empty end;

  # ================= 模型规则翻译：把 domain/ip/port/protocol 带入 Xray =================
  def mk_rule:
    (
      {
        type: "field",
        outboundTag: (.outbound | tostring),
        inboundTag: (
          if .inbound
          then (if (.inbound|type)=="array" then .inbound else [(.inbound|tostring)] end)
          else null
          end
        )
      }
      + (if (.domain? != null)
         then { domain: (if (.domain|type)=="array" then .domain else [(.domain|tostring)] end) }
         else {} end)
      + (if (.ip? != null)
         then { ip: (if (.ip|type)=="array" then .ip else [(.ip|tostring)] end) }
         else {} end)
      + (if (.port? != null)
         then { port: (if (.port|type)=="array" then .port else [(.port|tostring)] end) }
         else {} end)
      + (if (.protocol? != null)
         then { protocol: (if (.protocol|type)=="array" then .protocol else [(.protocol|tostring)] end) }
         else {} end)
    ) | with_entries(select(.value != null));

  # ================= 节点 fixed_ip 绑定：生成 direct-<tag> 出站 + 优先路由 =================
  ($meta[0] | to_entries | map(select(.value.fixed_ip != null)) | from_entries) as $bindings |

  ($bindings | to_entries | map(
    . as $e
    | (if (($e.value.ip_version // "") == "v6") or (($e.value.fixed_ip | tostring) | contains(":"))
       then "UseIPv6"
       elif (($e.value.ip_version // "") == "v4")
       then "UseIPv4"
       else $ds
       end) as $bind_ds
    | {
        protocol: "freedom",
        tag: ("direct-" + $e.key),
        settings: { domainStrategy: $bind_ds },
        sendThrough: $e.value.fixed_ip
      }
  )) as $bound_outbounds |

  . as $root
  | (
      (($root.outbounds // []) | map(mk_outbound) | map(select(. != null))) as $base_outbounds

      | (
          if ($base_outbounds | map(select(.tag=="direct")) | length) == 0
          then ($base_outbounds + [{protocol:"freedom", tag:"direct", settings:{domainStrategy:$ds}}])
          else $base_outbounds
          end
        ) as $outbounds_ready0

      # 给 direct 注入全局默认出口 IP（若设置了）
      | (
          if ($gip | length) > 0 then
            $outbounds_ready0
            | map(
                if .tag=="direct" and ((.sendThrough // "") | length) == 0
                then . + {sendThrough:$gip}
                else .
                end
              )
          else
            $outbounds_ready0
          end
        ) as $outbounds_ready

      | {
          log: { loglevel: "warning", access: $log, error: $log },
          inbounds: ((($root.inbounds // []) | map(mk_inbound)) | map(select(. != null))),
          outbounds: ($outbounds_ready + $bound_outbounds),
          routing: {
            domainStrategy: $ds,
            rules: (
              # 1) fixed_ip 绑定规则优先
              ($bindings | to_entries | map({
                type: "field",
                inboundTag: [.key],
                outboundTag: ("direct-" + .key)
              }))
              +
              # 2) 模型 route.rules（带 domain）
              ((($root.route.rules // []) | map(select(.outbound != null)) | map(mk_rule)))
            )
          }
        }
    )
' "$MODEL_CFG" > "$OUT_CFG"
SYNC
  chmod +x /usr/local/bin/xray-sync

  # ========================================================
  # 2. 生成 xray-singleton (单例守护程序)
  # ========================================================
  cat > /usr/local/bin/xray-singleton <<'WRAP'
#!/usr/bin/env bash
set -euo pipefail
umask 022

XRAY_BASE_DIR="/etc/xray"
PIDFILE="/run/xray.pid"
OUT_CFG="${XRAY_BASE_DIR}/xray_config.json"
BIN="/usr/local/bin/xray"
LOG="/var/log/xray.log"

/usr/local/bin/xray-sync >/dev/null 2>&1 || true

if ! "$BIN" run -test -c "$OUT_CFG" >/dev/null 2>&1; then
  echo "[$(date)] [xray-singleton] 配置文件语法错误" >> "$LOG"
  exit 1
fi

if [[ "${1:-}" != "--force" ]]; then
  if [[ -f "$PIDFILE" ]] && ps -p "$(cat "$PIDFILE")" -o comm= | grep -q 'xray'; then
    exit 0
  fi
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

restart_xray() {
  # ✅ 确保 wrapper 存在（systemd ExecStartPre 也依赖它）
  install_singleton_wrapper >/dev/null 2>&1 || true

  # 先同步并做语法校验，避免“重启即翻车”
  if ! sync_xray_config >/dev/null 2>&1; then
    err "配置文件不合法（Xray 校验未通过）"
    return 1
  fi

  # --- systemd 路径：只有真的 systemd 才走这里；没有 xray.service 就自动装一个 ---
  if command -v systemctl >/dev/null 2>&1 && is_real_systemd; then
    if ! systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx 'xray.service'; then
      install_systemd_service >/dev/null 2>&1 || true
    fi

    systemctl restart xray >/dev/null 2>&1 || true
    sleep 1
    if systemctl is-active --quiet xray; then
      ok "Xray 重启完成（systemd）"
      return 0
    fi
  fi

  # --- OpenRC ---
  if command -v rc-service >/dev/null 2>&1 && [[ -f /etc/init.d/xray ]]; then
    rc-service xray restart >/dev/null 2>&1 || true
    sleep 1
    if rc-service xray status 2>/dev/null | grep -q started; then
      ok "Xray 重启完成（OpenRC）"
      return 0
    fi
  fi

  # --- Fallback：必须真启动成功才算成功 ---
  pkill -x xray >/dev/null 2>&1 || true
  if start_xray_singleton_force; then
    auto_optimize_cpu
    ok "Xray 重启完成（Fallback）"
    return 0
  fi

  err "Xray 重启失败（Fallback 也未能拉起进程）"
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

  
  # 移除之前的强制降级逻辑，确保使用你当前的 26.1.23 环境
  
  while true; do
    echo -e "\n${C_CYAN}>>> 添加节点${C_RESET}"
    say "1) SOCKS5"
    say "2) VLESS-REALITY"
    say "3) Hysteria2"
    say "4) CF Tunnel 隧道"
    say "0) 返回主菜单"
    safe_read proto "输入协议编号: "
    proto=${proto:-1}
    [[ "$proto" == "0" ]] && return
    [[ "$proto" =~ ^[1-4]$ ]] && break
    warn "无效输入"
  done

  if [[ "$proto" == "3" ]]; then add_hysteria2_node; return; fi
  if [[ "$proto" == "4" ]]; then argo_menu_wrapper; return; fi
  
  GLOBAL_IPV4=$(get_public_ipv4_ensure)

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
      local tag="sk5-$(get_country_code)-${port}"
      safe_json_edit "$CONFIG" \
        '.inbounds += [{"type":"socks","tag":$tag,"listen":"::","listen_port":($port|tonumber),"users":[{"username":$user,"password":$pass}]}]' \
        --arg port "$port" --arg user "$user" --arg pass "$pass" --arg tag "$tag"
      restart_xray
      local creds=$(printf "%s:%s" "$user" "$pass" | base64 -w0)
      print_card "SOCKS5 成功" "$tag" "端口: $port" "socks://${creds}@${GLOBAL_IPV4}:${port}#${tag}"
  fi

  if [[ "$proto" == "2" ]]; then
    local port uuid server_name key_pair private_key public_key short_id tag
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
    
    # 获取 Xray 执行路径
    local xray_cmd=$(_xray_bin)
    [[ ! -x "$xray_cmd" ]] && xray_cmd=$(command -v xray)
    
    if [[ -z "$xray_cmd" ]]; then
        err "未发现 Xray 核心，正在尝试安装..."
        install_xray_if_needed
        xray_cmd="/usr/local/bin/xray"
    fi

    # --- 核心修复：兼容新版 xray x25519 输出（PublicKey/Password/Hash32） ---
# 更加强悍的提取函数：忽略大小写，兼容多种分隔符
extract_kv() {
  local pat="$1"
  # 兼容多种冒号分隔符、空格以及新旧版标签名
  grep -iE "$pat" | awk -F':' '{print $2}' | tr -d '[:space:]'
}

# 在 add_node 函数中 VLESS-REALITY 分支下的修改：
key_pair=$($xray_cmd x25519 2>/dev/null)

# 兼容各种版本的输出标签
private_key=$(echo "$key_pair" | extract_kv 'private')
public_key=$(echo "$key_pair" | extract_kv 'public|password')

# 终极保险：如果还是没取到，手动用私钥推导公钥
if [[ -z "$public_key" && -n "$private_key" ]]; then
  public_key=$($xray_cmd x25519 -i "$private_key" 2>/dev/null | extract_kv 'public|password')
fi

# 如果还是空，直接报错停止，不进入写入流程
if [[ -z "$private_key" || -z "$public_key" ]]; then
    err "致命错误：无法通过 Xray 核心生成有效的 x25519 密钥对"
    return 1
fi

key_pair=$($xray_cmd x25519 2>/dev/null)

# PrivateKey / Private key
private_key=$(echo "$key_pair" | extract_kv 'privatekey|private key|private')

# 兼容：PublicKey / Public key / Password（新版用 Password 代替旧 PublicKey）
public_key=$(echo "$key_pair" | extract_kv 'publickey|public key|password')

# 如果首轮没取到（极少数情况），用私钥再算一次，同样兼容 Password/PublicKey
if [[ -z "$public_key" && -n "$private_key" ]]; then
  public_key=$($xray_cmd x25519 -i "$private_key" 2>/dev/null | extract_kv 'publickey|public key|password')
fi


    short_id=$(openssl rand -hex 4)
    tag=$(generate_unique_tag)

    safe_json_edit "$CONFIG" \
       '.inbounds += [{"type": "vless","tag": $tag,"listen": "::","listen_port": ($port | tonumber),"users": [{ "uuid": $uuid, "flow": "xtls-rprx-vision" }],"tls": {"enabled": true,"server_name": $server,"reality": {"enabled": true,"handshake": { "server": $server, "server_port": 443 },"private_key": $prikey,"short_id": [ $sid ]}}}]' \
       --arg port "$port" --arg uuid "$uuid" --arg prikey "$private_key" --arg sid "$short_id" --arg server "$server_name" --arg tag "$tag"

    safe_json_edit "$META" '. + {($tag): {pbk:$pbk, sid:$sid, sni:$sni, port:$port, fp:"chrome"}}' \
       --arg tag "$tag" --arg pbk "$public_key" --arg sid "$short_id" --arg sni "$server_name" --arg port "$port"

    # 写入后：必须重启成功
if ! restart_xray; then
  err "Xray 重启失败：该节点未生效，已回滚"
  safe_json_edit "$CONFIG" '(.inbounds |= map(select(.tag != $tag)))' --arg tag "$tag" >/dev/null 2>&1 || true
  safe_json_edit "$META" 'del(.[$tag])' --arg tag "$tag" >/dev/null 2>&1 || true
  return
fi

# 重启成功后：必须监听端口，否则也回滚（避免“假可用”）
port_status "$port"
case $? in
  0) ;; # xray 正在监听
  1)
    err "端口 $port 被其他进程占用：该节点不可用，已回滚"
    safe_json_edit "$CONFIG" '(.inbounds |= map(select(.tag != $tag)))' --arg tag "$tag" >/dev/null 2>&1 || true
    safe_json_edit "$META" 'del(.[$tag])' --arg tag "$tag" >/dev/null 2>&1 || true
    restart_xray >/dev/null 2>&1 || true
    return
    ;;
  2)
    err "Xray 未监听 $port：该节点不可用，已回滚（请看 /var/log/xray.log）"
    safe_json_edit "$CONFIG" '(.inbounds |= map(select(.tag != $tag)))' --arg tag "$tag" >/dev/null 2>&1 || true
    safe_json_edit "$META" 'del(.[$tag])' --arg tag "$tag" >/dev/null 2>&1 || true
    restart_xray >/dev/null 2>&1 || true
    return
    ;;
esac

local link="vless://${uuid}@${GLOBAL_IPV4}:${port}?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&pbk=${public_key}&sid=${short_id}&sni=${server_name}&fp=chrome#${tag}"
print_card "VLESS-REALITY 成功" "$tag" "端口: $port\nSNI: $server_name" "$link"

  fi
}

# --- Hysteria 2 Logic (Keep Original) ---
add_hysteria2_node() {
  ensure_runtime_deps
  GLOBAL_IPV4=$(get_public_ipv4_ensure)
  
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

  local link="hysteria2://${auth}@${GLOBAL_IPV4}:${port}?obfs=salamander&obfs-password=${obfs}&sni=${sni}&insecure=1#${tag}"
  print_card "Hysteria2 成功" "$tag" "端口: $port" "$link"
  read -rp "按回车继续..." _
}

# --- Argo Tunnel Logic Wrapper ---
argo_menu_wrapper() {
    # 提取原脚本 ARGO 相关逻辑
    # 为节省篇幅且不删除逻辑，这里包含核心 Argo 函数
    
    ensure_argo_deps() {
        mkdir -p "/etc/xray/argo_users" "/root/agsbx"
        if [[ ! -f "/root/agsbx/cloudflared" ]]; then
             local arch="amd64"; [[ "$(uname -m)" == "aarch64" ]] && arch="arm64"
             curl -L -o /root/agsbx/cloudflared "https://github.com/cloudflare/cloudflared/releases/download/2024.6.1/cloudflared-linux-${arch}"
             chmod +x /root/agsbx/cloudflared
        fi
        if [[ ! -f "/root/agsbx/xray" ]]; then
             local z="https://github.com/XTLS/Xray-core/releases/download/v1.8.11/Xray-linux-64.zip"
             [[ "$(uname -m)" == "aarch64" ]] && z="https://github.com/XTLS/Xray-core/releases/download/v1.8.11/Xray-linux-arm64-v8a.zip"
             wget -qO /root/agsbx/x.zip "$z" && unzip -o /root/agsbx/x.zip -d /root/agsbx "xray" && rm /root/agsbx/x.zip
             chmod +x /root/agsbx/xray
        fi
    }

    temp_tunnel_logic() {
        ensure_argo_deps
        say "启动临时隧道..."
        local ARGO_DIR="/root/agsbx"
        mkdir -p "$ARGO_DIR/temp_node"
        
        # Cleanup
        pkill -f "cloudflared_temp"
        pkill -f "xray_temp"
        
        cp "$ARGO_DIR/xray" "$ARGO_DIR/temp_node/xray_temp"
        cp "$ARGO_DIR/cloudflared" "$ARGO_DIR/temp_node/cloudflared_temp"
        
        local port=$((RANDOM % 10000 + 40000))
        local uuid=$(uuidgen)
        local path="/$uuid"
        
        # Xray Config
        cat > "$ARGO_DIR/temp_node/config.json" <<EOF
{ "inbounds": [{ "port": ${port}, "listen": "127.0.0.1", "protocol": "vmess", "settings": { "clients": [{ "id": "${uuid}" }] }, "streamSettings": { "network": "ws", "wsSettings": { "path": "${path}" } } }], "outbounds": [{ "protocol": "freedom" }] }
EOF
        nohup "$ARGO_DIR/temp_node/xray_temp" run -c "$ARGO_DIR/temp_node/config.json" >/dev/null 2>&1 &
        
        # Cloudflared
        nohup "$ARGO_DIR/temp_node/cloudflared_temp" tunnel --url http://127.0.0.1:$port --no-autoupdate > "$ARGO_DIR/temp_node/cf.log" 2>&1 &
        
        say "正在获取域名 (5s)..."
        sleep 5
        local url=$(grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$ARGO_DIR/temp_node/cf.log" | head -n1)
        if [[ -z "$url" ]]; then err "获取失败"; return; fi
        
        local domain=${url#https://}
        local tag="Argo-Temp"
        local vm_json='{"v":"2","ps":"'$tag'","add":"'$domain'","port":"443","id":"'$uuid'","net":"ws","path":"'$path'","tls":"tls","sni":"'$domain'","host":"'$domain'"}'
        local link="vmess://$(echo -n "$vm_json" | base64 -w 0)"
        
        # Update Meta
        local tmp=$(mktemp)
        jq --arg t "$tag" --arg raw "$link" '. + {($t): {type:"argo", subtype:"temp", raw:$raw}}' "$META" >"$tmp" && mv "$tmp" "$META"
        
        print_card "临时隧道成功" "$tag" "域名: $domain" "$link"
        read -rp "按回车继续..." _
    }
    
    add_argo_user() {
        ensure_argo_deps
        read -rp "Token: " token
        [[ -z "$token" ]] && return
        read -rp "域名: " domain
        read -rp "本地端口: " port
        
        local uuid=$(uuidgen)
        local path="/vm-${port}"
        local tag="Argo-${port}"
        
        # Config & Services setup (Simplifying text but logic is same)
        mkdir -p "/etc/xray/argo_users"
        cat > "/etc/xray/argo_users/${port}.json" <<EOF
{ "inbounds": [{ "port": ${port}, "listen": "127.0.0.1", "protocol": "vmess", "settings": { "clients": [{ "id": "${uuid}" }] }, "streamSettings": { "network": "ws", "wsSettings": { "path": "${path}" } } }], "outbounds": [{ "protocol": "freedom" }] }
EOF
        # Start processes (Fixed nodes)
        nohup /root/agsbx/xray run -c "/etc/xray/argo_users/${port}.json" >/dev/null 2>&1 &
        nohup /root/agsbx/cloudflared tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token "$token" --url "http://127.0.0.1:${port}" >/dev/null 2>&1 &
        
        local vm_json='{"v":"2","ps":"'$tag'","add":"'$domain'","port":"443","id":"'$uuid'","net":"ws","path":"'$path'","tls":"tls","sni":"'$domain'","host":"'$domain'"}'
        local link="vmess://$(echo -n "$vm_json" | base64 -w 0)"
        
        local tmp=$(mktemp)
        jq --arg t "$tag" --arg p "$port" --arg d "$domain" --arg raw "$link" '. + {($t): {type:"argo", port:$p, domain:$d, raw:$raw}}' "$META" >"$tmp" && mv "$tmp" "$META"
        ok "添加成功"
    }
    
    uninstall_argo_all() {
        pkill -f /root/agsbx
        rm -rf /root/agsbx
        local tmp=$(mktemp)
        jq 'to_entries | map(select(.value.type != "argo")) | from_entries' "$META" > "$tmp" && mv "$tmp" "$META"
        ok "Argo 已卸载"
    }

    while true; do
      say "====== Cloudflare 隧道管理 ======"
      say "1) 临时隧道"
      say "2) 固定隧道 (Token)"
      say "3) 卸载/清理"
      say "0) 返回"
      safe_read ac "选择: "
      case "$ac" in
          1) temp_tunnel_logic ;;
          2) add_argo_user ;;
          3) uninstall_argo_all ;;
          0) return ;;
      esac
    done
}

# --- View / Delete Nodes (Original Logic) ---
view_nodes_menu() {
  # 1. 基础环境与显示优化准备
  local V4_ADDR=$(get_public_ipv4_ensure)
  local V6_ADDR=$(get_public_ipv6_ensure)
  local global_pref="v4"
  [[ -f "/etc/xray/ip_pref" ]] && global_pref=$(cat /etc/xray/ip_pref)
  local meta_json="{}"
  [[ -f "$META" ]] && meta_json=$(cat "$META")

  # 存储用于详情跳转的索引数据
  local -a NODE_TAGS=()
  local -a NODE_TYPES=()
  local -a NODE_PORTS=()
  local -a NODE_IPS=()
  local -a NODE_V_DISP=()
  local idx=1

  # 汇总并去重所有标签 (从运行配置和元数据文件中聚合)
  local all_tags
  all_tags=$( (jq -r '.inbounds[].tag // empty' "$CONFIG" 2>/dev/null; jq -r 'keys[]' "$META" 2>/dev/null) | sort -u)

  echo -e "\n${C_CYAN}=== 节点列表预览 (选择序号查看详情) ===${C_RESET}"
  echo -e "➜ ${C_GRAY}正在聚合节点出口状态...${C_RESET}"

  # 使用缓冲区实现“一次性全显”，消除跳跃感
  local menu_buffer=""

  while read -r tag; do
      [[ -z "$tag" || "$tag" == "null" ]] && continue
      
      # 2. 获取节点基础信息 (优先从运行配置读取，Meta 兜底)
      local type=$(jq -r --arg t "$tag" '.inbounds[] | select(.tag == $t) | .type // empty' "$CONFIG" 2>/dev/null)
      [[ -z "$type" ]] && type=$(jq -r --arg t "$tag" '.[$t].type // "UNKNOWN"' "$META" 2>/dev/null)
      
      local port=$(jq -r --arg t "$tag" '.inbounds[] | select(.tag == $t) | .listen_port // empty' "$CONFIG" 2>/dev/null)
      [[ -z "$port" || "$port" == "null" ]] && port=$(jq -r --arg t "$tag" '.[$t].port // "0"' "$META" 2>/dev/null)

      # 3. 判定 IP 版本与出口显示
      local fixed_ip=$(jq -r --arg t "$tag" '.[$t].fixed_ip // empty' "$META" 2>/dev/null)
      local node_v=$(jq -r --arg t "$tag" '.[$t].ip_version // empty' "$META" 2>/dev/null)
      local use_v=${node_v:-$global_pref} 
      
      local CURRENT_IP="$V4_ADDR"
      [[ "$use_v" == "v6" && -n "$V6_ADDR" ]] && CURRENT_IP="$V6_ADDR"
      [[ -n "$fixed_ip" && "$fixed_ip" != "null" ]] && CURRENT_IP="$fixed_ip"

      # 4. 规范化协议名称显示
      local display_type="${type^^}"
      [[ "$type" == "vless" ]] && display_type="VLESS-REALITY"
      [[ "$type" == "argo" ]] && display_type="ARGO-TUNNEL"

      # 存储数据
      NODE_TAGS+=("$tag")
      NODE_TYPES+=("$type")
      NODE_PORTS+=("$port")
      NODE_IPS+=("$CURRENT_IP")
      NODE_V_DISP+=("$use_v")

      local geo=$(get_ip_country "$CURRENT_IP")
      
      # 5. 构建缓冲行：格式为 [序号] 标签 (协议 | 端口:xxx | 出口:v4 [国家])
      local line_color="$C_YELLOW"
      [[ "$type" != "vless" && "$type" != "socks" ]] && line_color="$C_PURPLE"
      
      local formatted_line=$(printf " ${C_GREEN}[%d]${C_RESET} ${line_color}%-20s${C_RESET} ${C_GRAY}(%s | 端口:%s | 出口:%s [%s])${C_RESET}\n" \
              "$idx" "$tag" "$display_type" "$port" "$use_v" "$geo")
      menu_buffer+="$formatted_line"
      
      ((idx++))
  done <<< "$all_tags"

  # 一次性打印列表
  echo -e "$menu_buffer"
  echo -e " ${C_GREEN}[0]${C_RESET} 返回主菜单"

  # 6. 二级详情查看逻辑
  read -rp " 请选择要查看详情的节点序号: " v_choice
  [[ -z "$v_choice" || "$v_choice" == "0" ]] && return

  local sel_idx=$((v_choice - 1))
  local target_tag="${NODE_TAGS[$sel_idx]}"
  local t_type="${NODE_TYPES[$sel_idx]}"
  local t_ip="${NODE_IPS[$sel_idx]}"
  local t_port="${NODE_PORTS[$sel_idx]}"
  
  [[ -z "$target_tag" ]] && { err "无效序号"; sleep 1; return; }

  # 展示详情卡片
  local final_link=""
  if [[ "$t_type" == "socks" ]]; then
      local user=$(jq -r --arg t "$target_tag" '.inbounds[] | select(.tag==$t) | .users[0].username // "user"' "$CONFIG" 2>/dev/null)
      local pass=$(jq -r --arg t "$target_tag" '.inbounds[] | select(.tag==$t) | .users[0].password // "pass"' "$CONFIG" 2>/dev/null)
      final_link="socks://$(printf "%s:%s" "$user" "$pass" | base64 -w0)@${t_ip}:${t_port}#${target_tag}"
      print_card "SOCKS5 详情" "$target_tag" "地址: ${t_ip}\n端口: ${t_port}\n用户: ${user}\n密码: ${pass}" "$final_link"
  elif [[ "$t_type" == "vless" ]]; then
      local uuid=$(jq -r --arg t "$target_tag" '.inbounds[] | select(.tag==$t) | .users[0].uuid' "$CONFIG" 2>/dev/null)
      local pbk=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].pbk // empty')
      local sid=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].sid // empty')
      local sni=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].sni // "www.microsoft.com"')
      final_link="vless://${uuid}@${t_ip}:${t_port}?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&pbk=${pbk}&sid=${sid}&sni=${sni}&fp=chrome#${target_tag}"
      print_card "VLESS-REALITY 详情" "$target_tag" "地址: ${t_ip}\n端口: ${t_port}\nUUID: ${uuid}\nSNI: ${sni}\nPublic Key: ${pbk}\nShort ID: ${sid}" "$final_link"
  elif [[ "$t_type" == "hysteria2" ]]; then
      local auth=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].auth')
      local obfs=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].obfs')
      local sni=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].sni')
      final_link="hysteria2://${auth}@${t_ip}:${t_port}?obfs=salamander&obfs-password=${obfs}&sni=${sni}&insecure=1#${target_tag}"
      print_card "Hysteria2 详情" "$target_tag" "地址: ${t_ip}\n端口: ${t_port}\n认证: ${auth}\n混淆: ${obfs}\nSNI: ${sni}" "$final_link"
  elif [[ "$t_type" == "argo" ]]; then
      final_link=$(echo "$meta_json" | jq -r --arg t "$target_tag" '.[$t].raw')
      print_card "Argo Tunnel 详情" "$target_tag" "出口类型: Cloudflare 隧道" "$final_link"
  elif [[ "$t_type" == "vmess" ]]; then
      # 如果有导入过 VMess 落地出口，这里也可以查看
      local uuid=$(jq -r --arg t "$target_tag" '.outbounds[] | select(.tag==$t) | .settings.vnext[0].users[0].id' "$CONFIG" 2>/dev/null)
      print_card "VMess 落地详情" "$target_tag" "此为落地出口节点，UUID: ${uuid}" "需配合分流规则使用"
  fi

  read -rp "按回车返回节点列表..." _
  view_nodes_menu # 递归返回列表
}

# 修改后的删除节点函数：支持自动清理关联路由规则
delete_node() {
  echo -e "\n${C_CYAN}=== 删除节点 ===${C_RESET}"

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

  # 3. 显示列表
  local i=0
  for tag in "${ALL_TAGS[@]}"; do
      i=$((i+1))
      local type_info="未知"
      [[ "$tag" == *"vless"* ]] && type_info="VLESS"
      [[ "$tag" == *"sk5"* ]] && type_info="SOCKS5"
      [[ "$tag" == *"Hy2"* ]] && type_info="Hysteria2"
      [[ "$tag" == *"Argo"* ]] && type_info="Argo"
      
      echo -e " ${C_GREEN}[$i]${C_RESET} ${C_YELLOW}${tag}${C_RESET} ${C_GRAY}(${type_info})${C_RESET}"
  done
  echo -e " ${C_RED}[00]${C_RESET} 删除全部节点"
  echo -e " ${C_GREEN}[0]${C_RESET} 取消返回"
  echo ""

  read -rp "请输入要删除的节点序号 [0-00]: " choice
  [[ "$choice" == "0" || -z "$choice" ]] && return

  # --- 逻辑 A: 全量删除 (00) 并清理所有规则 ---
  if [[ "$choice" == "00" ]]; then
      echo -e ""
      warn "⚠️  确定要删除所有 ${#ALL_TAGS[@]} 个节点及相关的所有分流规则吗？"
      read -rp "请输入 y 确认: " confirm
      if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
          say "正在执行全量清理..."
          for target_tag in "${ALL_TAGS[@]}"; do
              # 清理 Hysteria2 / Argo 相关服务与进程
              if [[ "$target_tag" =~ Hy2 ]]; then
                  local port=$(echo "$target_tag" | grep -oE '[0-9]+')
                  [[ -n "$port" ]] && systemctl disable --now "hysteria2-${port}" 2>/dev/null && rm -f "/etc/systemd/system/hysteria2-${port}.service" "/etc/hysteria2/${port}.yaml"
              fi
              [[ "$target_tag" =~ Argo ]] && pkill -f "cloudflared" 2>/dev/null && pkill -f "xray" 2>/dev/null
          done

          # 一键排空配置、元数据和所有关联规则
          safe_json_edit "$CONFIG" '.inbounds = [] | .route.rules = []'
          safe_json_edit "$META" '{}'

          systemctl daemon-reload 2>/dev/null
          restart_xray
          ok "所有节点及关联规则已清理完毕。"
      else
          say "操作已取消。"
      fi
      read -rp "按回车继续..." _
      return
  fi

  # --- 逻辑 B: 删除单个节点并同步清理其规则 ---
  local target_tag=""
  if [[ "$choice" =~ ^[0-9]+$ ]]; then
      if [ "$choice" -ge 1 ] && [ "$choice" -le "$i" ]; then
          target_tag="${ALL_TAGS[$((choice-1))]}"
      else
          warn "无效序号"
          return
      fi
  else
      target_tag="$choice"
  fi

  if [[ -z "$target_tag" ]]; then warn "未选择有效节点"; return; fi

  say "正在执行级联删除: ${C_RED}${target_tag}${C_RESET} ..."
  
  # 1. 核心删除：从入站和元数据中移除
  safe_json_edit "$CONFIG" "del(.inbounds[] | select(.tag==\$t))" --arg t "$target_tag"
  safe_json_edit "$META" "del(.[\$t])" --arg t "$target_tag"

  # 2. 自动清理：移除所有引用了该节点标签的路由规则
  # 这里的 jq 逻辑会同时匹配字符串或数组形式的 inbound 标签
  safe_json_edit "$CONFIG" '
    (.route.rules //= []) | 
    del(.route.rules[] | select(
      if (.inbound|type)=="array" then (.inbound | index($t) != null) else (.inbound == $t) end
    ))
  ' --arg t "$target_tag"

  # 3. 特殊服务清理
  if [[ "$target_tag" =~ Hy2 ]]; then
      local port=$(echo "$target_tag" | grep -oE '[0-9]+')
      if [[ -n "$port" ]]; then
          systemctl disable --now "hysteria2-${port}" 2>/dev/null
          rm -f "/etc/systemd/system/hysteria2-${port}.service" "/etc/hysteria2/${port}.yaml"
      fi
  fi
  [[ "$target_tag" =~ Argo ]] && pkill -f "cloudflared" 2>/dev/null && pkill -f "xray" 2>/dev/null

  systemctl daemon-reload 2>/dev/null
  restart_xray
  ok "节点 [${target_tag}] 及其关联规则已成功移除。"
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


# 查看并删除落地出口 (显示 IP:端口 + 国家版)
# 查看并删除落地出口 (显示 IP:端口 + 国家版) — 修复：过滤掉裸 direct / 空tag
list_and_del_outbounds() {
    local menu_buffer=""
    menu_buffer+="\n${C_CYAN}=== 当前落地出口列表 (管理自定义落地) ===${C_RESET}\n"

    echo -e "➜ ${C_GRAY}正在加载出口数据...${C_RESET}"

    # 仅展示“可管理的自定义落地”：
    # - tag 必须存在且非空
    # - 排除 tag=direct
    # - 排除“裸 direct”（type=direct 且没有 sendThrough/send_through）
    #   （如果你未来确实用 direct+sendThrough 当作“绑定出口IP”，它会被显示出来）
    mapfile -t TAG_LIST < <(
      jq -r '
        .outbounds[]?
        | select(.tag != null and (.tag|tostring|length) > 0)
        | select(.tag != "direct")
        | select(.type != "direct" or ((.sendThrough // .send_through // "")|tostring|length) > 0)
        | .tag
      ' "$CONFIG" 2>/dev/null
    )

    if [ ${#TAG_LIST[@]} -eq 0 ]; then
        warn "当前没有可删除的自定义落地。"
        return
    fi

    local i=0
    for tag in "${TAG_LIST[@]}"; do
        i=$((i+1))

        # 尽量兼容多种 outbound：优先 server/server_port；否则尝试 address/port；再否则显示占位
        local ob_info
        ob_info=$(jq -r --arg t "$tag" '
          .outbounds[] | select(.tag == $t)
          | "\(.type // "unknown")|\(.server // .address // .host // "")|\(.server_port // .port // "")"
        ' "$CONFIG" 2>/dev/null)

        local type_info server_addr server_port
        type_info=$(echo "$ob_info" | cut -d'|' -f1)
        server_addr=$(echo "$ob_info" | cut -d'|' -f2)
        server_port=$(echo "$ob_info" | cut -d'|' -f3)

        # 兜底显示
        [[ -z "$server_addr" ]] && server_addr="未知"
        [[ -z "$server_port" ]] && server_port="??"

        # 只有像正常地址时才查国家，避免 "未知" 触发无意义查询
        local geo="??"
        if [[ "$server_addr" != "未知" && "$server_addr" != "N/A" && -n "$server_addr" ]]; then
            geo=$(get_ip_country "$server_addr")
        fi

        menu_buffer+=" ${C_GREEN}[$i]${C_RESET} ${C_YELLOW}${server_addr}:${server_port}${C_RESET} ${C_GRAY}(${type_info})${C_RESET} ${C_PURPLE}[${geo}]${C_RESET}\n"
    done
    menu_buffer+=" ${C_GREEN}[0]${C_RESET} 取消并返回"

    echo -e "$menu_buffer"
    read -rp "请输入要删除的序号: " del_idx
    [[ "$del_idx" == "0" || -z "$del_idx" ]] && return

    # 校验输入
    if [[ ! "$del_idx" =~ ^[0-9]+$ ]] || [ "$del_idx" -gt "$i" ] || [ "$del_idx" -lt 1 ]; then
        err "无效序号，请输入 1 到 $i 之间的数字"
        return
    fi

    # 还原对应的标签名
    local target_tag="${TAG_LIST[$((del_idx-1))]}"

    say "正在执行级联移除: ${target_tag} ..."

    # 1) 从 outbounds 数组中删除
    safe_json_edit "$CONFIG" "del(.outbounds[] | select(.tag == \$t))" --arg t "$target_tag"

    # 2) 自动清理引用了该落地的路由规则 (关键：防止 Xray 启动失败)
    safe_json_edit "$CONFIG" 'del(.route.rules[] | select(.outbound == $t))' --arg t "$target_tag"

    ok "落地出口及其关联规则已移除。"
    restart_xray
}

list_and_del_routing_rules() {
    echo -e "\n${C_CYAN}=== 查看/解除 关联规则 (route.rules) ===${C_RESET}"

    safe_json_edit "$CONFIG" '(.route //= {}) | (.route.rules //= []) | (.outbounds //= [])' >/dev/null 2>&1 || true

    local total
    total=$(jq -r '(.route.rules // []) | length' "$CONFIG" 2>/dev/null || echo 0)

    if [[ "$total" == "0" ]]; then
        warn "当前没有任何关联规则。"
        return
    fi

    echo -e "➜ ${C_GRAY}当前规则总数: ${total}${C_RESET}"
    echo -e "${C_BLUE}提示：输入序号删除单条；in:<tag> 删除该入站全部规则；ms:<tag> 仅删该入站 media-split 规则；all 清空全部规则；0 返回${C_RESET}\n"

    # ---------- helpers：把 outbound tag 渲染成 “公网IP/国家” ----------
    is_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
    is_ipv6() { [[ "$1" == *:* ]]; }

    is_private_ip() {
      local ip="$1"
      # IPv4 私网/保留
      if is_ipv4 "$ip"; then
        [[ "$ip" =~ ^10\. ]] && return 0
        [[ "$ip" =~ ^192\.168\. ]] && return 0
        [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0
        [[ "$ip" =~ ^127\. ]] && return 0
        [[ "$ip" =~ ^169\.254\. ]] && return 0
      fi
      # IPv6 ULA/loopback/link-local
      if is_ipv6 "$ip"; then
        [[ "$ip" =~ ^fd ]] && return 0
        [[ "$ip" == "::1" ]] && return 0
        [[ "$ip" =~ ^fe80: ]] && return 0
      fi
      return 1
    }

    get_iface_public_ip() {
      local iface="$1"
      local proto="${2:-4}"
      local url="https://api.ipify.org"
      local curl_flag="-4"
      if [[ "$proto" == "6" ]]; then
        url="https://api64.ipify.org"
        curl_flag="-6"
      fi
      curl -s ${curl_flag} --interface "$iface" --connect-timeout 1.5 --max-time 2 "$url" 2>/dev/null | tr -d '\r\n'
    }

    # 用本地源IP反查接口名（wg0/wg1...）
    iface_by_local_ip() {
      local lip="$1"
      ip -o addr show 2>/dev/null | awk -v ip="$lip" '$0 ~ ip {print $2; exit}'
    }

    # 解析域名 -> IP（缓存）
    declare -A _HOST2IP
    resolve_host_ip_cached() {
      local host="$1"
      if [[ -n "${_HOST2IP[$host]:-}" ]]; then
        echo "${_HOST2IP[$host]}"; return 0
      fi
      if is_ipv4 "$host" || is_ipv6 "$host"; then
        _HOST2IP["$host"]="$host"; echo "$host"; return 0
      fi
      local ipaddr=""
      ipaddr="$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1; exit}')"
      [[ -z "$ipaddr" ]] && ipaddr="$(getent ahostsv6 "$host" 2>/dev/null | awk 'NR==1{print $1; exit}')"
      _HOST2IP["$host"]="$ipaddr"
      echo "$ipaddr"
    }

    # 提取一个 outbound 的关键字段：type|host|port|sendThrough
    outbound_info_by_tag() {
      local tag="$1"
      jq -r --arg t "$tag" '
        .outbounds[]? | select(.tag == $t)
        | [
            (.type // "unknown"),
            (
              .server
              // .address
              // .host
              // .settings.servers[0].address
              // .settings.servers[0].server
              // .settings.vnext[0].address
              // .vnext[0].address
              // ""
            ),
            (
              (.server_port // .port // .settings.servers[0].port // .settings.vnext[0].port // .vnext[0].port // "")
              | tostring
            ),
            ((.sendThrough // .send_through // "") | tostring)
          ]
        | @tsv
      ' "$CONFIG" 2>/dev/null
    }

    # 如果 tag 不是 outbound.tag，但刚好是 sendThrough 的本地IP，也把它当作“本地绑定出口”
    find_sendthrough_by_tag_or_ip() {
      local tag="$1"
      # 1) tag 对应 outbound 的 sendThrough
      local st
      st="$(jq -r --arg t "$tag" '.outbounds[]? | select(.tag==$t) | (.sendThrough // .send_through // "")' "$CONFIG" 2>/dev/null | head -n1)"
      [[ -n "$st" && "$st" != "null" ]] && { echo "$st"; return 0; }

      # 2) 如果 tag 本身是私网IP，直接用它
      if (is_ipv4 "$tag" || is_ipv6 "$tag") && is_private_ip "$tag"; then
        echo "$tag"; return 0
      fi

      # 3) 否则查找 “sendThrough == tag”
      st="$(jq -r --arg ip "$tag" '
        .outbounds[]? | select((.sendThrough // .send_through // "") == $ip) | (.sendThrough // .send_through // "")
      ' "$CONFIG" 2>/dev/null | head -n1)"
      [[ -n "$st" && "$st" != "null" ]] && { echo "$st"; return 0; }

      echo ""
      return 1
    }

    format_outbound_label() {
      local tag="$1"
      [[ -z "$tag" || "$tag" == "null" ]] && { echo "-"; return; }
      [[ "$tag" == "direct" ]] && { echo "direct"; return; }

      # 1) 优先判定：这是不是“本地绑定出口”（direct + sendThrough，或 tag 本身就是私网IP）
      local st
      st="$(find_sendthrough_by_tag_or_ip "$tag")"
      if [[ -n "$st" ]]; then
        local iface pub cc proto
        iface="$(iface_by_local_ip "$st")"
        proto="4"; is_ipv6 "$st" && proto="6"
        if [[ -n "$iface" ]]; then
          pub="$(get_iface_public_ip "$iface" "$proto")"
          if [[ -n "$pub" ]]; then
            cc="$(get_ip_country "$pub")"
            echo "${pub} [${cc}] (${iface}) src=${st}"
            return
          fi
          echo "(${iface}) src=${st}"
          return
        fi
        echo "src=${st}"
        return
      fi

      # 2) 普通代理落地：显示 host:port -> real_ip [CC] (type)
      local info type host port sendThrough
      info="$(outbound_info_by_tag "$tag")"
      type="$(echo "$info" | awk '{print $1}')"
      host="$(echo "$info" | awk '{print $2}')"
      port="$(echo "$info" | awk '{print $3}')"
      sendThrough="$(echo "$info" | awk '{print $4}')"

      [[ -z "$type" ]] && type="unknown"
      [[ -z "$host" ]] && host="未知"
      [[ -z "$port" || "$port" == "null" ]] && port="??"

      # direct 且没有 sendThrough 的，直接显示 tag（避免 host:??）
      if [[ "$type" == "direct" ]]; then
        echo "${tag} (direct)"
        return
      fi

      local real_ip="" cc="??"
      if [[ "$host" != "未知" ]]; then
        real_ip="$(resolve_host_ip_cached "$host")"
        [[ -n "$real_ip" ]] && cc="$(get_ip_country "$real_ip")"
      fi

      if [[ -n "$real_ip" ]]; then
        echo "${host}:${port} -> ${real_ip} [${cc}] (${type})"
      else
        echo "${host}:${port} -> ?? [??] (${type})"
      fi
    }

    # ---------- 展示规则 ----------
    jq -r '
      (.route.rules // [])
      | to_entries[]
      | .key as $i
      | .value as $r
      | [
          ($i+1),
          (if ($r.inbound|type)=="array" then ($r.inbound|join(",")) else ($r.inbound//"-") end),
          ($r.kind // "-"),
          ($r.outbound // "-"),
          (if ($r.domain|type)=="array" then (($r.domain|length)|tostring) else "0" end)
        ]
      | @tsv
    ' "$CONFIG" 2>/dev/null | while IFS=$'\t' read -r idx inbound kind outbound_tag dcnt; do
        local ob_label
        ob_label="$(format_outbound_label "$outbound_tag")"
        echo -e " ${C_GREEN}[$idx]${C_RESET} inbound=${C_YELLOW}${inbound}${C_RESET}  kind=${C_CYAN}${kind}${C_RESET}  outbound=${C_PURPLE}${ob_label}${C_RESET}  domains=${dcnt}"
    done

    echo
    read -rp "请输入操作: " action
    [[ -z "${action:-}" || "$action" == "0" ]] && return

    # 1) 删除单条：纯数字
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
        ok "已清空全部规则（恢复全局直连行为）。"
        restart_xray
        return
    fi

    # 3) in:<tag> 删除该入站全部规则
    if [[ "$action" =~ ^in:(.+)$ ]]; then
        local in_tag="${BASH_REMATCH[1]}"
        safe_json_edit "$CONFIG" '
          .route.rules |= map(select(
            (if (.inbound|type)=="array" then (.inbound|index($in)!=null) else (.inbound==$in) end) | not
          ))
        ' --arg in "$in_tag" >/dev/null 2>&1 || true
        ok "已删除 inbound=${in_tag} 的全部规则。"
        restart_xray
        return
    fi

    # 4) ms:<tag> 仅删除该入站的 media-split-* 规则
    if [[ "$action" =~ ^ms:(.+)$ ]]; then
        local in_tag="${BASH_REMATCH[1]}"
        safe_json_edit "$CONFIG" '
          .route.rules |= map(select(
            (
              (if (.inbound|type)=="array" then (.inbound|index($in)!=null) else (.inbound==$in) end)
              and ((.kind // "") | test("^media-split-"))
            ) | not
          ))
        ' --arg in "$in_tag" >/dev/null 2>&1 || true
        ok "已删除 inbound=${in_tag} 的 media-split 分流规则。"
        restart_xray
        return
    fi

    warn "未识别的输入：$action"
    warn "可用：序号 / in:<tag> / ms:<tag> / all / 0"
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




ip_version_menu() {
  while true; do
    echo -e "\n${C_CYAN}=== 网络版本切换 (IPv4 / IPv6) ===${C_RESET}"

    # --- 使用与列表相同的过滤逻辑进行计数 ---
    local v4_count
    v4_count=$(ip -4 addr show scope global \
      | awk '/inet / {print $2}' | cut -d/ -f1 \
      | grep -vE '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)' \
      | wc -l)

    local v6_count
    v6_count=$(ip -6 addr show scope global \
      | grep -v "temporary" \
      | awk '/inet6 [23]/ {print $2}' | cut -d/ -f1 \
      | wc -l)

    say "1) 全局设置：优先使用 IPv4 ${C_GRAY}(检测到 $v4_count 个出口)${C_RESET}"
    say "2) 全局设置：优先使用 IPv6 ${C_GRAY}(检测到 $v6_count 个出口)${C_RESET}"
    say "3) 指定节点：单独设置 IP 版本与出口"
    say "0) 返回主菜单"
    safe_read ip_choice " 请选择操作: "

    case "$ip_choice" in
            1|2)
        local pref="v4"
        [[ "$ip_choice" == "2" ]] && pref="v6"

        mkdir -p /etc/xray >/dev/null 2>&1 || true

        # 记录旧值：用于判断是否需要“立刻生效”
        local old_pref
        old_pref="$(cat /etc/xray/ip_pref 2>/dev/null | tr -d '\r\n ' || true)"

        # === 新增：全局也选择具体出口 IP（可跳过）===
        local p_flag="4"
        [[ "$pref" == "v6" ]] && p_flag="6"

        echo -e "\n正在检测可用 IPv${p_flag} 出口及归属地..."
        mapfile -t avail_ips < <(get_all_ips_with_geo "$p_flag")

        # ✅ 如果用户选 v6 但根本没 v6 出口：不切换、不重启（避免把策略切到 UseIPv6 造成没网）
        if [[ "$pref" == "v6" && ${#avail_ips[@]} -eq 0 ]]; then
          warn "未检测到可用的 IPv6 公网地址：已忽略本次 v6 偏好切换（不会重启）。"
          continue
        fi

        # 先写偏好（但不强制重启；只有“真的改了全局出口IP”才重启）
        echo "$pref" > /etc/xray/ip_pref
        ok "全局偏好已设置为：$pref（将于下次重启生效；如需立刻生效请选择全局出口IP）"

        # 没有可用公网出口：只保存偏好，不重启
        if [ ${#avail_ips[@]} -eq 0 ]; then
          warn "未检测到可用的 IPv${p_flag} 公网地址，仅保存偏好（不重启）"
          continue
        fi

        local j=0
        for line in "${avail_ips[@]}"; do
          j=$((j+1))
          echo -e " ${C_GREEN}[$j]${C_RESET} ${C_CYAN}${line}${C_RESET}"
        done
        echo -e " ${C_GREEN}[0]${C_RESET} 跳过（仅保存偏好，不重启）"

        read -rp "请选择全局默认出口 IP 序号: " ip_idx

        # ✅ 只有选了具体出口IP，才需要重启立刻生效
        if [[ -n "${ip_idx:-}" && "$ip_idx" != "0" ]]; then
          local chosen_raw="${avail_ips[$((ip_idx-1))]}"
          local chosen_ip
          chosen_ip=$(echo "$chosen_raw" | awk '{print $1}')

          if [[ "$pref" == "v6" ]]; then
            echo "$chosen_ip" > /etc/xray/global_egress_ip_v6
            ok "全局默认 IPv6 出口已设置为: $chosen_raw"
          else
            echo "$chosen_ip" > /etc/xray/global_egress_ip_v4
            ok "全局默认 IPv4 出口已设置为: $chosen_raw"
          fi

          restart_xray
        else
          ok "已跳过设置全局出口 IP（仅保存偏好，不重启）"
        fi
        ;;

      3)
        # --- 节点选择层级 ---
        local tags_raw=""
        [[ -f "$CONFIG" ]] && tags_raw+=$(jq -r '.inbounds[].tag // empty' "$CONFIG")
        [[ -f "$META" ]] && tags_raw+=$'\n'$(jq -r 'keys[]' "$META")
        mapfile -t ALL_TAGS < <(echo "$tags_raw" | grep -v '^$' | sort -u)

        if [ ${#ALL_TAGS[@]} -eq 0 ]; then
          warn "当前没有任何节点可配置。"
          break
        fi

        local i=0
        for tag in "${ALL_TAGS[@]}"; do
          i=$((i+1))
          local current_v
          current_v=$(jq -r --arg t "$tag" '.[$t].ip_version // "跟随全局"' "$META" 2>/dev/null)
          local current_ip
          current_ip=$(jq -r --arg t "$tag" '.[$t].fixed_ip // "动态抓取"' "$META" 2>/dev/null)
          echo -e " ${C_GREEN}[$i]${C_RESET} ${C_YELLOW}${tag}${C_RESET} ${C_GRAY}(版本:${current_v} | IP:${current_ip})${C_RESET}"
        done
        echo -e " ${C_GREEN}[0]${C_RESET} 返回上级"

        read -rp "请输入节点序号: " n_idx
        [[ "$n_idx" == "0" || -z "$n_idx" ]] && continue
        local target_tag="${ALL_TAGS[$((n_idx-1))]}"

        # --- 详细 IP 选择层级 ---
        echo -e "\n➜ 为节点 [${C_YELLOW}${target_tag}${C_RESET}] 配置出口:"
        say "1. 强制 IPv4 列表"
        say "2. 强制 IPv6 列表"
        say "3. 跟随全局设置"
        say "0. 返回"

        read -rp "选择 [0-3]: " v_choice
        case "$v_choice" in
          1|2)
            local p_flag="4"
            [[ "$v_choice" == "2" ]] && p_flag="6"

            echo -e "\n正在检测可用 IPv${p_flag} 出口及归属地..."
            mapfile -t avail_ips < <(get_all_ips_with_geo "$p_flag")

            if [ ${#avail_ips[@]} -eq 0 ]; then
              err "未检测到可用的 IPv${p_flag} 公网地址"
              continue
            fi

            local j=0
            for line in "${avail_ips[@]}"; do
              j=$((j+1))
              echo -e " ${C_GREEN}[$j]${C_RESET} ${C_CYAN}${line}${C_RESET}"
            done
            echo -e " ${C_GREEN}[0]${C_RESET} 取消"

            read -rp "请选择具体的 IP 出口序号: " ip_idx
            [[ "$ip_idx" == "0" || -z "$ip_idx" ]] && continue

            local chosen_raw="${avail_ips[$((ip_idx-1))]}"
            local chosen_ip
            chosen_ip=$(echo "$chosen_raw" | awk '{print $1}')

            # 1) 写入 Meta：锁定版本和具体 IP（展示/记录）
            safe_json_edit "$META" '. + {($tag): (.[$tag] + {"ip_version": "v'$p_flag'", "fixed_ip": $ip})}' \
              --arg tag "$target_tag" --arg ip "$chosen_ip"
            ok "已锁定节点出口为: $chosen_raw"

            # 2) 同步写入模型配置（可选：你实现了才会真正生效）
            if command -v apply_node_egress_lock_to_model >/dev/null 2>&1; then
              apply_node_egress_lock_to_model "$target_tag" "$chosen_ip" || {
                warn "已写入 META，但写入模型配置失败（所以可能仍不会生效）"
              }
            fi

            # 3) 立刻生效
            restart_xray
            ;;
          3)
            # 清理 Meta（跟随全局）
            safe_json_edit "$META" 'del(.[ $tag ].ip_version) | del(.[ $tag ].fixed_ip)' --arg tag "$target_tag"
            ok "已恢复为跟随全局"

            # 同步清理模型配置（如果你实现了该函数）
            if command -v clear_node_egress_lock_from_model >/dev/null 2>&1; then
              clear_node_egress_lock_from_model "$target_tag" || true
            fi

            restart_xray
            ;;
          0) continue ;;
        esac
        ;;
      0) return ;;
    esac
  done
}



# 手动添加 SOCKS5 或 HTTP 落地
add_manual_proxy_outbound() {
    local type_choice="$1"
    local proto="socks"
    [[ "$type_choice" == "2" ]] && proto="http"

    echo -e "\n${C_CYAN}=== 手动添加 ${proto^^} 落地 (先测后加) ===${C_RESET}"
    read -rp "落地服务器地址 (IP/域名, 输入0返回): " server
    [[ "$server" == "0" || -z "$server" ]] && return
    read -rp "端口: " port
    [[ -z "$port" ]] && return
    read -rp "用户名 (可选): " user
    read -rp "密码 (可选): " pass

    # 重启前测试
    test_outbound_connection "$proto" "$server" "$port" "$user" "$pass"
    [[ $? -ne 0 ]] && { warn "落地测试未通过，已取消添加。"; return 1; }

    local tag="MAN-${proto^^}-${port}"
    local new_node
    if [[ -n "$user" && -n "$pass" ]]; then
        new_node=$(jq -n --arg t "$tag" --arg s "$server" --arg p "$port" --arg u "$user" --arg pw "$pass" --arg pr "$proto" '{type: $pr, tag: $t, server: $s, server_port: ($p|tonumber), username: $u, password: $pw}')
    else
        new_node=$(jq -n --arg t "$tag" --arg s "$server" --arg p "$port" --arg pr "$proto" '{type: $pr, tag: $t, server: $s, server_port: ($p|tonumber)}')
    fi

    local sandbox="/tmp/sb_proxy_check.json"
    cp "$CONFIG" "$sandbox"
    jq --argjson node "$new_node" '(.outbounds //= []) | .outbounds += [$node]' "$sandbox" > "${sandbox}.tmp" && mv "${sandbox}.tmp" "$sandbox"

    if _check_model_config "$sandbox" >/dev/null 2>&1; then
        mv "$sandbox" "$CONFIG"
        ok "落地已保存。(请在关联节点后查看效果)"
        # 移除 restart_xray
    else
        err "✖ 校验失败：内部逻辑冲突。"
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
  echo -e "\n${C_CYAN}=== 分流模式：增量配置 (自定义域名支持追加) ===${C_RESET}"

  # --- helper：按接口探测真实公网出口 IP（v4/v6） ---
  get_iface_public_ip() {
    local iface="$1"
    local proto="${2:-4}"  # 4 或 6

    local url="https://api.ipify.org"
    local curl_flag="-4"
    if [[ "$proto" == "6" ]]; then
      url="https://api64.ipify.org"
      curl_flag="-6"
    fi

    curl -s ${curl_flag} --interface "$iface" \
      --connect-timeout 1.5 --max-time 2 \
      "$url" 2>/dev/null | tr -d '\r\n'
  }
  get_iface_local_ip4() {
  local iface="$1"
  ip -4 -o addr show dev "$iface" 2>/dev/null | awk 'NR==1{split($4,a,"/"); print a[1]; exit}'
}
get_iface_local_ip6() {
  local iface="$1"
  # 取一个全局/ULA v6（你环境是 fd00/2xxx），按需可改过滤
  ip -6 -o addr show dev "$iface" 2>/dev/null | awk '
    /inet6 (fd00|2)/{split($4,a,"/"); print a[1]; exit}
  '
}


  build_iface_egress_line() {
    local iface="$1"
    local proto="${2:-4}"
    local pub
    pub="$(get_iface_public_ip "$iface" "$proto")"
    [[ -z "$pub" ]] && return 1

    local cc="??"
    cc="$(get_ip_country "$pub")"
    echo "${pub} [${cc}] (${iface})"
  }

  # --- helper：自定义代理落地展示：解析真实IP + 国家 ---
  is_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
  is_ipv6() { [[ "$1" == *:* ]]; }

  resolve_host_ip_cached() {
    local host="$1"
    local ip=""

    # 缓存命中
    if [[ -n "${_HOST2IP[$host]:-}" ]]; then
      echo "${_HOST2IP[$host]}"
      return 0
    fi

    # 已经是IP就直接返回
    if is_ipv4 "$host" || is_ipv6 "$host"; then
      _HOST2IP["$host"]="$host"
      echo "$host"
      return 0
    fi

    # 优先 v4，再 v6（用 getent，尽量避免额外依赖）
    ip="$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1; exit}')"
    if [[ -z "$ip" ]]; then
      ip="$(getent ahostsv6 "$host" 2>/dev/null | awk 'NR==1{print $1; exit}')"
    fi

    _HOST2IP["$host"]="$ip"
    echo "$ip"
  }

  describe_outbound_tag() {
  local tag="$1"
  # 显式使用 jq 提取并以制表符分隔，防止空格干扰
  jq -r --arg t "$tag" '
    .outbounds[]? | select(.tag == $t)
    | [
        (.type // "unknown"),
        (.server // .address // .host // .settings.servers[0].address // "未知"),
        ((.server_port // .port // .settings.servers[0].port // "0") | tostring)
      ]
    | @tsv
  ' "$CONFIG" 2>/dev/null
}

  build_proxy_out_display() {
    local tag="$1"
    local info type host port
    info="$(describe_outbound_tag "$tag")"

    # 使用 cut 确保提取正确，避免空格干扰
    type="$(echo "$info" | cut -f1)"
    host="$(echo "$info" | cut -f2)"
    port="$(echo "$info" | cut -f3)"

    # 修复核心：严禁在此处使用 (( ))
    if [[ -z "$host" || "$host" == "未知" ]]; then
        echo "${tag}  (配置缺失)"
        return
    fi

    local real_ip="" cc="??"
    # 先尝试直接解析，如果 host 本身是 IP，resolve 函数应直接返回它
    real_ip="$(resolve_host_ip_cached "$host")"

    if [[ -n "$real_ip" ]]; then
        # 调用你已经修复了 -4 参数的 get_ip_country 函数
        cc="$(get_ip_country "$real_ip")"
        echo "${tag}  ${host}:${port} -> ${real_ip} [${cc}] (${type})"
    else
        # 如果解析不到 IP，尝试直接对 host 运行一次国家查询（兜底方案）
        cc="$(get_ip_country "$host")"
        echo "${tag}  ${host}:${port} -> ${host} [${cc}] (${type})"
    fi
}

  # 0) 基础结构初始化 (确保 route/outbounds 存在)
  safe_json_edit "$CONFIG" '(.route //= {}) | (.route.rules //= []) | (.outbounds //= []) | (.inbounds //= [])' >/dev/null 2>&1 || true

  # 1) 选择入站 (Inbound)
  mapfile -t IN_TAGS < <(jq -r '.inbounds[] | select(.tag != null) | .tag' "$CONFIG" 2>/dev/null)
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

  # 2) 聚合所有可能的落地出口
  echo -e "➜ ${C_GRAY}正在扫描可用出口...${C_RESET}"

  # 自定义代理落地（配置里已有的非 direct 且非 LOCAL-OUT-）
  mapfile -t PROXY_OUTS < <(
    jq -r '.outbounds[]
      | select(.tag != null and .tag != "direct" and (.tag | startswith("LOCAL-OUT-") | not))
      | .tag' "$CONFIG" 2>/dev/null | sort -u
  )

  # 本地出口：探测真实公网 IP + 国家 + 接口名（wg0/wg1/...）
  LOCAL_V4=()   # 存 "展示文本|本地源IP"
LOCAL_V6=()

declare -A _seen4 _seen6
local -a _fail4 _fail6

# v4：候选接口（仍按 10.* 选 wg）
while read -r iface _ip; do
  [[ -n "$iface" ]] || continue
  [[ -n "${_seen4[$iface]:-}" ]] && continue
  _seen4[$iface]=1

  local lip pub cc line
  lip="$(get_iface_local_ip4 "$iface")"
  [[ -z "$lip" ]] && { _fail4+=("$iface"); continue; }

  pub="$(get_iface_public_ip "$iface" 4)"
  [[ -z "$pub" ]] && { _fail4+=("$iface"); continue; }

  cc="$(get_ip_country "$pub")"
  line="${pub} [${cc}] (${iface})|${lip}"
  LOCAL_V4+=("$line")
done < <(ip -4 -o addr show | awk '/inet 10\./{split($4,a,"/"); print $2, a[1]}')


# v6：候选接口（fd00/2xxx）
# 原代码：按接口名去重
while read -r iface _ip; do
  [[ -n "$iface" ]] || continue
  [[ -n "${_seen6[$iface]:-}" ]] && continue  # 这里导致了重复网卡被跳过
  _seen6[$iface]=1

  local lip pub cc line
  lip="$(get_iface_local_ip6 "$iface")"
  [[ -z "$lip" ]] && { _fail6+=("$iface"); continue; }

  pub="$(get_iface_public_ip "$iface" 6)"
  [[ -z "$pub" ]] && { _fail6+=("$iface"); continue; }

  cc="$(get_ip_country "$pub")"
  line="${pub} [${cc}] (${iface})|${lip}"
  LOCAL_V6+=("$line")
done < <(ip -6 -o addr show | awk '/inet6 (fd00|2)/{split($4,a,"/"); print $2, a[1]}')

[ ${#_fail4[@]} -gt 0 ] && echo -e "${C_GRAY}⚠ IPv4 以下接口未探测到公网/本地源IP，已跳过: ${_fail4[*]}${C_RESET}"
[ ${#_fail6[@]} -gt 0 ] && echo -e "${C_GRAY}⚠ IPv6 以下接口未探测到公网/本地源IP，已跳过: ${_fail6[*]}${C_RESET}"


  # 提示哪些接口没探测到公网 IP（不会加入可选列表，避免选到错误 sendThrough）
  if [ ${#_fail4[@]} -gt 0 ]; then
    echo -e "${C_GRAY}⚠ IPv4 以下接口未探测到公网出口，已跳过: ${_fail4[*]}${C_RESET}"
  fi
  if [ ${#_fail6[@]} -gt 0 ]; then
    echo -e "${C_GRAY}⚠ IPv6 以下接口未探测到公网出口，已跳过: ${_fail6[*]}${C_RESET}"
  fi

  echo -e "\n${C_CYAN}=== 第二步：选择落地出口 (Outbound) ===${C_RESET}"
  local j=0
  declare -a TEMP_OUT_LIST

  if [ ${#PROXY_OUTS[@]} -gt 0 ]; then
      echo -e "${C_BLUE}--- 自定义代理落地（真实IP/国家） ---${C_RESET}"
      for tag in "${PROXY_OUTS[@]}"; do
          j=$((j+1))
          local pretty
          pretty="$(build_proxy_out_display "$tag")"
          echo -e " ${C_GREEN}[$j]${C_RESET} ${C_YELLOW}${pretty}${C_RESET}"
          TEMP_OUT_LIST[$j]="$tag"
      done
  fi

  if [ ${#LOCAL_V4[@]} -gt 0 ]; then
  echo -e "${C_BLUE}--- 本地 IPv4 出口（显示公网IP，实际绑定本地源IP） ---${C_RESET}"
  for line in "${LOCAL_V4[@]}"; do
    j=$((j+1))
    local show="${line%%|*}"
    local srcip="${line#*|}"
    echo -e " ${C_GREEN}[$j]${C_RESET} ${C_CYAN}${show}${C_RESET}"
    TEMP_OUT_LIST[$j]="IP:${srcip}"
  done
fi

if [ ${#LOCAL_V6[@]} -gt 0 ]; then
  echo -e "${C_BLUE}--- 本地 IPv6 出口（显示公网IP，实际绑定本地源IP） ---${C_RESET}"
  for line in "${LOCAL_V6[@]}"; do
    j=$((j+1))
    local show="${line%%|*}"
    local srcip="${line#*|}"
    echo -e " ${C_GREEN}[$j]${C_RESET} ${C_PURPLE}${show}${C_RESET}"
    TEMP_OUT_LIST[$j]="IP:${srcip}"
  done
fi


  if [ "$j" -eq 0 ]; then
    err "没有可用的落地出口（自定义落地为空，且本地接口也未探测到公网出口）。"
    return
  fi

  read -rp "请选择落地序号 (0 取消): " out_idx
  [[ -z "${out_idx:-}" || "$out_idx" == "0" ]] && return
  local raw_choice="${TEMP_OUT_LIST[$out_idx]}"
  local selected_outbound_tag=""

  if [[ "$raw_choice" == IP:* ]]; then
  local target_ip="${raw_choice#IP:}"     # 这里现在会是 10.* 或 fd00::*
  local safe_ip_tag="${target_ip//./-}"; safe_ip_tag="${safe_ip_tag//:/-}"
  selected_outbound_tag="LOCAL-OUT-SRC-${safe_ip_tag}"
  safe_json_edit "$CONFIG" \
    '.outbounds |= (map(select(.tag != $tag)) + [{"type":"direct","tag":$tag,"sendThrough":$ip}])' \
    --arg tag "$selected_outbound_tag" --arg ip "$target_ip"
else
  selected_outbound_tag="$raw_choice"
fi


  # 3) 分流分类定义
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
  echo -e " ${C_GREEN}[a]${C_RESET} 全选"
  read -rp "请选择 (逗号分隔): " sel_raw
  [[ -z "${sel_raw:-}" || "$sel_raw" == "0" ]] && return

  local -a selected_keys=()
  if [[ "$sel_raw" =~ ^[aA]$ ]]; then
    selected_keys=("${CAT_KEYS[@]}")
  else
    for n in $(echo "$sel_raw" | tr ',' ' '); do
      [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -le "${#CAT_KEYS[@]}" ] && selected_keys+=("${CAT_KEYS[$((n-1))]}")
    done
  fi

  # 4) 增量更新逻辑
  for key in "${selected_keys[@]}"; do
    local kind_tag="media-split-$key"
    local domains_str=""

    if [[ "$key" == "CUSTOM" ]]; then
        local existing_doms
        existing_doms=$(jq -r --arg in_tag "$selected_inbound" --arg kind "$kind_tag" '
          .route.rules[] | select((.kind == $kind) and (if (.inbound|type)=="array" then (.inbound | index($in_tag) != null) else (.inbound == $in_tag) end)) | .domain[]
        ' "$CONFIG" 2>/dev/null | tr '\n' ' ')

        echo -e "\n${C_CYAN}➜ 正在配置自定义分流${C_RESET}"
        if [ -n "$existing_doms" ]; then
            echo -e "${C_GRAY}当前已有内容: ${C_RESET}${C_YELLOW}${existing_doms}${C_RESET}"
            echo -e "${C_GRAY}新输入的内容将追加到上述列表之后。${C_RESET}"
        fi

        read -rp "请输入要分流的域名或 IP (空格分隔): " custom_input
        [[ -z "$custom_input" && -z "$existing_doms" ]] && continue

        local new_doms
        new_doms=$(echo "$custom_input" | tr ',' ' ' | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9.]+$/) print $i; else print "domain:"$i}')
        domains_str="$existing_doms $new_doms"
    else
        domains_str="${CAT_DOMAINS[$key]}"
    fi

    local dom_json
    dom_json=$(echo "$domains_str" | tr ' ' '\n' | grep -v '^$' | sort -u | jq -R . | jq -s .)

    echo -e "➜ 正在更新分类 [${C_YELLOW}$key${C_RESET}] 出口 -> [${C_CYAN}$selected_outbound_tag${C_RESET}]"

    # A. 清理该分类旧规则
    safe_json_edit "$CONFIG" '
      .route.rules |= map(select(
        ((if (.inbound|type)=="array" then (.inbound | index($in_tag) != null) else (.inbound == $in_tag) end) and
        (.kind == $kind)) | not
      ))
    ' --arg in_tag "$selected_inbound" --arg kind "$kind_tag"

    # B. 插入合并后的新规则
    safe_json_edit "$CONFIG" '
      .route.rules = [
        {
          "inbound": [$in_tag],
          "outbound": $out_tag,
          "domain": $domains,
          "kind": $kind
        }
      ] + .route.rules
    ' --arg in_tag "$selected_inbound" --arg out_tag "$selected_outbound_tag" --arg kind "$kind_tag" --argjson domains "$dom_json"
  done

  # 5) Fallback 兜底
  safe_json_edit "$CONFIG" '
    if (.route.rules | map(select(.kind == "media-split-fallback" and (if (.inbound|type)=="array" then (.inbound | index($in_tag) != null) else (.inbound == $in_tag) end))) | length == 0) then
      .route.rules += [{
        "inbound": [$in_tag],
        "outbound": "direct",
        "kind": "media-split-fallback"
      }]
    else . end
  ' --arg in_tag "$selected_inbound"

  ok "关联成功！自定义域名已实现增量更新。"
  restart_xray
}




main_menu() {
  update_ip_async 
  while true; do
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

# ============= 6. 极速启动逻辑 (脚本执行入口) =============

# --- 1. 定义快捷键函数 ---
setup_shortcuts() {
  local SCRIPT_PATH
  SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo '/root/baby.sh')"
  if [[ ! -f /root/.bashrc ]]; then touch /root/.bashrc; fi
  if ! grep -q "alias my=" /root/.bashrc; then
      echo "alias my='$SCRIPT_PATH'" >> /root/.bashrc
      echo "alias MY='$SCRIPT_PATH'" >> /root/.bashrc
      ok "快捷指令 'my' 已设置，下次登录生效"
  fi
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
