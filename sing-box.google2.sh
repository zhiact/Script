#!/bin/bash
# 脚本：sing-box 与 Cloudflare Tunnel 自动化安装器 (兼容 systemd 和 OpenRC)
# 版本：12.2-AdvancedProtocols (尝试支持更多高级协议)

# --- 严格模式与全局设置 ---
set -euo pipefail
export LANG=en_US.UTF-8

# --- 全局配置与变量 (初始化) ---
readonly SCRIPT_VERSION="12.2-AdvancedProtocols"

TMP_DIR="/tmp/sing-box-installer-$$"
LOG_FILE="${TMP_DIR}/installer.log"
CF_TEMP_TUNNEL_PID_FILE="${TMP_DIR}/cf_temp_tunnel.pid"

SB_INSTALL_PATH="/usr/local/bin/sing-box"
SB_CONFIG_DIR="/etc/sing-box"
SB_CONFIG_FILE="${SB_CONFIG_DIR}/config.json"
SB_LOG_FILE="${SB_CONFIG_DIR}/sing-box.log"
SB_SERVICE_NAME="sing-box"

CF_INSTALL_PATH="/usr/local/bin/cloudflared"
CF_CONFIG_DIR="/etc/cloudflared"
CF_SERVICE_NAME="cloudflared"

# 用户配置
sb_uuid=""
sb_port=""
selected_protocol="" # 用户选择的协议: "vmess", "vless", "vless-reality", "hysteria2", "trojan", "vless-tls-tcp"
sb_ws_path=""        # WebSocket路径 (仅WS协议使用)
reality_private_key="" # 用于 Reality
reality_public_key=""  # 用于 Reality
reality_short_id=""    # 用于 Reality
hysteria2_password=""  # Hysteria2 密码/OBFS
hysteria2_up_mbps=""
hysteria2_down_mbps=""
trojan_password=""     # Trojan 密码
user_domain=""         # 用户为 TLS/Reality SNI 提供的域名
server_ip_address=""   # 服务器IP地址，用于直连协议的链接生成

# TLS证书相关 (用于 sing-box 直接处理 TLS)
server_cert_path=""
server_key_path=""

force_cf_choice=""
cf_use_tunnel="" # "temp", "fixed", "no"
cf_tunnel_token=""
cf_domain=""
cf_assigned_temp_domain=""

# 系统环境
detected_os=""
detected_arch=""
detected_init_system=""

# --- 颜色定义 ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; PLAIN='\033[0m'

# --- 日志函数 ---
_log() { local level="$1"; local message="$2"; local ts; ts=$(date +"%Y-%m-%d %H:%M:%S"); echo -e "${ts} [${level}] ${message}${PLAIN}" | tee -a "${LOG_FILE}"; }
info() { _log "${BLUE}INFO   " "$1"; }
success() { _log "${GREEN}SUCCESS" "$1"; }
warn() { _log "${YELLOW}WARNING" "$1" >&2; }
error_exit() { _log "${RED}ERROR  " "$1" >&2; exit 1; }

# 1. 预设退出原因
EXIT_REASON="EXIT"
# 2. 捕获 SIGINT（Ctrl+C），并设置退出码为 130（128+2）
trap 'EXIT_REASON="SIGINT"; exit 130' SIGINT
# 3. 捕获 SIGTERM（kill），并设置退出码为 143（128+15）
trap 'EXIT_REASON="SIGTERM"; exit 143' SIGTERM
# 4. 捕获任何脚本退出（无论正常、exit n 还是因错误），执行 CLEANUP
trap 'CLEANUP' EXIT
# --- 清理函数 ---
CLEANUP() { # ... (与版本12.1一致，此处省略以减少篇幅) ...
    info "执行清理操作..."
    exit_code=$?
    case "$EXIT_REASON" in
        "SIGINT")
            echo "⛔ 被 Ctrl+C 中断（SIGINT），退出码：$exit_code"
            close_tmptunnel
            ;;
        "SIGTERM")
            echo "🚫 被 kill （SIGTERM），退出码：$exit_code"
            close_tmptunnel
            ;;
        "EXIT")
            if [ $exit_code -eq 0 ]; then
                echo "✅ 正常退出（EXIT，退出码 0）"
            else
                echo "❌ 异常退出（EXIT，退出码 $exit_code）"
                close_tmptunnel
            fi
            ;;
        *)
            echo "⚠️ 未知退出原因：$EXIT_REASON，退出码：$exit_code"
            close_tmptunnel
            ;;
    esac
    if [ -d "${TMP_DIR}" ]; then rm -rf "${TMP_DIR}"; echo "临时目录 ${TMP_DIR} 已删除。"; fi

}
close_tmptunnel(){
    if [ -f "${CF_TEMP_TUNNEL_PID_FILE}" ] && [ -s "${CF_TEMP_TUNNEL_PID_FILE}" ] ; then
        local pid
        pid=$(cat "${CF_TEMP_TUNNEL_PID_FILE}")
        if ps | grep -q "^\s*$pid\s"; then 
            info "正在停止临时的 Cloudflare tunnel (PID: ${pid})..."
            run_sudo kill "${pid}" &>/dev/null || true
        fi
        rm -f "${CF_TEMP_TUNNEL_PID_FILE}"
    fi
}

# --- Sudo 权限执行封装 ---
run_sudo() { # ... (与版本12.1一致) ...
    if [ "$(id -ru)" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then sudo "$@"; else error_exit "此脚本需要 sudo 权限，但 sudo 命令未找到。"; fi
    else "$@"; fi
}

# --- 初始化系统检测 ---
detect_init_system() { # ... (与版本12.1一致) ...
    if [ -d /run/systemd/system ] && command -v systemctl &>/dev/null; then detected_init_system="systemd";
    elif command -v rc-service &>/dev/null && command -v rc-update &>/dev/null; then detected_init_system="openrc";
    elif [ -f /etc/init.d/cron ] && [ ! -d /run/systemd/system ]; then detected_init_system="sysvinit";
    else detected_init_system="unknown"; warn "未能明确识别初始化系统。服务管理可能受限。"; fi
    info "检测到的初始化系统: ${detected_init_system}"
}

# --- 依赖检查 ---
check_dependencies() { # ... (与版本12.1一致，确保jq, curl, wget, tar, uuidgen等存在) ...
    info "开始检查依赖项..."
    local dep_missing=0; local core_deps=("wget" "curl" "unzip" "grep" "jq" "tar" "openssl");local missing_deps=()
    for dep in "${core_deps[@]}"; do 
        if ! command -v "${dep}" >/dev/null 2>&1; then  
            warn "核心依赖项 '${dep}' 未安装。"; 
            dep_missing=$((dep_missing + 1)); 
            missing_deps+=("${dep}")

        fi; 
        done
    if ! command -v uuidgen >/dev/null 2>&1 && [ ! -f /proc/sys/kernel/random/uuid ]; then
        warn "命令 'uuidgen' 未安装，且 '/proc/sys/kernel/random/uuid' 不可用。"; dep_missing=$((dep_missing + 1))
        if [ "${detected_os}" = "linux" ] && [ "${detected_init_system}" = "openrc" ]; then 
        info "在 Alpine 上可尝试 'sudo apk add util-linux'"; 
        fi
    fi
    if [ "${detected_os}" = "linux" ] && [ "${detected_init_system}" = "openrc" ] && command -v apk >/dev/null 2>&1 && ! apk info -e libc6-compat >/dev/null 2>&1; then
        warn "当前为 Alpine Linux，建议安装 'libc6-compat' 增强兼容性 (sudo apk add libc6-compat)。";
    fi
    # 如果有缺失依赖，尝试自动安装
    if [ "${dep_missing}" -gt 0 ]; then
        local pkg_mgr=""
        if command -v apt >/dev/null 2>&1; then pkg_mgr="apt"
        elif command -v yum >/dev/null 2>&1; then pkg_mgr="yum"
        elif command -v apk >/dev/null 2>&1; then pkg_mgr="apk"
        fi

        if [ -n "$pkg_mgr" ]; then
            info "检测到包管理器: $pkg_mgr，尝试自动安装缺失依赖：${missing_deps[*]}"
            case "$pkg_mgr" in
                apt)
                    run_sudo apt update && run_sudo apt install -y "${missing_deps[@]}"
                    ;;
                yum)
                    run_sudo yum install -y "${missing_deps[@]}"
                    ;;
                apk)
                    run_sudo apk add --no-cache "${missing_deps[@]}"
                    ;;
            esac
        else
            error_exit "未检测到支持的包管理器，请手动安装以下依赖项：${missing_deps[*]}"
        fi
    fi

    wget --no-check-certificate --continue -qO $TMP_DIR/qrencode https://github.com/zhiact/Script/raw/main/qrencode-go/qrencode-go-linux-$detected_arch >/dev/null 2>&1 && run_sudo chmod +x $TMP_DIR/qrencode >/dev/null 2>&1
    success "所有核心依赖项检查完毕。"
}

# --- 环境检测 (OS 和架构) ---
detect_environment() { # ... (与版本12.1一致) ...
    info "检测操作系统和架构..."; local machine_arch; machine_arch=$(uname -m)
    case "$machine_arch" in amd64|x86_64) detected_arch="amd64" ;; i386|i686) detected_arch="386" ;; aarch64|arm64) detected_arch="arm64" ;; armv7*|armv7l) detected_arch="armv7" ;; armv6*|armv6l) detected_arch="armv6" ;; *arm*) detected_arch="arm" ;; s390x) detected_arch="s390x" ;; riscv64) detected_arch="riscv64" ;; mips) detected_arch="mips" ;; mipsle) detected_arch="mipsle" ;; *) error_exit "不支持架构: ${machine_arch}" ;; esac
    local system_name; system_name=$(uname -s)
    case "$system_name" in Linux) detected_os="linux" ;; Darwin) detected_os="darwin"; warn "macOS 支持有限。" ;; FreeBSD) detected_os="freebsd"; warn "FreeBSD 支持有限。" ;; *) error_exit "不支持操作系统: ${system_name}" ;; esac
    success "检测到环境: 系统=${detected_os}, 架构=${detected_arch}"
}

# --- 下载文件封装 ---
download_file() { # ... (与版本12.1一致) ...
    local url="$1"; local output_path="$2"; local file_description="$3"
    info "正在下载 ${file_description} 从 ${url} ..."
    if command -v curl &>/dev/null; then
        if ! curl -L --connect-timeout 20 --retry 3 --retry-delay 5 -o "${output_path}" "${url}"; then error_exit "curl 下载 ${file_description} 失败。"; fi
    elif command -v wget &>/dev/null; then
        if ! wget --timeout=20 --tries=3 --waitretry=5 -O "${output_path}" "${url}"; then error_exit "wget 下载 ${file_description} 失败。"; fi
    else error_exit "未找到 curl 或 wget，无法下载。"; fi
    success "${file_description} 下载成功: ${output_path}"
}

# --- 服务管理函数 (适配 systemd 和 OpenRC) ---
# $1: 操作 (install, uninstall, enable, disable, start, stop, status)
# $2: 服务名 (例如 sing-box, cloudflared)
# $3: (可选) 服务脚本路径 (用于OpenRC install/uninstall)
# $4: (可选) 服务配置文件路径 (用于OpenRC install/uninstall)
# $5: (可选) 服务描述 (用于OpenRC install)
manage_service() {
    local action="$1"
    local service_name="$2"
    local service_script_path="${3:-}"
    local service_confd_path="${4:-}"
    local service_description="${5:-}"
    local binary_path="" # 服务对应的可执行文件路径

    if [[ "${service_name}" == "${SB_SERVICE_NAME}" ]]; then
        binary_path="${SB_INSTALL_PATH}"
    elif [[ "${service_name}" == "${CF_SERVICE_NAME}" ]]; then
        binary_path="${CF_INSTALL_PATH}"
    else
        error_exit "未知的服务名: ${service_name} 无法管理。"
    fi

    info "正在对服务 '${service_name}' 执行 '${action}' 操作 (使用 ${detected_init_system})..."

    case "${detected_init_system}" in
        systemd)
            case "$action" in
                install) # systemd 的 install 通常指 daemon-reload 和 enable
                    run_sudo systemctl daemon-reload
                    run_sudo systemctl enable "${service_name}.service"
                    ;;
                uninstall) # systemd 的 uninstall 通常指 disable 和 daemon-reload
                    run_sudo systemctl disable "${service_name}.service" &>/dev/null || true
                    run_sudo systemctl daemon-reload
                    # 服务文件通常由包管理器处理，这里不直接删除，除非是脚本自己创建的
                    if [ -f "/etc/systemd/system/${service_name}.service" ] && grep -q "Generated by installer script" "/etc/systemd/system/${service_name}.service"; then
                        info "移除由脚本生成的 systemd 服务文件: /etc/systemd/system/${service_name}.service"
                        run_sudo rm -f "/etc/systemd/system/${service_name}.service"
                        run_sudo systemctl daemon-reload
                    fi
                    ;;
                enable) run_sudo systemctl enable "${service_name}.service" ;;
                disable) run_sudo systemctl disable "${service_name}.service" &>/dev/null || true ;; # 忽略错误
                start) run_sudo systemctl restart "${service_name}.service" ;; # 使用 restart 确保加载最新配置
                stop) run_sudo systemctl stop "${service_name}.service" &>/dev/null || true ;;
                status)
                    if run_sudo systemctl is-active --quiet "${service_name}.service"; then
                        success "服务 '${service_name}' 正在运行。"
                        return 0
                    else
                        warn "服务 '${service_name}' 未运行或状态未知。"
                        run_sudo systemctl status "${service_name}.service" --no-pager || true
                        return 1
                    fi
                    ;;
                *) error_exit "systemd 不支持的操作: ${action}" ;;
            esac
            ;;
        openrc)
            case "$action" in
                install)
                    if [ -z "${service_script_path}" ] || [ -z "${service_confd_path}" ]; then
                        error_exit "OpenRC 服务安装需要提供 init.d 脚本路径和 conf.d 文件路径。"
                    fi
                    info "为 OpenRC 创建服务脚本 ${service_script_path} 和配置文件 ${service_confd_path} (如果尚不存在)..."
                    if [ ! -f "${service_script_path}" ]; then
                        info "创建 OpenRC init.d 脚本: ${service_script_path}"
                        local openrc_script_content
                        local confd_file="${service_confd_path}"
                        local service_bin="${binary_path}"
                        local desc="${service_description:-$service_name service}"
                        local cmd_args=""

                        if [[ "${service_name}" == "${SB_SERVICE_NAME}" ]]; then
                            cmd_args="-D ${SB_CONFIG_DIR} run"
                            # shellcheck disable=SC2001 # awk aytacını temizlemek için sed kullanılıyor
                            if [[ "$(run_sudo "${binary_path}" version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -n1 | sed 's/\([0-9]*\.[0-9]*\).*/\1/')" < "1.9" ]]; then
                                cmd_args="run -c ${SB_CONFIG_FILE}"
                            fi
                        elif [[ "${service_name}" == "${CF_SERVICE_NAME}" ]]; then
                            if [ "${cf_use_tunnel}" = "fixed" ]; then
                                cmd_args="tunnel run" # 固定隧道的OpenRC脚本通常更复杂，依赖config.yml
                            else
                                info "Cloudflared 临时隧道不由 OpenRC 服务管理。"
                                return 0
                            fi
                        fi

                        # shellcheck disable=SC2016 # $ Gelenkten değişkenler burada kasıtlıdır
                        openrc_script_content=$(cat  <<EOF
#!/sbin/openrc-run
supervisor=supervise-daemon

name="${service_name}"
description="${desc}"
command="${service_bin}"
command_args="${cmd_args}"
pidfile="/var/run/\${RC_SVCNAME}.pid"
supervise_daemon_args="--stdout /var/log/${service_name}.log --stderr /var/log/${service_name}.err"
command_background=true


depend() {
    need net
    use dns logger
}
EOF
                        )
                        echo "${openrc_script_content}" | run_sudo tee "${service_script_path}" > /dev/null
                        run_sudo chmod 0755 "${service_script_path}"
                        success "已创建 OpenRC init.d 脚本: ${service_script_path}"
                    else
                        info "OpenRC init.d 脚本 ${service_script_path} 已存在。"
                    fi

                    if [ ! -f "${service_confd_path}" ]; then
                         info "创建 OpenRC conf.d 文件: ${service_confd_path}"
                         local openrc_confd_content="# Options for ${service_name}"
                         if [[ "${service_name}" == "${SB_SERVICE_NAME}" ]]; then
                             openrc_confd_content+="\nSINGBOX_ARGS=\"${cmd_args}\"" # 确保 cmd_args 在这里是正确的
                         elif [[ "${service_name}" == "${CF_SERVICE_NAME}" ]]; then
                             openrc_confd_content+="\n# CLOUDFLARED_OPTS=\"tunnel --config ${CF_CONFIG_DIR}/config.yml run <TUNNEL_ID_OR_NAME>\""
                             openrc_confd_content+="\n# Ensure your tunnel is configured, e.g., in ${CF_CONFIG_DIR}/config.yml or via token installation"
                         fi
                         echo -e "${openrc_confd_content}" | run_sudo tee "${service_confd_path}" > /dev/null
                         run_sudo chmod 0644 "${service_confd_path}"
                         success "已创建 OpenRC conf.d 文件: ${service_confd_path}"
                    else
                        info "OpenRC conf.d 文件 ${service_confd_path} 已存在。"
                    fi
                    run_sudo rc-update add "${service_name}" default
                    ;;
                uninstall)
                    run_sudo rc-update del "${service_name}" default &>/dev/null || true
                    if [ -f "${service_script_path}" ]; then
                        info "移除 OpenRC init.d 脚本: ${service_script_path}"
                        run_sudo rm -f "${service_script_path}"
                    fi
                    if [ -f "${service_confd_path}" ]; then
                        info "移除 OpenRC conf.d 文件: ${service_confd_path}"
                        run_sudo rm -f "${service_confd_path}"
                    fi
                    ;;
                enable) run_sudo rc-update add "${service_name}" default ;;
                disable) run_sudo rc-update del "${service_name}" default &>/dev/null || true ;;
                start) run_sudo rc-service "${service_name}" restart ;;
                stop) run_sudo rc-service "${service_name}" stop &>/dev/null || true ;;
                status)
                    if run_sudo rc-service "${service_name}" status | grep -q "status: started"; then
                        success "服务 '${service_name}' 正在运行。"
                        return 0
                    else
                        warn "服务 '${service_name}' 未运行或状态未知。"
                        run_sudo rc-service "${service_name}" status || true
                        return 1
                    fi
                    ;;
                *) error_exit "OpenRC 不支持的操作: ${action}" ;;
            esac
            ;;
        sysvinit|unknown)
            warn "初始化系统为 '${detected_init_system}'，自动服务管理支持有限。"
            warn "请参考相应文档手动配置 '${service_name}' 服务。"
            case "$action" in
                install|enable|start) info "请确保 '${binary_path}' 已正确安装并手动配置为服务。" ;;
                uninstall|disable|stop) info "请手动停止并移除 '${service_name}' 服务。" ;;
                status)
                    info "请手动检查 '${service_name}' 服务状态。"
                    if pgrep -f "${binary_path}" >/dev/null; then
                         success "检测到 '${service_name}' 进程正在运行 (基于 pgrep)。"
                         return 0
                    else
                         warn "未通过 pgrep 检测到 '${service_name}' 进程。"
                         return 1
                    fi
                    ;;
                *) error_exit "不支持的操作: ${action} 对于 ${detected_init_system}" ;;
            esac
            if [[ "$action" == "install" ]] && [[ "$(${binary_path} help service install 2>&1 || true)" != *"unknown command"* ]]; then
                info "尝试使用 '${binary_path} service install'..."
                if [[ "${service_name}" == "${SB_SERVICE_NAME}" ]]; then
                    run_sudo "${binary_path}" service -c "${SB_CONFIG_FILE}" install || warn "Sing-box service install 命令可能失败或不适用。"
                elif [[ "${service_name}" == "${CF_SERVICE_NAME}" ]] && [ -n "${cf_tunnel_token}" ]; then
                     run_sudo "${binary_path}" service install "${cf_tunnel_token}" || warn "Cloudflared service install 命令可能失败或不适用。"
                fi
            elif [[ "$action" == "uninstall" ]] && [[ "$(${binary_path} help service uninstall 2>&1 || true)" != *"unknown command"* ]]; then
                info "尝试使用 '${binary_path} service uninstall'..."
                 if [[ "${service_name}" == "${SB_SERVICE_NAME}" ]]; then
                    run_sudo "${binary_path}" service -c "${SB_CONFIG_FILE}" uninstall &>/dev/null || true
                elif [[ "${service_name}" == "${CF_SERVICE_NAME}" ]]; then
                     run_sudo "${binary_path}" service uninstall &>/dev/null || true
                fi
            fi
            ;;
    esac
    success "服务 '${service_name}' 的 '${action}' 操作已执行。"
}

# --- 获取服务器公网IP ---
get_server_ip() {
    info "尝试获取服务器公网IP地址..."
    # 尝试多个源获取IP
    server_ip_address=$(curl -s -m 5 https://api.ipify.org || curl -s -m 5 https://ipinfo.io/ip || curl -s -m 5 https://checkip.amazonaws.com || curl -s -m 5 ip.sb || hostname -I | awk '{print $1}')
    if [ -z "${server_ip_address}" ]; then
        warn "未能自动获取服务器公网IP。对于直连协议，您可能需要手动配置。"
        printf "${YELLOW}请手动输入您的服务器公网IP地址 (如果留空，某些链接可能不完整): ${PLAIN}"
        read -r server_ip_address
    fi
    if [ -n "${server_ip_address}" ]; then
        info "检测到/输入的服务器IP地址为: ${server_ip_address}"
    else
        warn "仍未获取到服务器IP地址。"
    fi
}


# --- 协议选择 ---
select_protocol() {
    info "开始协议选择..."
    echo -e "${YELLOW}请选择您希望安装的 sing-box 协议类型:${PLAIN}"
    echo "  1. VMess (WebSocket)                                  (兼容性好，可配合CDN)"
    echo "  2. VLESS (WebSocket)                                  (性能较好，可配合CDN)"
    echo "  3. VLESS + TCP + Reality (Vision Flow)              (推荐，抗封锁性强，性能好，通常直连)"
    echo "  4. Hysteria2                                        (暴力发包，高带宽需求，抗干扰，通常直连)"
    echo "  5. Trojan (TCP + TLS, 由 sing-box 处理 TLS)         (较好的伪装性，通常直连或特定CDN场景)"
    echo "  6. VLESS + TCP + TLS (由 sing-box 处理 TLS)         (类似Trojan，通常直连)"
    # 未来可以扩展更多选项

    local choice
    while true; do
        printf "${YELLOW}请输入您的选择 [1-6] (默认: 3. VLESS + Reality): ${PLAIN}"
        read -r choice
        choice=${choice:-3} # 用户直接回车则默认为 VLESS + Reality
        case "$choice" in
            1) selected_protocol="vmess_ws"; break ;;
            2) selected_protocol="vless_ws"; break ;;
            3) selected_protocol="vless_reality_tcp_vision"; break ;;
            4) selected_protocol="hysteria2"; break ;;
            5) selected_protocol="trojan_tcp_tls"; break ;;
            6) selected_protocol="vless_tcp_tls"; break ;;
            *) warn "无效的选择，请输入 1 到 6 之间的数字。" ;;
        esac
    done
    info "您已选择安装协议: ${selected_protocol}"
}

# --- 获取通用配置 (UUID, 端口, 用户域名/IP) ---
get_common_config() {
    info "获取通用配置..."
    # UUID 配置
    printf "${YELLOW}请输入用于协议的 UUID (例如 VLESS/VMess，留空则自动生成): ${PLAIN}"
    read -r input_uuid
    if [ -z "${input_uuid}" ]; then
        if command -v uuidgen &>/dev/null; then sb_uuid=$(uuidgen);
        elif [ -f /proc/sys/kernel/random/uuid ]; then sb_uuid=$(cat /proc/sys/kernel/random/uuid);
        else warn "uuidgen 未找到，将生成一个伪UUID。"; sb_uuid=$(date +%s%N | sha256sum | base64 | head -c 32 | sed -e 's/\(.\{8\}\)/\1-/g' -e 's/\(.\{13\}\)/\1-/g' -e 's/\(.\{18\}\)/\1-/g' -e 's/\(.\{23\}\)/\1-/g' | cut -c1-36); fi
        info "已自动生成 UUID: ${sb_uuid}"
    else
        if [[ ! "${input_uuid}" =~ ^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$ ]]; then error_exit "输入的 UUID 格式无效。"; fi
        sb_uuid="${input_uuid}"; info "将使用用户提供的 UUID: ${sb_uuid}"
    fi

    # 监听端口配置
    local default_port="443" # Reality, Hysteria2, Trojan, TLS 通常用443
    if [[ "${selected_protocol}" == "vmess_ws" ]] || [[ "${selected_protocol}" == "vless_ws" ]]; then
        default_port="8008" # WS 协议如果不由 sing-box 处理 TLS，可以用其他端口
        if [[ "${cf_use_tunnel}" != "no" ]]; then # 如果用 CF Tunnel，CF 会监听 80/443，sing-box 本地端口可以是任意
             default_port="8008"
        fi
    fi
    printf "${YELLOW}请输入 sing-box 监听端口 (默认: ${default_port}，根据协议有所不同): ${PLAIN}"
    read -r input_port
    sb_port=${input_port:-${default_port}}
    if ! [[ "${sb_port}" =~ ^[0-9]+$ ]] || [ "${sb_port}" -lt 1 ] || [ "${sb_port}" -gt 65535 ]; then error_exit "端口号无效。"; fi
    info "sing-box 将监听端口: ${sb_port}"

    # 根据协议类型确定是否需要用户提供域名或服务器IP
    case "${selected_protocol}" in
        vmess_ws|vless_ws) # WS 协议通常配合 CDN，依赖 cf_domain (后续配置) 或直连 IP
            if [[ "${cf_use_tunnel}" == "no" ]]; then # 如果不用 CF 隧道，则需要服务器IP
                get_server_ip
                user_domain="${server_ip_address}" # 用 IP 作为链接中的地址
            fi
            sb_ws_path="/${sb_uuid}-${selected_protocol%%_*}" # 例如 /uuid-vmess 或 /uuid-vless
            info "WebSocket 路径将设置为: ${sb_ws_path}"
            ;;
        vless_reality_tcp_vision)
            get_server_ip # Reality 通常需要直连服务器IP
            user_domain="${server_ip_address}" # 链接中用IP
            printf "${YELLOW}请输入 Reality Handshake SNI/目标服务器域名 (例如: www.microsoft.com): ${PLAIN}"
            read -r reality_dest_domain_input
            if [ -z "${reality_dest_domain_input}" ];then reality_dest_domain_input="www.microsoft.com";fi
            user_domain_sni="${reality_dest_domain_input}" # 用于SNI欺骗
            info "Reality SNI 将设置为: ${user_domain_sni}"
            ;;
        hysteria2)
            get_server_ip # Hysteria2 通常直连
            user_domain="${server_ip_address}"
            printf "${YELLOW}请输入 Hysteria2 密码 (OBFS): ${PLAIN}"
            read -rs hysteria2_password; echo
            if [ -z "${hysteria2_password}" ]; then error_exit "Hysteria2 密码不能为空。"; fi
            printf "${YELLOW}请输入 Hysteria2 上传带宽 (Mbps, 例如 50): ${PLAIN}"; read -r hysteria2_up_mbps
            printf "${YELLOW}请输入 Hysteria2 下载带宽 (Mbps, 例如 200): ${PLAIN}"; read -r hysteria2_down_mbps
            hysteria2_up_mbps=${hysteria2_up_mbps:-50}
            hysteria2_down_mbps=${hysteria2_down_mbps:-200}
            # Hysteria2 SNI (可选，如果服务器端TLS配置了server_name)
            # printf "${YELLOW}请输入用于 Hysteria2 的 SNI/域名 (如果留空，将使用自签名证书的IP): ${PLAIN}"; read -r user_domain_sni
            user_domain_sni="${user_domain}" # Hysteria2 链接中 SNI 可以是服务器IP或真实域名
            ;;
        trojan_tcp_tls|vless_tcp_tls)
            get_server_ip
            printf "${YELLOW}请输入您的域名 (用于TLS证书和SNI，必须已解析到本服务器IP ${server_ip_address}): ${PLAIN}"
            read -r user_domain_input
            if [ -z "${user_domain_input}" ]; then error_exit "域名不能为空，因 sing-box 将处理 TLS。"; fi
            user_domain="${user_domain_input}" # 链接和SNI都用这个域名
            user_domain_sni="${user_domain_input}"

            printf "${YELLOW}请输入 TLS 证书 (.pem 或 .crt) 文件的完整路径: ${PLAIN}"
            read -r server_cert_path
            if [ ! -f "${server_cert_path}" ]; then 
                # 生成自签名证书
                run_sudo mkdir -p "${SB_CONFIG_DIR}"
                server_key_path="${SB_CONFIG_DIR}/server_key.key"
                server_cert_path="${SB_CONFIG_DIR}/server_cert.pem"
                openssl ecparam -genkey -name prime256v1 -out "${server_key_path}"
                openssl req -new -x509 -days 3650 -key "${server_key_path}" -out "${server_cert_path}" -subj "/CN=bing.com"
            else
                printf "${YELLOW}请输入 TLS 私钥 (.key) 文件的完整路径: ${PLAIN}"
                read -r server_key_path
                if [ ! -f "${server_key_path}" ]; 
                    then error_exit "私钥文件路径无效: ${server_key_path}"; 
                fi
            fi

            if [[ "${selected_protocol}" == "trojan_tcp_tls" ]]; then
                printf "${YELLOW}请输入 Trojan 密码: ${PLAIN}"
                read -rs trojan_password; echo
                if [ -z "${trojan_password}" ]; then error_exit "Trojan 密码不能为空。"; fi
            fi
            ;;
        *) error_exit "内部错误：未知的 selected_protocol: ${selected_protocol} 在 get_common_config" ;;
    esac
}


# --- Sing-box 配置 (根据选择的协议) ---
configure_sing_box() {
    info "开始配置 sing-box (${selected_protocol})..."
    run_sudo mkdir -p "${SB_CONFIG_DIR}"
    run_sudo chmod 700 "${SB_CONFIG_DIR}"
    info "正在生成 sing-box ${selected_protocol} 配置文件: ${SB_CONFIG_FILE}"
    
    local inbound_json_string="" # 用于存储具体协议的inbound JSON
    info "inbound_json_string的值：$inbound_json_string"
    case "${selected_protocol}" in
        vmess_ws)
            inbound_json_string=$(jq -n \
                --arg uuid "${sb_uuid}" --argjson port "${sb_port}" --arg path "${sb_ws_path}" \
                '{type: "vmess", tag: "vmess-ws-in", listen: "::", listen_port: $port, users: [ { uuid: $uuid, alterId: 0 } ], transport: {type: "ws", path: $path, early_data_header_name: "Sec-WebSocket-Protocol"}}')
            ;;
        vless_ws)
            inbound_json_string=$(jq -n \
                --arg uuid "${sb_uuid}" --argjson port "${sb_port}" --arg path "${sb_ws_path}" \
                '{type: "vless", tag: "vless-ws-in", listen: "::", listen_port: $port, users: [ { uuid: $uuid, flow: "" } ], transport: {type: "ws", path: $path, early_data_header_name: "Sec-WebSocket-Protocol"}}')
            ;;
        vless_reality_tcp_vision)
            # --- Reality 密钥对生成逻辑 ---
            info "为 VLESS+Reality 生成或获取密钥对..."
            # 初始化将要设置的变量
            reality_private_key=""
            reality_public_key=""
            reality_short_id="" # short_id 的处理稍后进行
            local keypair_generated_successfully=false
            local keypair_output_buffer="" # 用于临时存储命令的输出

            # 尝试1: 使用 "utility reality-keypair" (sing-box 1.9+ 推荐)
            info "尝试使用 'utility reality-keypair' 命令 (sing-box 1.9+)..."
            # 将标准错误重定向到临时文件，以便后续查看具体错误
            if keypair_output_buffer=$(run_sudo "${SB_INSTALL_PATH}" utility reality-keypair 2> "${TMP_DIR}/reality_cmd_err.txt"); then
                # 命令执行成功 (退出码为0)
                if echo "${keypair_output_buffer}" | grep -q 'PrivateKey' && echo "${keypair_output_buffer}" | grep -q 'PublicKey'; then
                    info "通过 'utility reality-keypair' 成功生成密钥对。"
                    reality_private_key=$(echo "${keypair_output_buffer}" | grep 'PrivateKey' | awk '{print $2}' | tr -d '"')
                    reality_public_key=$(echo "${keypair_output_buffer}" | grep 'PublicKey' | awk '{print $2}' | tr -d '"')
                    keypair_generated_successfully=true
                else
                    warn "'utility reality-keypair' 命令执行成功，但输出格式不符合预期 (未找到 PrivateKey 或 PublicKey)。"
                    warn "命令输出: ${keypair_output_buffer}"
                    warn "命令错误流: $(cat "${TMP_DIR}/reality_cmd_err.txt" 2>/dev/null || echo '无')"
                fi
            else
                # 命令执行失败 (退出码非0)
                warn "'utility reality-keypair' 命令执行失败或不可用。"
                warn "错误信息: $(cat "${TMP_DIR}/reality_cmd_err.txt" 2>/dev/null || echo '无详细错误信息')"
            fi
            rm -f "${TMP_DIR}/reality_cmd_err.txt" # 清理临时错误文件

            # 尝试2: 使用 "generate reality-keypair" (旧版 sing-box)，仅当尝试1未成功时
            if ! ${keypair_generated_successfully}; then
                info "尝试使用 'generate reality-keypair' 命令 (旧版 sing-box)..."
                if keypair_output_buffer=$(run_sudo "${SB_INSTALL_PATH}" generate reality-keypair 2> "${TMP_DIR}/reality_cmd_err.txt"); then
                    # 命令执行成功
                    if echo "${keypair_output_buffer}" | grep -q 'PrivateKey' && echo "${keypair_output_buffer}" | grep -q 'PublicKey'; then
                        info "通过 'generate reality-keypair' 成功生成密钥对。"
                        reality_private_key=$(echo "${keypair_output_buffer}" | grep 'PrivateKey' | awk '{print $2}' | tr -d '"')
                        reality_public_key=$(echo "${keypair_output_buffer}" | grep 'PublicKey' | awk '{print $2}' | tr -d '"')
                        keypair_generated_successfully=true
                    else
                        warn "'generate reality-keypair' 命令执行成功，但输出格式不符合预期。"
                        warn "命令输出: ${keypair_output_buffer}"
                        warn "命令错误流: $(cat "${TMP_DIR}/reality_cmd_err.txt" 2>/dev/null || echo '无')"
                    fi
                else
                    # 命令执行失败
                    warn "'generate reality-keypair' 命令执行失败或不可用。"
                    warn "错误信息: $(cat "${TMP_DIR}/reality_cmd_err.txt" 2>/dev/null || echo '无详细错误信息')"
                fi
                rm -f "${TMP_DIR}/reality_cmd_err.txt" # 清理临时错误文件
            fi

            # 根据自动生成是否成功，决定是否提示用户手动输入
            if ${keypair_generated_successfully}; then
                # 为了安全，不在日志中直接打印私钥，但可以打印公钥和提示
                info "Reality 公钥已自动生成: ${reality_public_key}"
                info "Reality 私钥已自动生成 (为安全不在此显示)。"
                # 对于 short_id 的处理：
                # sing-box 1.9+ 的 `utility reality-keypair` 可能不直接输出 short_id。
                # short_id 通常由客户端根据公钥选择或自动派生，或者用户可以指定一个。
                # 服务端配置通常不需要 short_id，但客户端链接中会使用。
                printf "${YELLOW}Reality Short ID (可选，客户端使用，通常8位十六进制，可由公钥派生或自定义): ${PLAIN}"
                read -r reality_short_id_input # 读取用户可能输入的 short_id
                if [ -n "${reality_short_id_input}" ]; then
                    reality_short_id="${reality_short_id_input}"
                    info "将使用用户提供的 Reality Short ID: ${reality_short_id}"
                else
                    # 如果用户未输入，可以尝试从公钥生成一个示例 (可选，且需要 xxd 和 sha256sum)
                    # 或者直接将其留空，让客户端处理
                    reality_short_id="" # 默认为空
                    info "未提供 Short ID，客户端将自行处理或不使用。"
                fi
            else
                # 两个自动生成命令都失败了，提示用户手动输入
                warn "自动生成 Reality 密钥对失败。请手动提供以下信息:"
                printf "${YELLOW}请输入 Reality Private Key: ${PLAIN}"; read -r reality_private_key
                printf "${YELLOW}请输入 Reality Public Key: ${PLAIN}"; read -r reality_public_key
                printf "${YELLOW}请输入 Reality Short ID (通常为8位十六进制字符): ${PLAIN}"; read -r reality_short_id
            fi
            if [ -z "${reality_private_key}" ] || [ -z "${reality_public_key}" ]; then
                error_exit "Reality 密钥对获取/输入失败。"
            fi
            # 如果 reality_short_id 为空，并且 reality_public_key 非空，则尝试从公钥生成
            if [ -z "${reality_short_id}" ] && [ -n "${reality_public_key}" ]; then
                reality_short_id=$(echo -n "${reality_public_key}" | xxd -r -p | sha256sum | head -c 16 || echo ' Реальностью является краткое описание')
            fi
            # 服务端通常不需要配置 short_id，客户端使用\
            inbound_json_string=$(jq -n \
                --arg uuid "${sb_uuid}" --argjson port "${sb_port}" \
                --arg reality_sni "${user_domain_sni}" \
                --arg private_key "${reality_private_key}" \
                --arg short_id "${reality_short_id}" \
                --arg public_key "${reality_public_key}" \
                '{
                    type: "vless", tag: "vless-reality-in", listen: "::", listen_port: $port,
                    users: [ { uuid: $uuid, flow: "xtls-rprx-vision" } ],
                    tls: {
                        enabled: true,
                        server_name: $reality_sni, # 伪装的SNI
                        reality: {
                            enabled: true,
                            handshake: { server: $reality_sni, server_port: 443 }, # 伪装的目标服务器和端口
                            private_key: $private_key,
                            short_id: [$short_id] # 服务端可以不指定，让客户端自行匹配
                            #public_key: $public_key # public_key 在服务端配置中不需要
                        }
                    }
                }')
            ;;
        hysteria2)
        # Hysteria2 的 SNI 主要用于客户端链接和服务器TLS配置
        # 生成自签名证书
            openssl ecparam -genkey -name prime256v1 -out "${SB_CONFIG_DIR}/private.key"
            openssl req -new -x509 -days 3650 -key "${SB_CONFIG_DIR}/private.key" -out "${SB_CONFIG_DIR}/cert.pem" -subj "/CN=bing.com"
            inbound_json_string=$(jq -n \
                --argjson port "${sb_port}" \
                --arg password "${hysteria2_password}" \
                --argjson up_mbps "${hysteria2_up_mbps}" \
                --argjson down_mbps "${hysteria2_down_mbps}" \
                --arg pubkey "${SB_CONFIG_DIR}/cert.pem" \
                --arg prikey "${SB_CONFIG_DIR}/private.key" \
                '{
                    type: "hysteria2", tag: "hysteria2-in", listen: "::", listen_port: $port,
                    up_mbps: $up_mbps, down_mbps: $down_mbps,
                    obfs: { type: "salamander", password: $password },
                    tls: {
                        "enabled": true,
                        "alpn": [
                            "h3"
                        ],
                        "min_version":"1.3",
                        "max_version":"1.3",
                        "certificate_path": $pubkey,
                        "key_path": $prikey
                    }
                }')
            ;;
        trojan_tcp_tls)
            inbound_json_string=$(jq -n \
                --argjson port "${sb_port}" \
                --arg password "${trojan_password}" \
                --arg domain "${user_domain}" \
                --arg cert_path "${server_cert_path}" \
                --arg key_path "${server_key_path}" \
                '{
                    type: "trojan", tag: "trojan-in", listen: "::", listen_port: $port,
                    users: [ { password: $password } ],
                    tls: {
                        enabled: true,
                        server_name: $domain,
                        certificate_path: $cert_path,
                        key_path: $key_path
                    }
                }')
            ;;
        vless_tcp_tls)
            inbound_json_string=$(jq -n \
                --arg uuid "${sb_uuid}" --argjson port "${sb_port}" \
                --arg domain "${user_domain}" \
                --arg cert_path "${server_cert_path}" \
                --arg key_path "${server_key_path}" \
                '{
                    type: "vless", tag: "vless-tls-in", listen: "::", listen_port: $port,
                    users: [ { uuid: $uuid, flow: "" } ], # 可选 flow: "xtls-rprx-vision"
                    tls: {
                        enabled: true,
                        server_name: $domain,
                        certificate_path: $cert_path,
                        key_path: $key_path
                    }
                }')
            ;;
        *) error_exit "内部错误：未知的 selected_protocol: ${selected_protocol} 无法生成配置。" ;;
    esac

    # 构建完整的 config.json
    # 如果需要支持多种协议同时监听，可以将 $inbound_config 放入一个数组，并允许多次选择协议
    if ! run_sudo sh -c "jq -n \
        --arg log_file \"${SB_LOG_FILE}\" \
        --argjson inbound_config '${inbound_json_string}' \
        '{
            \"log\": { \"level\": \"info\", \"timestamp\": true, \"output\": \$log_file },
            \"dns\": { \"servers\": [ {\"address\": \"8.8.8.8\",\"detour\": \"direct\"}, {\"address\": \"1.1.1.1\",\"detour\": \"direct\"} ] },
            \"inbounds\": [ \$inbound_config ],
            \"outbounds\": [{\"type\": \"direct\",\"tag\": \"direct\"}],
            \"route\": {\"rules\": []}
        }' > '${SB_CONFIG_FILE}'"; then
        error_exit "生成 sing-box 配置文件 (${SB_CONFIG_FILE}) 失败。"
    fi

    run_sudo chmod 600 "${SB_CONFIG_FILE}"
    success "sing-box (${selected_protocol}) 配置完成。配置文件位于: ${SB_CONFIG_FILE}"
}


# --- Sing-box 安装 ---
install_sing_box() { # ... (与版本12.1一致，但注意 OpenRC 脚本中的 command_args 可能需要根据协议调整) ...
    info "开始安装 sing-box..."
    local latest_tag download_url archive_name extracted_dir binary_in_archive
    local sb_openrc_script_path="/etc/init.d/${SB_SERVICE_NAME}"
    local sb_openrc_confd_path="/etc/conf.d/${SB_SERVICE_NAME}"

    info "正在获取 sing-box 最新版本信息..."
    # shellcheck disable=SC2016
    latest_tag=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name // empty' | sed 's/^v//')
    if [ -z "${latest_tag}" ]; then
        warn "自动获取 sing-box 最新版本失败。请手动输入版本号 (例如: 1.9.0)，或留空尝试。"
        read -r input_tag
        if [ -n "$input_tag" ]; then latest_tag="$input_tag"; else error_exit "未能获取 sing-box 版本信息，安装中止。"; fi
    fi
    info "准备安装 sing-box 版本: v${latest_tag}"
    archive_name="sing-box-${latest_tag}-${detected_os}-${detected_arch}.tar.gz"
    download_url="https://github.com/SagerNet/sing-box/releases/download/v${latest_tag}/${archive_name}"
    if [[ "${detected_arch}" == "armv7" || "${detected_arch}" == "armv6" ]]; then
        local potential_arch_names=("${detected_arch}" "arm"); local found_url=false
        for arch_variant in "${potential_arch_names[@]}"; do
            local archive_name_variant="sing-box-${latest_tag}-${detected_os}-${arch_variant}.tar.gz"
            local download_url_variant="https://github.com/SagerNet/sing-box/releases/download/v${latest_tag}/${archive_name_variant}"
            info "尝试检查下载链接 (架构: ${arch_variant}): ${download_url_variant}"
            if curl --output /dev/null --silent --head --fail "${download_url_variant}"; then
                archive_name="${archive_name_variant}"; download_url="${download_url_variant}"; info "找到有效下载链接: ${download_url}"; found_url=true; break
            else info "链接无效: ${download_url_variant}"; fi
        done
        if ! ${found_url}; then error_exit "未能找到适用于架构 '${detected_arch}' 或 'arm' 的 sing-box 下载链接。"; fi
    fi
    download_file "${download_url}" "${TMP_DIR}/${archive_name}" "sing-box v${latest_tag} 压缩包"
    info "正在解压 ${archive_name}..."; extracted_dir="${TMP_DIR}/sing-box-extracted"; mkdir -p "${extracted_dir}"
    if ! tar -xzf "${TMP_DIR}/${archive_name}" -C "${extracted_dir}"; then error_exit "解压 sing-box 压缩包 (${archive_name}) 失败。"; fi
    binary_in_archive=$(find "${extracted_dir}" -type f -name "sing-box" | head -n 1)
    if [ -z "${binary_in_archive}" ]; then error_exit "在解压的目录中未找到 'sing-box' 二进制文件。"; fi
    info "找到 sing-box 二进制文件: ${binary_in_archive}"
    info "正在安装 sing-box 到 ${SB_INSTALL_PATH}..."; run_sudo install -m 755 "${binary_in_archive}" "${SB_INSTALL_PATH}"
    info "正在设置 sing-box 系统服务 (使用 ${detected_init_system})..."
    manage_service "stop" "${SB_SERVICE_NAME}" &>/dev/null || true
    manage_service "disable" "${SB_SERVICE_NAME}" &>/dev/null || true

    # 服务卸载和用户/组创建逻辑，根据init system调整
    if [[ "${detected_init_system}" == "openrc" ]]; then
        manage_service "uninstall" "${SB_SERVICE_NAME}" "${sb_openrc_script_path}" "${sb_openrc_confd_path}" &>/dev/null || true

        # 判断系统可用命令并创建组
        if ! getent group "${SB_SERVICE_NAME}" >/dev/null; then
            if command -v groupadd &>/dev/null; then
                run_sudo groupadd -r "${SB_SERVICE_NAME}" || warn "创建组 ${SB_SERVICE_NAME} 失败。"
            elif command -v addgroup &>/dev/null; then
                run_sudo addgroup -S "${SB_SERVICE_NAME}" || warn "创建组 ${SB_SERVICE_NAME} 失败。"
            else
                warn "无法创建组：未找到 groupadd 或 addgroup 命令。"
            fi
        fi

        # 判断系统可用命令并创建用户
        if ! getent passwd "${SB_SERVICE_NAME}" >/dev/null; then
            if command -v useradd &>/dev/null; then
                run_sudo useradd -r -g "${SB_SERVICE_NAME}" -d "${SB_CONFIG_DIR}" -s /sbin/nologin -c "${SB_SERVICE_NAME} service user" "${SB_SERVICE_NAME}" || warn "创建用户 ${SB_SERVICE_NAME} 失败。"
            elif command -v adduser &>/dev/null; then
                run_sudo adduser -S -H -D -G "${SB_SERVICE_NAME}" -s /sbin/nologin "${SB_SERVICE_NAME}" || warn "创建用户 ${SB_SERVICE_NAME} 失败。"
            else
                warn "无法创建用户：未找到 useradd 或 adduser 命令。"
            fi
        fi

        run_sudo chown -R "${SB_SERVICE_NAME}:${SB_SERVICE_NAME}" "${SB_CONFIG_DIR}"

    elif [[ "${detected_init_system}" == "systemd" ]]; then
        manage_service "uninstall" "${SB_SERVICE_NAME}"

    else # SysVinit 或 unknown
        if [[ "$(run_sudo "${SB_INSTALL_PATH}" help service uninstall 2>&1 || true)" != *"unknown command"* ]]; then
            run_sudo "${SB_INSTALL_PATH}" service -c "${SB_CONFIG_FILE}" uninstall &>/dev/null || true
        fi
    fi

    
    # 服务安装
    if [[ "${detected_init_system}" == "systemd" ]]; then
        # shellcheck disable=SC2001
        local sb_version_major_minor; sb_version_major_minor=$(run_sudo "${SB_INSTALL_PATH}" version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -n1 | sed 's/\([0-9]*\.[0-9]*\).*/\1/')
        if [[ "${sb_version_major_minor}" < "1.9" ]]; then # sing-box < 1.9
            warn "当前 sing-box 版本 (${sb_version_major_minor}) 可能不支持 'service install' 创建 systemd 服务。"
            local systemd_service_content="[Unit]\nDescription=sing-box service (managed by script)\nAfter=network.target nss-lookup.target\n\n[Service]\nUser=root\nWorkingDirectory=${SB_CONFIG_DIR}\nExecStart=${SB_INSTALL_PATH} run -c ${SB_CONFIG_FILE}\nRestart=on-failure\nRestartSec=10s\nLimitNOFILE=infinity\n\n[Install]\nWantedBy=multi-user.target"
            echo -e "${systemd_service_content}" | run_sudo tee "/etc/systemd/system/${SB_SERVICE_NAME}.service" > /dev/null
            run_sudo chmod 0644 "/etc/systemd/system/${SB_SERVICE_NAME}.service"
            run_sudo systemctl daemon-reload
        else # sing-box >= 1.9
            if ! run_sudo "${SB_INSTALL_PATH}" service -c "${SB_CONFIG_FILE}" install; then
                warn "'${SB_INSTALL_PATH} service -c ${SB_CONFIG_FILE} install' 执行失败。"
                warn "尝试创建基础的 systemd 服务文件 (适用于 sing-box 1.9+ run -D)..."
                local systemd_service_content="[Unit]\nDescription=sing-box service (managed by script)\nDocumentation=https://sing-box.sagernet.org/\nAfter=network.target nss-lookup.target\n\n[Service]\nUser=root\nWorkingDirectory=${SB_CONFIG_DIR}\nExecStart=${SB_INSTALL_PATH} run -D ${SB_CONFIG_DIR}\nRestart=on-failure\nRestartSec=10s\nLimitNOFILE=infinity\n\n[Install]\nWantedBy=multi-user.target"
                echo -e "${systemd_service_content}" | run_sudo tee "/etc/systemd/system/${SB_SERVICE_NAME}.service" > /dev/null
                run_sudo chmod 0644 "/etc/systemd/system/${SB_SERVICE_NAME}.service"
                run_sudo systemctl daemon-reload
            fi
        fi
        manage_service "install" "${SB_SERVICE_NAME}" # 确保 enable
    elif [[ "${detected_init_system}" == "openrc" ]]; then
        manage_service "install" "${SB_SERVICE_NAME}" "${sb_openrc_script_path}" "${sb_openrc_confd_path}" "sing-box proxy service"
    else # SysVinit 或 unknown
        warn "未知初始化系统，尝试使用 sing-box 内建的 'service install'..."
        if [[ "$(run_sudo "${SB_INSTALL_PATH}" help service install 2>&1 || true)" != *"unknown command"* ]]; then
             if ! run_sudo "${SB_INSTALL_PATH}" service -c "${SB_CONFIG_FILE}" install; then warn "sing-box 'service install' 执行失败。"; fi
        else warn "当前 sing-box 版本不支持 'service install'。请手动配置服务。"; fi
    fi

    manage_service "start" "${SB_SERVICE_NAME}"
    if ! manage_service "status" "${SB_SERVICE_NAME}"; then
        warn "sing-box 服务未能成功启动或状态未知。请检查日志。"
        info "  - systemd: journalctl -u ${SB_SERVICE_NAME} -n 50 --no-pager"
        info "  - openrc: /var/log/${SB_SERVICE_NAME}.log 和 /var/log/${SB_SERVICE_NAME}.err"
        info "  - sing-box 日志: ${SB_LOG_FILE}"
    fi
    success "sing-box v${latest_tag} 安装和服务设置尝试完成。"
}


# --- Cloudflare Tunnel 配置 ---
configure_cloudflare_tunnel() { # ... (与版本12.1基本一致) ...
    # 新增：根据选的协议判断是否强烈建议不使用 CF Tunnel
    case "${selected_protocol}" in
        vless_reality_tcp_vision|hysteria2)
            info "您选择的协议 (${selected_protocol}) 通常用于直连服务器以获得最佳性能和特性。"
            info "一般不推荐与 Cloudflare Tunnel (CDN) 配合使用，因其可能影响 Reality 或 Hysteria2 的效果。"
            printf "${YELLOW}尽管如此，您仍然希望配置 Cloudflare Tunnel 吗? (如果您清楚自己在做什么) [y/N]: ${PLAIN}"
            read -r force_cf_choice
            if ! [[ "${force_cf_choice,,}" == "y" || "${force_cf_choice,,}" == "yes" ]]; then
                info "用户选择不为 ${selected_protocol} 配置 Cloudflare Tunnel。"
                cf_use_tunnel="no" # 强制设为 no
                return 0
            fi
            ;;
    esac

    info "开始配置 Cloudflare Tunnel..." # 后续逻辑与 12.1 版相似
    echo -e "${YELLOW}您是否希望使用 Cloudflare Tunnel ?${PLAIN}"
    echo "  1. 是，临时隧道"
    echo "  2. 是，固定隧道 (需要 Token)"
    echo "  3. 否，不使用"
    local choice; while true; do printf "${YELLOW}选择 [1-3] (默认: 3): ${PLAIN}"; read -r choice; choice=${choice:-3}; case "$choice" in 1) cf_use_tunnel="temp"; break ;; 2) cf_use_tunnel="fixed"; break ;; 3) cf_use_tunnel="no"; break ;; *) warn "无效选择。" ;; esac; done
    if [ "${cf_use_tunnel}" = "fixed" ]; then 
        printf "${YELLOW}输入 Cloudflare Tunnel Token: ${PLAIN}"; 
        read -rs cf_tunnel_token; echo; 
        if [ -z "${cf_tunnel_token}" ]; then 
            error_exit "Token 不能为空。";
        fi; 
        printf "${YELLOW}输入用于 Cloudflare Tunnel 的域名 (例如 my.domain.com): ${PLAIN}"; read -r cf_domain
        if [ -z "${cf_domain}" ]; then 
            error_exit "固定隧道域名不能为空。";    
        fi
        if ! echo "${cf_domain}" | grep -Eq '^([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$' && [ "${#cf_domain}" -le 253 ]; then 
            error_exit "域名格式无效。"; 
        fi
        if [ -n "${cf_domain}" ]; then info "CF Tunnel 将用域名: ${cf_domain}"; fi
    fi
    success "Cloudflare Tunnel 配置选项已设定。"
}

# --- Cloudflare Tunnel 安装 ---
install_cloudflare_tunnel() { # ... (与版本12.1基本一致，服务管理部分已整合到 manage_service) ...
    if [ "${cf_use_tunnel}" = "no" ]; then info "跳过 Cloudflare Tunnel 安装。"; return 0; fi
    info "开始安装 Cloudflare Tunnel (cloudflared)..."
    local latest_tag download_url binary_name; local cf_openrc_script_path="/etc/init.d/${CF_SERVICE_NAME}"
    info "获取 cloudflared 最新版本..."; latest_tag=$(curl -s https://api.github.com/repos/cloudflare/cloudflared/releases/latest | jq -r '.tag_name // empty')
    if [ -z "${latest_tag}" ]; then warn "自动获取失败，请手动输入版本 (如 2024.5.0) 或留空尝试 latest:"; read -r input_tag; if [ -n "$input_tag" ]; then latest_tag="$input_tag"; else latest_tag="latest"; info "尝试下载 'latest' 版本。"; fi; fi
    if [[ "$latest_tag" != "latest" ]]; then info "安装 cloudflared 版本: ${latest_tag}"; fi
    binary_name="cloudflared-${detected_os}-${detected_arch}"; if [ "${detected_os}" = "windows" ]; then binary_name="${binary_name}.exe"; fi
    if [[ "$latest_tag" == "latest" ]]; then download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/${binary_name}"; else download_url="https://github.com/cloudflare/cloudflared/releases/download/${latest_tag}/${binary_name}"; fi
    download_file "${download_url}" "${TMP_DIR}/${binary_name}" "cloudflared (${latest_tag})"
    info "安装 cloudflared 到 ${CF_INSTALL_PATH}..."; run_sudo install -m 755 "${TMP_DIR}/${binary_name}" "${CF_INSTALL_PATH}"

    if [ "${cf_use_tunnel}" = "temp" ]; then
        info "启动临时的 Cloudflare Tunnel (本地端口 ${sb_port})..."; info "日志: ${TMP_DIR}/cf_temp_tunnel.log"
        run_sudo nohup "${CF_INSTALL_PATH}" tunnel --url "http://localhost:${sb_port}" --logfile "${TMP_DIR}/cf_temp_tunnel.log" --pidfile "${CF_TEMP_TUNNEL_PID_FILE}" --edge-ip-version auto --no-autoupdate > "${TMP_DIR}/nohup_cf_stdout.log" 2>&1 &
        info "等待临时隧道启动 (最多60秒)..."; local i; for i in {1..60}; do if [ -f "${CF_TEMP_TUNNEL_PID_FILE}" ] && [ -s "${CF_TEMP_TUNNEL_PID_FILE}" ] && ps | grep -q "^\s*$(cat "${CF_TEMP_TUNNEL_PID_FILE}")\s";then success "临时 CF Tunnel 已启动 (PID: $(cat "${CF_TEMP_TUNNEL_PID_FILE}"))."; sleep 3; cf_assigned_temp_domain=$(grep -Eo 'https://[a-z0-9.-]+\.trycloudflare\.com' "${TMP_DIR}/cf_temp_tunnel.log" | head -n 1 | sed 's|https://||'); if [ -n "$cf_assigned_temp_domain" ]; then info "检测到 CF 分配域名: ${cf_assigned_temp_domain}";if [ -z "${cf_domain}" ]; then cf_domain="${cf_assigned_temp_domain}"; info "将用此域名生成链接: ${cf_domain}"; fi; else info "未自动检测到 CF 分配域名。"; if [ -z "${cf_domain}" ]; then warn "链接地址可能不准确。"; fi; fi; break; fi; echo -n "."; sleep 1; done; echo
        if ! [ -f "${CF_TEMP_TUNNEL_PID_FILE}" ] && [ -s "${CF_TEMP_TUNNEL_PID_FILE}" ] && ps | grep -q "^\s*$(cat "${CF_TEMP_TUNNEL_PID_FILE}")\s";then warn "临时 CF Tunnel 可能启动失败。检查日志。"; fi
    elif [ "${cf_use_tunnel}" = "fixed" ]; then
        info "设置永久 Cloudflare Tunnel (使用 Token)..."; run_sudo mkdir -p "${CF_CONFIG_DIR}"; run_sudo chown nobody:nogroup "${CF_CONFIG_DIR}" &>/dev/null || true
        info "尝试使用 'cloudflared service install ${cf_tunnel_token}'..."
        if ! run_sudo "${CF_INSTALL_PATH}" service install "${cf_tunnel_token}"; then
            warn "'cloudflared service install TOKEN' 失败或不受支持。"; warn "非 systemd 系统可能需额外配置或 cloudflared-openrc 包。"
            if [[ "${detected_init_system}" == "openrc" ]]; then warn "OpenRC 固定隧道通常需手动配置 ${CF_CONFIG_DIR}/config.yml 和凭据。脚本创建的 OpenRC 脚本可能不足。"; fi
        else
            success "'cloudflared service install TOKEN' 已执行。"
            if [[ "${detected_init_system}" == "systemd" ]]; then manage_service "enable" "${CF_SERVICE_NAME}"; manage_service "start" "${CF_SERVICE_NAME}";
            elif [[ "${detected_init_system}" == "openrc" ]]; then if [ -f "${cf_openrc_script_path}" ]; then manage_service "enable" "${CF_SERVICE_NAME}"; manage_service "start" "${CF_SERVICE_NAME}"; else warn "CF 已执行 'service install TOKEN'，但 OpenRC 脚本 ${cf_openrc_script_path} 未找到或不由脚本管理。"; fi; fi
        fi
        if ! manage_service "status" "${CF_SERVICE_NAME}"; then warn "CF 固定隧道服务启动失败或状态未知。确保域名DNS和隧道配置正确。"; fi
    fi
    success "Cloudflare Tunnel 安装和配置尝试完成。"
}


# --- 生成输出链接 (根据选择的协议) ---
generate_output_links() {
    info "正在生成 sing-box (${selected_protocol}) 连接信息..."
    local conn_address="" proxy_port="" conn_host_header="" conn_security="none" conn_sni=""
    local link_remark="sing-box_${selected_protocol}"
    local final_link=""

    # 确定连接地址、端口、TLS设置等
    # 如果使用 Cloudflare Tunnel
    if [ "${cf_use_tunnel}" != "no" ]; then
        # Reality 和 Hysteria2 通常不建议与 CF Tunnel 一起使用，但如果用户强制选择，则按 CF Tunnel 方式配置链接
        if [[ "${selected_protocol}" == "vless_reality_tcp_vision" || "${selected_protocol}" == "hysteria2" ]]; then
            if [[ "${force_cf_choice,,}" == "y" || "${force_cf_choice,,}" == "yes" ]]; then # 检查用户是否强制使用CF
                warn "您选择了 ${selected_protocol} 并强制使用 Cloudflare Tunnel。链接将基于CF域名生成，但这可能不是最佳实践。"
                if [ -n "${cf_domain}" ]; then conn_address="${cf_domain}"; proxy_port="443"; conn_host_header="${cf_domain}"; conn_security="tls"; conn_sni="${cf_domain}"; link_remark+="_CF_${cf_domain}";
                else warn "CF Tunnel 已启用但域名未知。链接地址需手动修改。"; conn_address="YOUR_CF_DOMAIN"; proxy_port="443"; conn_host_header="YOUR_CF_DOMAIN"; conn_security="tls"; conn_sni="YOUR_CF_DOMAIN"; link_remark+="_CF_CheckDomain"; fi
            else # 用户未强制，则 Reality/Hysteria2 直连
                conn_address="${user_domain}" # 此时 user_domain 应该是服务器IP
                proxy_port="${sb_port}"
                conn_host_header="${user_domain_sni:-${user_domain}}" # SNI 可能与地址不同 (如Reality)
                # Reality 和 Hysteria2 自身处理加密，链接中的 security/tls 字段有特定含义或不存在
                if [[ "${selected_protocol}" == "vless_reality_tcp_vision" ]]; then conn_security="reality"; conn_sni="${user_domain_sni}"; fi
                # Hysteria2 链接不直接用 'security=tls' 字段，其加密内建
                link_remark+="_Direct_${conn_address}"
            fi
        else # 其他协议 (VMess-WS, VLESS-WS, Trojan-TCP-TLS, VLESS-TCP-TLS) 可以很好地配合 CF Tunnel
            if [ -n "${cf_domain}" ]; then conn_address="${cf_domain}"; proxy_port="443"; conn_host_header="${cf_domain}"; conn_security="tls"; conn_sni="${cf_domain}"; link_remark+="_CF_${cf_domain}";
            else warn "CF Tunnel 已启用但域名未知。链接地址需手动修改。"; conn_address="YOUR_CF_DOMAIN"; proxy_port="443"; conn_host_header="YOUR_CF_DOMAIN"; conn_security="tls"; conn_sni="YOUR_CF_DOMAIN"; link_remark+="_CF_CheckDomain"; fi
        fi
    else # 不使用 Cloudflare Tunnel (直连)
        conn_address="${user_domain}" # user_domain 在 get_common_config 中已设为IP或用户提供的域名
        proxy_port="${sb_port}"
        conn_host_header="${user_domain_sni:-${user_domain}}"
        if [[ "${selected_protocol}" == "vless_reality_tcp_vision" ]]; then conn_security="reality"; conn_sni="${user_domain_sni}";
        elif [[ "${selected_protocol}" == "trojan_tcp_tls" || "${selected_protocol}" == "vless_tcp_tls" ]]; then conn_security="tls"; conn_sni="${user_domain_sni}"; # sing-box 处理 TLS
        elif [[ "${selected_protocol}" == "hysteria2" ]]; then conn_security="none"; # Hysteria2 链接中不显式标 tls，加密内建
        else conn_security="none"; fi # VMess-WS, VLESS-WS 直连默认无TLS (除非sing-box内部配置)
        link_remark+="_Direct_${conn_address}"
        if [[ "${conn_address}" == "YOUR_SERVER_IP" ]]; then warn "未启用CF Tunnel且未能获取公网IP。"; fi
    fi
    
    # shellcheck disable=SC2046 # jq @uri 需要这种方式
    local encoded_remark=$(echo -n "${link_remark}" | jq -sRr @uri)

    case "${selected_protocol}" in
        vmess_ws)
            local vmess_json; vmess_json=$(jq -n --arg v "2" --arg ps "${link_remark}" --arg add "${conn_address}" --arg port "${proxy_port}" --arg id "${sb_uuid}" --arg aid "0" --arg scy "auto" --arg net "ws" --arg type "none" --arg host "${conn_host_header}" --arg path "${sb_ws_path}" --arg tls "${conn_security}" --arg sni "${conn_sni}" --arg alpn "" --arg fp "" '{v:$v,ps:$ps,add:$add,port:$port,id:$id,aid:$aid,scy:$scy,net:$net,type:$type,host:$host,path:$path,tls:$tls,sni:$sni,alpn:$alpn,fp:$fp}')
            final_link="vmess://$(echo -n "${vmess_json}" | base64 -w0)"
            ;;
        vless_ws)
            # shellcheck disable=SC2046
            local encoded_ws_path=$(echo -n "${sb_ws_path}" | jq -sRr @uri)
            local link_params="type=ws&security=${conn_security}&path=${encoded_ws_path}"
            if [ -n "${conn_host_header}" ]; then link_params+="&host=${conn_host_header}"; fi
            if [ -n "${conn_sni}" ]; then link_params+="&sni=${conn_sni}"; fi
            # VLESS over WS 通常不带 flow，如果需要 Vision，服务端和此处都要改
            final_link="vless://${sb_uuid}@${conn_address}:${proxy_port}?${link_params}#${encoded_remark}"
            ;;
        vless_reality_tcp_vision)
            local client_fp="chrome" # 客户端TLS指纹，可以设为可配置
            # Reality 公钥和 short ID 用于客户端链接
            local link_params="security=reality&sni=${user_domain_sni}&fp=${client_fp}&pbk=${reality_public_key}&sid=${reality_short_id}&type=tcp&flow=xtls-rprx-vision"
            final_link="vless://${sb_uuid}@${conn_address}:${proxy_port}?${link_params}#${encoded_remark}"
            ;;
        hysteria2)
            # Hysteria2 链接格式: hysteria2://user:pass@host:port?sni=yoursni.com&upmbps=100&downmbps=100&obfs=salamander&obfs-password=yourpassword
            # user部分可以省略或用密码代替。这里密码通过 obfs-password 参数传递。
            local link_params="upmbps=${hysteria2_up_mbps}&downmbps=${hysteria2_down_mbps}&obfs=salamander&obfs-password=${hysteria2_password}"
            if [ -n "${user_domain_sni}" ]; then link_params+="&sni=${user_domain_sni}"; fi
            # 如果服务器是自签名证书 (如此脚本中未配置证书路径的默认行为)，客户端可能需要 insecure=1
            # link_params+="&insecure=1" # 酌情添加
            final_link="hysteria2://${conn_address}:${proxy_port}/?${link_params}#${encoded_remark}"
            ;;
        trojan_tcp_tls)
            # trojan://password@domain:port?sni=domain#remark
            local link_params="sni=${conn_sni}&security=tls" # security=tls 是默认，也可不写
            # 如果有其他 trojan 参数如 allowInsecure, peer 等可添加
            final_link="trojan://${trojan_password}@${conn_address}:${proxy_port}?${link_params}#${encoded_remark}"
            ;;
        vless_tcp_tls)
            # vless://uuid@domain:port?type=tcp&security=tls&sni=domain&flow=xtls-rprx-vision#remark
            local link_params="type=tcp&security=tls&sni=${conn_sni}"
            # flow_control="xtls-rprx-vision" # 如果服务端配置了Vision flow
            # if [ -n "${flow_control}" ]; then link_params+="&flow=${flow_control}"; fi
            final_link="vless://${sb_uuid}@${conn_address}:${proxy_port}?${link_params}#${encoded_remark}"
            ;;
        *) error_exit "内部错误：未知的 selected_protocol: ${selected_protocol} 无法生成链接。" ;;
    esac

    echo -e "\n${GREEN}================ Sing-box (${selected_protocol}) 安装与配置摘要 ================${PLAIN}"
    echo -e "  协议类型:         ${YELLOW}${selected_protocol}${PLAIN}"
    echo -e "  Sing-box UUID:     ${YELLOW}${sb_uuid:- (N/A for Hysteria2/Trojan password auth)}${PLAIN}"
    if [[ "${selected_protocol}" == "hysteria2" ]]; then
        echo -e "  Hysteria2 密码:  ${YELLOW}${hysteria2_password}${PLAIN}"
        echo -e "  Hysteria2 带宽: ${YELLOW}UP ${hysteria2_up_mbps} Mbps / DOWN ${hysteria2_down_mbps} Mbps${PLAIN}"
    elif [[ "${selected_protocol}" == "trojan_tcp_tls" ]]; then
        echo -e "  Trojan 密码:     ${YELLOW}${trojan_password}${PLAIN}"
    fi
    if [[ "${selected_protocol}" == "vless_reality_tcp_vision" ]]; then
        echo -e "  Reality 公钥:    ${YELLOW}${reality_public_key}${PLAIN}"
        echo -e "  Reality ShortID: ${YELLOW}${reality_short_id:- (客户端可从公钥派生)}${PLAIN}"
        echo -e "  Reality SNI:     ${YELLOW}${user_domain_sni}${PLAIN}"
    fi
    echo -e "  监听地址:         ${YELLOW}${conn_address}:${proxy_port}${PLAIN}"
    if [[ "${selected_protocol}" == *"_ws" ]]; then # 仅WS协议显示路径
        echo -e "  WebSocket 路径:  ${YELLOW}${sb_ws_path}${PLAIN}"
    fi
    if [ "${cf_use_tunnel}" != "no" ] && ! [[ "${selected_protocol}" == "vless_reality_tcp_vision" || "${selected_protocol}" == "hysteria2" ]] || [[ "${force_cf_choice,,}" == "y" ]]; then
        echo -e "  Cloudflare 域名:  ${YELLOW}${cf_domain:- (请查看日志或Cloudflare仪表板)}${PLAIN}"
        if [ "${cf_use_tunnel}" = "temp" ] && [ -n "${cf_assigned_temp_domain}" ] && [[ "${cf_domain}" != "${cf_assigned_temp_domain}" ]]; then
            echo -e "  (隧道实际分配域名可能为: ${YELLOW}${cf_assigned_temp_domain}${PLAIN})"
        fi
    elif [[ "${selected_protocol}" == "vless_reality_tcp_vision" || "${selected_protocol}" == "hysteria2" ]]; then
        echo -e "  (当前协议通常直连，未使用 Cloudflare Tunnel 暴露)"
    else
        echo -e "  Cloudflare Tunnel: ${RED}未使用${PLAIN}"
    fi

    echo -e "\n${GREEN}${selected_protocol} 连接链接:${PLAIN}"
    echo -e "${YELLOW}${final_link}${PLAIN}\n"

    if command -v $TMP_DIR/qrencode &>/dev/null; then
        echo -e "${GREEN}${selected_protocol} 二维码:${PLAIN}"
        $TMP_DIR/qrencode -t ansiutf8 "${final_link}"
    else info "未安装 'qrencode'，无法生成二维码。"; fi
    echo -e "${GREEN}====================================================================${PLAIN}\n"
    if [ "${cf_use_tunnel}" = "temp" ]; then info "临时 CF Tunnel 正在运行。日志: ${TMP_DIR}/cf_temp_tunnel.log"; fi
}

# --- 卸载功能 ---
# (基本保持不变，服务卸载通过 manage_service 处理)
uninstall_package() {
    info "开始执行卸载流程..."
    local choice
    local sb_openrc_script_path="/etc/init.d/${SB_SERVICE_NAME}"
    local sb_openrc_confd_path="/etc/conf.d/${SB_SERVICE_NAME}"
    local cf_openrc_script_path="/etc/init.d/${CF_SERVICE_NAME}"
    # local cf_openrc_confd_path="/etc/conf.d/${CF_SERVICE_NAME}" # cloudflared 的 conf.d 通常较少

    info "正在停止 sing-box 服务..."
    manage_service "stop" "${SB_SERVICE_NAME}" &>/dev/null || true
    info "正在禁用/卸载 sing-box 服务..."
    manage_service "uninstall" "${SB_SERVICE_NAME}" "${sb_openrc_script_path}" "${sb_openrc_confd_path}" &>/dev/null || true

    if [ -f "${SB_INSTALL_PATH}" ]; then
        info "正在移除 sing-box 二进制文件: ${SB_INSTALL_PATH}"
        run_sudo rm -f "${SB_INSTALL_PATH}"
    else
        info "未找到 sing-box 二进制文件 (${SB_INSTALL_PATH})，跳过移除。"
    fi

    if [ -d "${SB_CONFIG_DIR}" ]; then
        printf "${YELLOW}是否移除 sing-box 配置文件目录 ${SB_CONFIG_DIR} (包含 config.json 和日志)? [y/N]: ${PLAIN}"
        read -r choice
        if [[ "${choice,,}" == "y" ]] || [[ "${choice,,}" == "yes" ]]; then
            info "正在移除 sing-box 配置目录: ${SB_CONFIG_DIR}"
            run_sudo rm -rf "${SB_CONFIG_DIR}"
            success "sing-box 配置目录已移除。"
        else
            info "保留 sing-box 配置目录 ${SB_CONFIG_DIR}。"
        fi
    fi

    if [ -f "${CF_INSTALL_PATH}" ]; then
        printf "${YELLOW}是否同时卸载 Cloudflare Tunnel (cloudflared)? [y/N]: ${PLAIN}"
        read -r choice
        if [[ "${choice,,}" == "y" ]] || [[ "${choice,,}" == "yes" ]]; then
            info "正在停止 Cloudflare Tunnel 服务..."
            manage_service "stop" "${CF_SERVICE_NAME}" &>/dev/null || true
            info "正在禁用/卸载 Cloudflare Tunnel 服务..."
            manage_service "uninstall" "${CF_SERVICE_NAME}" "${cf_openrc_script_path}" # CF 的 conf.d 不由此脚本管理
            
            info "正在移除 cloudflared 二进制文件: ${CF_INSTALL_PATH}"
            run_sudo rm -f "${CF_INSTALL_PATH}"

            if [ -d "${CF_CONFIG_DIR}" ]; then
                printf "${YELLOW}是否移除 cloudflared 配置文件目录 ${CF_CONFIG_DIR} (可能包含固定隧道的配置和凭据)? [y/N]: ${PLAIN}"
                read -r choice_cf_config
                if [[ "${choice_cf_config,,}" == "y" ]] || [[ "${choice_cf_config,,}" == "yes" ]]; then
                    info "正在移除 cloudflared 配置目录: ${CF_CONFIG_DIR}"
                    run_sudo rm -rf "${CF_CONFIG_DIR}"
                    success "cloudflared 配置目录已移除。"
                else
                    info "保留 cloudflared 配置目录 ${CF_CONFIG_DIR}。"
                fi
            fi
            info "Cloudflare Tunnel 卸载尝试完成。您可能还需要在 Cloudflare Dashboard 中手动清理隧道和DNS记录。"
        else
            info "跳过卸载 Cloudflare Tunnel。"
        fi
    fi
    success "卸载流程已完成。"
}

# --- 主安装流程 ---
run_installation() {
    mkdir -p "${TMP_DIR}"; echo "Installer Log $(date) - ${SCRIPT_VERSION}" > "${LOG_FILE}"
    info "安装日志将保存在: ${LOG_FILE}"

    detect_environment; detect_init_system; check_dependencies
    
    select_protocol    # 选择协议
    get_common_config  # 获取通用和协议特定的配置参数
    
    # 对于需要提前安装 sing-box 以便使用其工具的协议 (如 Reality keygen)
    if [[ "${selected_protocol}" == "vless_reality_tcp_vision" ]]; then
        info "VLESS+Reality 需要先安装 sing-box 以便生成密钥对。"
        # 简化版安装，只下载和放置二进制文件，不配置服务
        # (实际 install_sing_box 会做得更多，这里只是为了拿到 binary_path)
        # 或者确保 install_sing_box 被调用前，binary_path 变量可用
        # 为了简单，我们假设 install_sing_box 会先被调用一次，或者提示用户
        if [ ! -f "${SB_INSTALL_PATH}" ]; then
             warn "sing-box 主程序 (${SB_INSTALL_PATH}) 尚未安装。"
             warn "将先执行 sing-box 的下载和基础安装步骤以使用其工具。"
             # 这里可以调用一个精简版的 install_sing_box_binary_only()
             # 或者，将 install_sing_box() 分为下载和配置服务两步
             # 暂时依赖于 install_sing_box 会在 configure_sing_box 之前或之内处理二进制文件
        fi
    fi
    
    # 如果 sing-box 还没安装 (例如 Reality 需要它来生成密钥)，先安装核心程序
    if [[ ! -x "${SB_INSTALL_PATH}" ]] && \
       [[ "${selected_protocol}" == "vless_reality_tcp_vision" || -n "$(echo "${selected_protocol}" | grep 'tls')" ]] ; then
        info "部分协议（如Reality, 或由sing-box处理TLS的协议）可能需要sing-box工具或配置其证书。"
        info "将先进行 sing-box 主程序的下载和放置..."
        # 简化：这里只做下载和放置，真正的服务配置在 install_sing_box 中
        # (这部分逻辑在 install_sing_box 函数中有更完整的实现)
        # 实际上，get_common_config 之后，install_sing_box 之前，
        # 如果 Reality 需要生成密钥，此时 SB_INSTALL_PATH 可能还不可用。
        # 调整顺序：install_sing_box (下载和放置二进制) -> get_common_config (可能使用工具) -> configure_sing_box
    fi

    # 调整后的顺序：
    # 1. 下载和放置 sing-box 二进制文件（如果 Reality 等需要其工具）
    #   (这部分逻辑已包含在 install_sing_box 前半部分)
    # 2. 获取用户配置 (包括可能需要 sing-box 工具的 Reality 密钥生成)
    # 3. 生成 sing-box 配置文件
    # 4. 完成 sing-box 服务安装和启动
    # 5. 配置和安装 Cloudflare Tunnel
    # 6. 生成链接

    # 步骤1: 安装 sing-box 主程序 (下载和放置二进制文件)
    # install_sing_box 函数内部分为：获取版本 -> 下载 -> 解压 -> 安装二进制 -> 服务设置
    # 我们需要确保二进制文件在 configure_sing_box (特别是Reality密钥生成) 前可用。
    # 因此，install_sing_box 的调用时机很重要。
    # 或者将 install_sing_box 拆分为 download_and_install_binary 和 setup_service 两部分。

    # 简化流程：先调用 install_sing_box 完成二进制安装
    install_sing_box_binary_only # 新增一个只负责下载和安装二进制的函数

    # 现在 sing-box 二进制应该可用了
    configure_sing_box # 生成配置文件，Reality 密钥生成在此函数内部处理

    install_sing_box_service_setup # 新增一个只负责设置和启动服务的函数

    configure_cloudflare_tunnel
    install_cloudflare_tunnel 
    generate_output_links

    success "所有安装和配置操作已成功完成！"
    info "详细日志请查看: ${LOG_FILE}"
}

# --- 新增：仅下载和安装 sing-box 二进制文件 ---
install_sing_box_binary_only() {
    info "开始下载和安装 sing-box 二进制文件..."
    # 此处复制 install_sing_box 函数中 下载、解压、安装二进制到 SB_INSTALL_PATH 的部分
    # 省略服务管理部分
    local latest_tag download_url archive_name extracted_dir binary_in_archive
    info "正在获取 sing-box 最新版本信息..."
    latest_tag=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name // empty' | sed 's/^v//')
    if [ -z "${latest_tag}" ]; then
        warn "自动获取 sing-box 最新版本失败。请手动输入版本号:"; read -r input_tag
        if [ -n "$input_tag" ]; then latest_tag="$input_tag"; else error_exit "未能获取 sing-box 版本信息。"; fi
    fi
    info "准备下载 sing-box 版本: v${latest_tag}"
    archive_name="sing-box-${latest_tag}-${detected_os}-${detected_arch}.tar.gz"
    download_url="https://github.com/SagerNet/sing-box/releases/download/v${latest_tag}/${archive_name}"
    # ... (arm 架构兼容性检查逻辑，同 install_sing_box) ...
    if [[ "${detected_arch}" == "armv7" || "${detected_arch}" == "armv6" ]]; then
        local potential_arch_names=("${detected_arch}" "arm"); local found_url=false
        for arch_variant in "${potential_arch_names[@]}"; do
            local archive_name_variant="sing-box-${latest_tag}-${detected_os}-${arch_variant}.tar.gz"
            local download_url_variant="https://github.com/SagerNet/sing-box/releases/download/v${latest_tag}/${archive_name_variant}"
            if curl --output /dev/null --silent --head --fail "${download_url_variant}"; then
                archive_name="${archive_name_variant}"; download_url="${download_url_variant}"; found_url=true; break
            fi
        done
        if ! ${found_url}; then error_exit "未能找到适用于架构 '${detected_arch}' 或 'arm' 的 sing-box 下载链接。"; fi
    fi
    download_file "${download_url}" "${TMP_DIR}/${archive_name}" "sing-box v${latest_tag} (binary only)"
    extracted_dir="${TMP_DIR}/sing-box-extracted"; mkdir -p "${extracted_dir}"
    if ! tar -xzf "${TMP_DIR}/${archive_name}" -C "${extracted_dir}"; then error_exit "解压 sing-box 失败 (binary only)。"; fi
    binary_in_archive=$(find "${extracted_dir}" -type f -name "sing-box" | head -n 1)
    if [ -z "${binary_in_archive}" ]; then error_exit "未找到 'sing-box' 二进制文件 (binary only)。"; fi
    info "正在安装 sing-box 二进制到 ${SB_INSTALL_PATH} (binary only)..."
    run_sudo install -m 755 "${binary_in_archive}" "${SB_INSTALL_PATH}"
    success "sing-box 二进制文件已安装到 ${SB_INSTALL_PATH}"
}

# --- 新增：仅设置和启动 sing-box 服务 ---
install_sing_box_service_setup() {
    info "开始设置和启动 sing-box 服务..."
    # 此处复制 install_sing_box 函数中 服务管理的部分
    local sb_openrc_script_path="/etc/init.d/${SB_SERVICE_NAME}"
    local sb_openrc_confd_path="/etc/conf.d/${SB_SERVICE_NAME}"
    info "正在设置 sing-box 系统服务 (使用 ${detected_init_system})..."
    manage_service "stop" "${SB_SERVICE_NAME}" &>/dev/null || true
    manage_service "disable" "${SB_SERVICE_NAME}" &>/dev/null || true
    # ... (服务卸载、用户组创建、服务安装、启动、状态检查逻辑，同 install_sing_box 的后半部分) ...
    # (这个复制粘贴会导致代码冗余，更好的方式是 install_sing_box 内部逻辑拆分得更细)
    # 为了快速演示，这里假设已复制粘贴完成
    # (具体实现参考版本 12.1 的 install_sing_box 后半部分并进行适配)
    # 例如:
    if [[ "${detected_init_system}" == "openrc" ]]; then
        manage_service "uninstall" "${SB_SERVICE_NAME}" "${sb_openrc_script_path}" "${sb_openrc_confd_path}" &>/dev/null || true
                # 判断系统可用命令并创建组
        if ! getent group "${SB_SERVICE_NAME}" >/dev/null; then
            if command -v groupadd &>/dev/null; then
                run_sudo groupadd -r "${SB_SERVICE_NAME}" || warn "创建组 ${SB_SERVICE_NAME} 失败。"
            elif command -v addgroup &>/dev/null; then
                run_sudo addgroup -S "${SB_SERVICE_NAME}" || warn "创建组 ${SB_SERVICE_NAME} 失败。"
            else
                warn "无法创建组：未找到 groupadd 或 addgroup 命令。"
            fi
        fi
                # 判断系统可用命令并创建用户
        if ! getent passwd "${SB_SERVICE_NAME}" >/dev/null; then
            if command -v useradd &>/dev/null; then
                run_sudo useradd -r -g "${SB_SERVICE_NAME}" -d "${SB_CONFIG_DIR}" -s /sbin/nologin -c "${SB_SERVICE_NAME} service user" "${SB_SERVICE_NAME}" || warn "创建用户 ${SB_SERVICE_NAME} 失败。"
            elif command -v adduser &>/dev/null; then
                run_sudo adduser -S -H -D -G "${SB_SERVICE_NAME}" -s /sbin/nologin "${SB_SERVICE_NAME}" || warn "创建用户 ${SB_SERVICE_NAME} 失败。"
            else
                warn "无法创建用户：未找到 useradd 或 adduser 命令。"
            fi
        fi
        run_sudo chown -R "${SB_SERVICE_NAME}:${SB_SERVICE_NAME}" "${SB_CONFIG_DIR}"
    elif [[ "${detected_init_system}" == "systemd" ]]; then
        manage_service "uninstall" "${SB_SERVICE_NAME}"
    fi
    
    if [[ "${detected_init_system}" == "systemd" ]]; then
        # shellcheck disable=SC2001
        local sb_version_major_minor; sb_version_major_minor=$(run_sudo "${SB_INSTALL_PATH}" version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -n1 | sed 's/\([0-9]*\.[0-9]*\).*/\1/')
        if [[ "${sb_version_major_minor}" < "1.9" ]]; then
            local systemd_service_content="[Unit]\nDescription=sing-box service (managed by script)\nAfter=network.target nss-lookup.target\n\n[Service]\nUser=root\nWorkingDirectory=${SB_CONFIG_DIR}\nExecStart=${SB_INSTALL_PATH} run -c ${SB_CONFIG_FILE}\nRestart=on-failure\nRestartSec=10s\nLimitNOFILE=infinity\n\n[Install]\nWantedBy=multi-user.target"
            echo -e "${systemd_service_content}" | run_sudo tee "/etc/systemd/system/${SB_SERVICE_NAME}.service" > /dev/null
        else # sing-box >= 1.9
            if ! run_sudo "${SB_INSTALL_PATH}" service -c "${SB_CONFIG_FILE}" install; then
                warn "'${SB_INSTALL_PATH} service -c ${SB_CONFIG_FILE} install' failed."
                local systemd_service_content="[Unit]\nDescription=sing-box service (managed by script)\nAfter=network.target nss-lookup.target\n\n[Service]\nUser=root\nWorkingDirectory=${SB_CONFIG_DIR}\nExecStart=${SB_INSTALL_PATH} run -D ${SB_CONFIG_DIR}\nRestart=on-failure\nRestartSec=10s\nLimitNOFILE=infinity\n\n[Install]\nWantedBy=multi-user.target"
                echo -e "${systemd_service_content}" | run_sudo tee "/etc/systemd/system/${SB_SERVICE_NAME}.service" > /dev/null
            fi
        fi
        run_sudo systemctl daemon-reload
        manage_service "install" "${SB_SERVICE_NAME}" # enable
    elif [[ "${detected_init_system}" == "openrc" ]]; then
        manage_service "install" "${SB_SERVICE_NAME}" "${sb_openrc_script_path}" "${sb_openrc_confd_path}" "sing-box proxy service"
    fi
    manage_service "start" "${SB_SERVICE_NAME}"
    if ! manage_service "status" "${SB_SERVICE_NAME}"; then warn "sing-box 服务启动失败或状态未知。"; fi
    success "sing-box 服务设置完成。"
}


# --- 脚本主入口 ---
main() {
    echo -e "\n${GREEN}欢迎使用 sing-box 与 Cloudflare Tunnel 自动化安装脚本${PLAIN}"
    echo -e "版本: ${YELLOW}${SCRIPT_VERSION}${PLAIN}"
    echo -e "此脚本将引导您完成安装或卸载过程。"
    echo -e "作者: (原始脚本作者 + AI 改进与兼容性增强)"
    echo -e "${BLUE}===============================================================${PLAIN}"
    echo
    mkdir -p "${TMP_DIR}"; echo "Installer Log $(date) - ${SCRIPT_VERSION}" > "${LOG_FILE}"
    info "安装日志将保存在: ${LOG_FILE}"
    detect_environment; detect_init_system; 
    if [ "$#" -gt 0 ]; then 
        case "$1" in
            uninstall|remove|delete) run_sudo echo "卸载操作需sudo..."; uninstall_package; exit 0 ;;
            help|--help|-h) printf "用法: $0 [命令]\n命令:\n  (无)        执行安装流程。\n  uninstall   卸载。\n  help        显示帮助。"; exit 0 ;;
            *) error_exit "未知参数: '$1'. 使用 '$0 help'." ;;
        esac
    fi
    run_sudo echo "安装操作需sudo..."
    
    # 修改后的主安装流程调用顺序

    check_dependencies
    
    select_protocol                # 1. 用户选择协议
    get_common_config              # 2. 获取通用和协议特定参数
    install_sing_box_binary_only   # 3. 确保 sing-box 二进制文件已安装 (Reality keygen 可能需要)
    configure_sing_box             # 4. 根据选择和参数生成配置文件
    install_sing_box_service_setup # 5. 设置并启动 sing-box 服务
    
    # Cloudflare Tunnel (如果选择)
    configure_cloudflare_tunnel
    install_cloudflare_tunnel 
    
    generate_output_links          # 6. 生成分享链接

    success "所有安装和配置操作已成功完成！"
    info "详细日志请查看: ${LOG_FILE}"
}

# --- 执行主函数 ---
main "$@"
