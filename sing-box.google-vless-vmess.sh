#!/bin/bash
# 脚本：sing-box 与 Cloudflare Tunnel 自动化安装器 (兼容 systemd 和 OpenRC)
# 版本：12.1-MultiProtocol (支持 VMess 和 VLESS 选择)

# --- 严格模式与全局设置 ---
set -euo pipefail # -e: 命令失败时退出, -u: 使用未定义变量时退出, -o pipefail: 管道中命令失败则整个管道失败
export LANG=en_US.UTF-8 # 避免因语言环境导致的问题

# --- 全局配置与变量 (初始化) ---
readonly SCRIPT_VERSION="12.1-MultiProtocol" # 脚本版本

# 临时目录 (使用PID确保唯一性)
TMP_DIR="/tmp/sing-box-installer-$$"
# 日志文件路径
LOG_FILE="${TMP_DIR}/installer.log"
# Cloudflare 临时隧道 PID 文件
CF_TEMP_TUNNEL_PID_FILE="${TMP_DIR}/cf_temp_tunnel.pid"

# 安装路径定义
SB_INSTALL_PATH="/usr/local/bin/sing-box"
SB_CONFIG_DIR="/etc/sing-box"
SB_CONFIG_FILE="${SB_CONFIG_DIR}/config.json"
SB_LOG_FILE="${SB_CONFIG_DIR}/sing-box.log" # sing-box 日志文件
SB_SERVICE_NAME="sing-box" # 服务名

CF_INSTALL_PATH="/usr/local/bin/cloudflared"
CF_CONFIG_DIR="/etc/cloudflared" # cloudflared 配置文件目录 (通常用于固定隧道)
CF_SERVICE_NAME="cloudflared" # 服务名

# 用户配置 (将由函数设置)
sb_uuid=""
sb_port=""
selected_protocol="" # 用户选择的协议: "vmess" 或 "vless"
sb_ws_path=""        # 根据协议和UUID生成的WebSocket路径

cf_use_tunnel="" # "temp" (临时), "fixed" (固定), "no" (不使用)
cf_tunnel_token="" # 仅用于固定隧道
cf_domain=""       # 用于隧道的域名
cf_assigned_temp_domain="" # Cloudflare 临时隧道分配的域名

# 系统环境 (将由函数检测)
detected_os=""      # linux, darwin, freebsd
detected_arch=""    # amd64, arm64, etc.
detected_init_system="" # systemd, openrc, unknown

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

# --- 日志函数 ---
# _log "级别" "消息"
_log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    # 同时输出到控制台和日志文件 (追加模式)
    echo -e "${timestamp} [${level}] ${message}${PLAIN}" | tee -a "${LOG_FILE}"
}

info() {    _log "${BLUE}INFO   " "$1"; }
success() { _log "${GREEN}SUCCESS" "$1"; }
warn() {    _log "${YELLOW}WARNING" "$1" >&2; } # 警告输出到 stderr
error_exit() { # 错误信息并退出
    _log "${RED}ERROR  " "$1" >&2
    # CLEANUP 函数会通过 trap 自动调用
    exit 1
}

# --- 清理函数 ---
CLEANUP() {
    info "执行清理操作..."
    if [ -f "${CF_TEMP_TUNNEL_PID_FILE}" ] && [ -s "${CF_TEMP_TUNNEL_PID_FILE}" ]; then
        local pid
        pid=$(cat "${CF_TEMP_TUNNEL_PID_FILE}")
        if ps -p "${pid}" > /dev/null 2>&1; then # 检查进程是否存在
            info "正在停止临时的 Cloudflare tunnel (PID: ${pid})..."
            # shellcheck disable=SC2046 # 我们确实需要这里的 word splitting
            run_sudo kill "${pid}" &>/dev/null || true # 忽略错误
        fi
        rm -f "${CF_TEMP_TUNNEL_PID_FILE}"
    fi

    if [ -d "${TMP_DIR}" ]; then
        rm -rf "${TMP_DIR}"
        info "临时目录 ${TMP_DIR} 已删除。"
    fi
}
trap CLEANUP EXIT SIGINT SIGTERM # 注册清理函数

# --- Sudo 权限执行封装 ---
run_sudo() {
    if [ "$(id -ru)" -ne 0 ]; then # 检查当前用户是否为 root
        if command -v sudo >/dev/null 2>&1; then
            sudo "$@"
        else
            error_exit "此脚本需要 sudo 权限执行部分操作，但 sudo 命令未找到。"
        fi
    else
        "$@" # 如果已经是 root 用户，则直接执行命令
    fi
}

# --- 初始化系统检测 ---
detect_init_system() {
    if [ -d /run/systemd/system ] && command -v systemctl &>/dev/null; then
        detected_init_system="systemd"
    elif command -v rc-service &>/dev/null && command -v rc-update &>/dev/null; then
        detected_init_system="openrc"
    elif [ -f /etc/init.d/cron ] && [ ! -d /run/systemd/system ]; then # 备用检测 SysVinit
        detected_init_system="sysvinit" # SysVinit 的服务管理比较分散，脚本可能无法完美支持
    else
        detected_init_system="unknown"
        warn "未能明确识别系统的初始化系统。服务管理功能可能受限。"
    fi
    info "检测到的初始化系统: ${detected_init_system}"
}

# --- 依赖检查 ---
check_dependencies() {
    info "开始检查依赖项..."
    local dep_missing=0
    # 核心依赖项: wget, curl, unzip, grep, jq, tar, uuidgen (或同等功能的命令)
    local core_deps=("wget" "curl" "unzip" "grep" "jq" "tar")
    for dep in "${core_deps[@]}"; do
        if ! command -v "${dep}" >/dev/null 2>&1; then
            warn "核心依赖项 '${dep}' 未安装。"
            dep_missing=$((dep_missing + 1))
        fi
    done

    # uuidgen 是生成UUID的首选
    if ! command -v uuidgen >/dev/null 2>&1; then
        # 在某些极简系统上，/proc/sys/kernel/random/uuid 可能可用
        if [ ! -f /proc/sys/kernel/random/uuid ]; then
            warn "命令 'uuidgen' 未安装，且 '/proc/sys/kernel/random/uuid' 不可用。UUID生成可能失败。"
            # 对于Alpine，可以提示 apk add util-linux
            if [ "${detected_os}" = "linux" ] && [ "${detected_init_system}" = "openrc" ]; then
                info "在 Alpine Linux 上，您可以尝试使用 'sudo apk add util-linux' 来安装 uuidgen。"
            fi
            dep_missing=$((dep_missing + 1))
        fi
    fi

    if [ ${dep_missing} -gt 0 ]; then
        error_exit "请先安装缺失的核心依赖项，然后重新运行脚本。"
    fi

    # 针对 Alpine Linux 的特定提示 (libc6-compat)
    if [ "${detected_os}" = "linux" ] && [ "${detected_init_system}" = "openrc" ]; then # 假设 openrc 主要用于 Alpine
        if command -v apk >/dev/null 2>&1 && ! apk info -e libc6-compat >/dev/null 2>&1; then
            warn "当前为 Alpine Linux 系统，建议安装 'libc6-compat' 以增强二进制文件兼容性。"
            info "您可以尝试使用 'sudo apk add libc6-compat' 命令安装 (非强制)。"
        fi
    fi
    success "所有核心依赖项检查完毕。"
}

# --- 环境检测 (OS 和架构) ---
detect_environment() {
    info "检测操作系统和架构..."
    local machine_arch
    machine_arch=$(uname -m)
    case "$machine_arch" in
        amd64|x86_64) detected_arch="amd64" ;;
        i386|i686)    detected_arch="386" ;;
        aarch64|arm64)detected_arch="arm64" ;;
        armv7*|armv7l) detected_arch="armv7" ;; # 更精确匹配 armv7
        armv6*|armv6l) detected_arch="armv6" ;; # 匹配 armv6
        *arm*)        detected_arch="arm" ;;   # 通用 arm 作为后备
        s390x)        detected_arch="s390x" ;;
        riscv64)      detected_arch="riscv64" ;;
        mips)         detected_arch="mips" ;;
        mipsle)       detected_arch="mipsle" ;;
        *) error_exit "不支持的系统架构: ${machine_arch}" ;;
    esac

    local system_name
    system_name=$(uname -s)
    case "$system_name" in
        Linux)   detected_os="linux" ;;
        Darwin)  detected_os="darwin"; warn "macOS (Darwin) 支持有限，主要为二进制运行，服务管理需手动。" ;;
        FreeBSD) detected_os="freebsd"; warn "FreeBSD 支持有限，主要为二进制运行，服务管理需手动。" ;;
        *) error_exit "不支持的操作系统: ${system_name}" ;;
    esac
    success "检测到环境: 系统=${detected_os}, 架构=${detected_arch}"
}

# --- 下载文件封装 ---
download_file() {
    local url="$1"
    local output_path="$2"
    local file_description="$3"
    # local checksum_url="$4" # 可选: 校验和文件URL
    # local expected_checksum="$5" # 可选: 预期的校验和值

    info "正在下载 ${file_description} 从 ${url} ..."
    if command -v curl &>/dev/null; then
        # 使用 curl 下载，启用重定向 (-L)，设置连接超时和重试
        if ! curl -L --connect-timeout 20 --retry 3 --retry-delay 5 -o "${output_path}" "${url}"; then
            error_exit "使用 curl 下载 ${file_description} 失败。请检查网络连接和URL。"
        fi
    elif command -v wget &>/dev/null; then
        # 使用 wget 下载，设置超时和重试次数
        if ! wget --timeout=20 --tries=3 --waitretry=5 -O "${output_path}" "${url}"; then
            error_exit "使用 wget 下载 ${file_description} 失败。请检查网络连接和URL。"
        fi
    else
        error_exit "未找到 curl 或 wget 命令，无法下载文件。"
    fi
    success "${file_description} 下载成功: ${output_path}"

    # 校验和验证逻辑 (此处为占位符，实际使用时需要提供校验和来源)
    # if [ -n "${expected_checksum}" ]; then
    #     info "正在校验 ${file_description} 的完整性..."
    #     local actual_checksum
    #     actual_checksum=$(sha256sum "${output_path}" | awk '{print $1}') # 或 md5sum
    #     if [ "${actual_checksum}" != "${expected_checksum}" ]; then
    #         rm -f "${output_path}" # 校验失败则删除下载的文件
    #         error_exit "${file_description} 校验和不匹配！文件可能已损坏或被篡改。"
    #     fi
    #     success "${file_description} 校验和验证通过。"
    # fi
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
                        read -r -d '' openrc_script_content <<EOF
#!/sbin/openrc-run
supervisor=supervise-daemon

name="${service_name}"
description="${desc}"
command="${service_bin}"
command_args="${cmd_args}"
command_user="${service_name}:${service_name}" # 假设已创建同名用户和组
pidfile="/run/\${RC_SVCNAME}.pid"
supervise_daemon_args="--stdout /var/log/${service_name}.log --stderr /var/log/${service_name}.err"

depend() {
    need net
    use dns logger
}
EOF
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

# --- 协议选择 ---
select_protocol() {
    info "开始协议选择..."
    echo -e "${YELLOW}请选择您希望安装的 sing-box 协议类型:${PLAIN}"
    echo "  1. VMess (WebSocket)"
    echo "  2. VLESS (WebSocket)"
    # 未来可以扩展更多选项
    # echo "  3. Shadowsocks"
    # echo "  4. Trojan"

    local choice
    while true; do
        printf "${YELLOW}请输入您的选择 [1-2] (默认: 2. VLESS): ${PLAIN}"
        read -r choice
        choice=${choice:-2} # 用户直接回车则默认为 VLESS
        case "$choice" in
            1) selected_protocol="vmess"; break ;;
            2) selected_protocol="vless"; break ;;
            # Add cases for other protocols here
            *) warn "无效的选择，请输入 1 或 2。" ;;
        esac
    done
    info "您已选择安装协议: ${selected_protocol^^}" # 转为大写显示
}


# --- Sing-box 配置 (根据选择的协议) ---
configure_sing_box() {
    info "开始配置 sing-box (协议: ${selected_protocol^^})..."
    local input_uuid
    local input_port

    # UUID 配置 (通用)
    printf "${YELLOW}请输入 sing-box UUID (留空则自动生成): ${PLAIN}"
    read -r input_uuid
    if [ -z "${input_uuid}" ]; then
        if command -v uuidgen &>/dev/null; then
            sb_uuid=$(uuidgen)
        elif [ -f /proc/sys/kernel/random/uuid ]; then
            sb_uuid=$(cat /proc/sys/kernel/random/uuid)
        else
            warn "uuidgen 未找到，将生成一个伪UUID。"
            sb_uuid=$(date +%s%N | sha256sum | base64 | head -c 32 | sed -e 's/\(.\{8\}\)/\1-/g' -e 's/\(.\{13\}\)/\1-/g' -e 's/\(.\{18\}\)/\1-/g' -e 's/\(.\{23\}\)/\1-/g' | cut -c1-36)
        fi
        info "已自动生成 sing-box UUID: ${sb_uuid}"
    else
        if [[ ! "${input_uuid}" =~ ^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$ ]]; then
            error_exit "输入的 UUID 格式无效。应为 RFC4122 标准格式。"
        fi
        sb_uuid="${input_uuid}"
        info "将使用用户提供的 UUID: ${sb_uuid}"
    fi

    # 端口配置 (通用)
    printf "${YELLOW}请输入 sing-box 监听端口 (默认: 8008): ${PLAIN}"
    read -r input_port
    sb_port=${input_port:-8008}
    if ! [[ "${sb_port}" =~ ^[0-9]+$ ]] || [ "${sb_port}" -lt 1 ] || [ "${sb_port}" -gt 65535 ]; then
        error_exit "端口号无效。必须是 1-65535 之间的整数。"
    fi
    info "sing-box 将监听端口: ${sb_port}"

    # 根据选择的协议确定 WebSocket 路径
    if [ "${selected_protocol}" = "vmess" ]; then
        sb_ws_path="/${sb_uuid}-vm" # VMess 使用 -vm 后缀
    elif [ "${selected_protocol}" = "vless" ]; then
        sb_ws_path="/${sb_uuid}-vl" # VLESS 使用 -vl 后缀
    else
        error_exit "内部错误：未知的 selected_protocol: ${selected_protocol}"
    fi
    info "WebSocket 路径将设置为: ${sb_ws_path}"


    # 创建配置目录并设置权限
    run_sudo mkdir -p "${SB_CONFIG_DIR}"
    run_sudo chmod 700 "${SB_CONFIG_DIR}"

    # 生成 sing-box 配置文件 (config.json)
    info "正在生成 sing-box ${selected_protocol^^} 配置文件: ${SB_CONFIG_FILE}"
    
    local inbound_json_string=""
    if [ "${selected_protocol}" = "vmess" ]; then
        # VMess over WS 配置
        inbound_json_string=$(jq -n \
            --arg uuid "${sb_uuid}" \
            --argjson port "${sb_port}" \
            --arg path "${sb_ws_path}" \
            '{
                "type": "vmess",
                "tag": "vmess-ws-in",
                "listen": "::",
                "listen_port": $port,
                "users": [ { "uuid": $uuid, "alterId": 0 } ],
                "transport": {
                    "type": "ws",
                    "path": $path,
                    "early_data_header_name": "Sec-WebSocket-Protocol"
                }
            }')
    elif [ "${selected_protocol}" = "vless" ]; then
        # VLESS over WS 配置 (修正: flow: "")
        inbound_json_string=$(jq -n \
            --arg uuid "${sb_uuid}" \
            --argjson port "${sb_port}" \
            --arg path "${sb_ws_path}" \
            '{
                "type": "vless",
                "tag": "vless-ws-in",
                "listen": "::",
                "listen_port": $port,
                "users": [ { "uuid": $uuid, "flow": "" } ], # VLESS 无 alterId, flow 为空表示基础
                "transport": {
                    "type": "ws",
                    "path": $path,
                    "early_data_header_name": "Sec-WebSocket-Protocol"
                }
            }')
    else
        error_exit "内部错误：不支持的协议类型 ${selected_protocol} 用于生成配置。"
    fi

    # 完整的 config.json 结构
    if ! run_sudo sh -c "jq -n \
        --arg log_file \"${SB_LOG_FILE}\" \
        --argjson inbound_config '${inbound_json_string}' \
        '{
            \"log\": {
                \"level\": \"info\",
                \"timestamp\": true,
                \"output\": \$log_file
            },
            \"dns\": {
                \"servers\": [
                    {\"address\": \"8.8.8.8\", \"tag\": \"google-dns\"},
                    {\"address\": \"1.1.1.1\", \"tag\": \"cloudflare-dns\"}
                ]
            },
            \"inbounds\": [
                \$inbound_config
            ]
        }' > '${SB_CONFIG_FILE}'"; then
        error_exit "生成 sing-box 配置文件 (${SB_CONFIG_FILE}) 失败。"
    fi

    run_sudo chmod 600 "${SB_CONFIG_FILE}"
    success "sing-box (${selected_protocol^^}) 配置完成。配置文件位于: ${SB_CONFIG_FILE}"
}

# --- Sing-box 安装 ---
install_sing_box() {
    info "开始安装 sing-box..."
    local latest_tag download_url archive_name extracted_dir binary_in_archive
    local sb_openrc_script_path="/etc/init.d/${SB_SERVICE_NAME}"
    local sb_openrc_confd_path="/etc/conf.d/${SB_SERVICE_NAME}"

    # 获取最新版本标签 (SagerNet/sing-box)
    info "正在获取 sing-box 最新版本信息..."
    # shellcheck disable=SC2016 # $ in jq query is for jq, not shell
    latest_tag=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name // empty' | sed 's/^v//')
    if [ -z "${latest_tag}" ]; then
        warn "自动获取 sing-box 最新版本失败。请手动输入版本号 (例如: 1.9.0)，或留空尝试使用预设的已知版本。"
        read -r input_tag
        if [ -n "$input_tag" ]; then
            latest_tag="$input_tag"
        else
            error_exit "未能获取 sing-box 版本信息，安装中止。"
        fi
    fi
    info "准备安装 sing-box 版本: v${latest_tag}"

    archive_name="sing-box-${latest_tag}-${detected_os}-${detected_arch}.tar.gz"
    download_url="https://github.com/SagerNet/sing-box/releases/download/v${latest_tag}/${archive_name}"

    if [[ "${detected_arch}" == "armv7" || "${detected_arch}" == "armv6" ]]; then
        local potential_arch_names=("${detected_arch}" "arm")
        local found_url=false
        for arch_variant in "${potential_arch_names[@]}"; do
            archive_name_variant="sing-box-${latest_tag}-${detected_os}-${arch_variant}.tar.gz"
            download_url_variant="https://github.com/SagerNet/sing-box/releases/download/v${latest_tag}/${archive_name_variant}"
            info "正在尝试检查下载链接 (架构: ${arch_variant}): ${download_url_variant}"
            if curl --output /dev/null --silent --head --fail "${download_url_variant}"; then
                archive_name="${archive_name_variant}"
                download_url="${download_url_variant}"
                info "找到有效的下载链接: ${download_url}"
                found_url=true
                break
            else
                info "链接无效或文件不存在: ${download_url_variant}"
            fi
        done
        if ! ${found_url}; then
            error_exit "未能找到适用于架构 '${detected_arch}' 或 'arm' 的 sing-box 下载链接。"
        fi
    fi

    download_file "${download_url}" "${TMP_DIR}/${archive_name}" "sing-box v${latest_tag} 压缩包"

    info "正在解压 ${archive_name}..."
    extracted_dir="${TMP_DIR}/sing-box-extracted"
    mkdir -p "${extracted_dir}"
    if ! tar -xzf "${TMP_DIR}/${archive_name}" -C "${extracted_dir}"; then
        error_exit "解压 sing-box 压缩包 (${archive_name}) 失败。文件可能已损坏。"
    fi

    binary_in_archive=$(find "${extracted_dir}" -type f -name "sing-box" | head -n 1)
    if [ -z "${binary_in_archive}" ]; then
        error_exit "在解压的目录中未找到 'sing-box' 二进制文件。"
    fi
    info "找到 sing-box 二进制文件: ${binary_in_archive}"

    info "正在安装 sing-box 到 ${SB_INSTALL_PATH}..."
    run_sudo install -m 755 "${binary_in_archive}" "${SB_INSTALL_PATH}"

    info "正在设置 sing-box 系统服务 (使用 ${detected_init_system})..."
    manage_service "stop" "${SB_SERVICE_NAME}" &>/dev/null || true
    manage_service "disable" "${SB_SERVICE_NAME}" &>/dev/null || true
    if [[ "${detected_init_system}" == "openrc" ]]; then
        manage_service "uninstall" "${SB_SERVICE_NAME}" "${sb_openrc_script_path}" "${sb_openrc_confd_path}" &>/dev/null || true
        if ! getent group "${SB_SERVICE_NAME}" >/dev/null; then
            info "为 OpenRC 服务创建用户组: ${SB_SERVICE_NAME}"
            run_sudo groupadd -r "${SB_SERVICE_NAME}" || warn "创建用户组 ${SB_SERVICE_NAME} 失败。"
        fi
        if ! getent passwd "${SB_SERVICE_NAME}" >/dev/null; then
            info "为 OpenRC 服务创建用户: ${SB_SERVICE_NAME}"
            run_sudo useradd -r -g "${SB_SERVICE_NAME}" -d "${SB_CONFIG_DIR}" -s /sbin/nologin -c "${SB_SERVICE_NAME} service user" "${SB_SERVICE_NAME}" || warn "创建用户 ${SB_SERVICE_NAME} 失败。"
        fi
        run_sudo chown -R "${SB_SERVICE_NAME}:${SB_SERVICE_NAME}" "${SB_CONFIG_DIR}"
    elif [[ "${detected_init_system}" == "systemd" ]]; then # systemd uninstall is handled by manage_service
         manage_service "uninstall" "${SB_SERVICE_NAME}" # ensures removal of script-generated unit file
    else
        if [[ "$(${SB_INSTALL_PATH} help service uninstall 2>&1 || true)" != *"unknown command"* ]]; then
            run_sudo "${SB_INSTALL_PATH}" service -c "${SB_CONFIG_FILE}" uninstall &>/dev/null || true
        fi
    fi

    if [[ "${detected_init_system}" == "systemd" ]]; then
        # shellcheck disable=SC2001 # awk aytacını temizlemek için sed kullanılıyor
        if [[ "$(run_sudo "${SB_INSTALL_PATH}" version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -n1 | sed 's/\([0-9]*\.[0-9]*\).*/\1/')" < "1.9" ]]; then
            warn "当前 sing-box 版本可能不支持 'service install' 来自动创建 systemd 服务文件。"
            local systemd_service_content="[Unit]\nDescription=sing-box service (managed by script)\nDocumentation=https://sing-box.sagernet.org/\nAfter=network.target nss-lookup.target\n\n[Service]\nUser=root\nWorkingDirectory=${SB_CONFIG_DIR}\nExecStart=${SB_INSTALL_PATH} run -c ${SB_CONFIG_FILE}\nRestart=on-failure\nRestartSec=10s\nLimitNOFILE=infinity\n\n[Install]\nWantedBy=multi-user.target"
            echo -e "${systemd_service_content}" | run_sudo tee "/etc/systemd/system/${SB_SERVICE_NAME}.service" > /dev/null
            run_sudo chmod 0644 "/etc/systemd/system/${SB_SERVICE_NAME}.service"
            info "已创建基础的 systemd 服务文件。执行 daemon-reload..."
            run_sudo systemctl daemon-reload
        else
            if ! run_sudo "${SB_INSTALL_PATH}" service -c "${SB_CONFIG_FILE}" install; then
                warn "'${SB_INSTALL_PATH} service -c ${SB_CONFIG_FILE} install' 执行失败或不受支持。"
                warn "尝试创建基础的 systemd 服务文件..."
                local systemd_service_content="[Unit]\nDescription=sing-box service (managed by script)\nDocumentation=https://sing-box.sagernet.org/\nAfter=network.target nss-lookup.target\n\n[Service]\nUser=root\nWorkingDirectory=${SB_CONFIG_DIR}\nExecStart=${SB_INSTALL_PATH} run -D ${SB_CONFIG_DIR}\nRestart=on-failure\nRestartSec=10s\nLimitNOFILE=infinity\n\n[Install]\nWantedBy=multi-user.target"
                echo -e "${systemd_service_content}" | run_sudo tee "/etc/systemd/system/${SB_SERVICE_NAME}.service" > /dev/null
                run_sudo chmod 0644 "/etc/systemd/system/${SB_SERVICE_NAME}.service"
                info "已创建基础的 systemd 服务文件。执行 daemon-reload..."
                run_sudo systemctl daemon-reload
            fi
        fi
        manage_service "install" "${SB_SERVICE_NAME}"
    elif [[ "${detected_init_system}" == "openrc" ]]; then
        manage_service "install" "${SB_SERVICE_NAME}" "${sb_openrc_script_path}" "${sb_openrc_confd_path}" "sing-box proxy service"
    else
        warn "未知初始化系统，尝试使用 sing-box 内建的 'service install' (如果可用)..."
        if [[ "$(${SB_INSTALL_PATH} help service install 2>&1 || true)" != *"unknown command"* ]]; then
             if ! run_sudo "${SB_INSTALL_PATH}" service -c "${SB_CONFIG_FILE}" install; then
                warn "sing-box 'service install' 命令执行失败或不适用。"
             fi
        else
            warn "当前 sing-box 版本不支持 'service install' 命令。请手动配置服务。"
        fi
    fi

    manage_service "start" "${SB_SERVICE_NAME}"
    
    if ! manage_service "status" "${SB_SERVICE_NAME}"; then
        warn "sing-box 服务未能成功启动或状态未知。请检查相关日志："
        info "  - systemd: journalctl -u ${SB_SERVICE_NAME} -n 50 --no-pager"
        info "  - openrc: /var/log/${SB_SERVICE_NAME}.log 和 /var/log/${SB_SERVICE_NAME}.err (如果按模板配置)"
        info "  - sing-box 日志: ${SB_LOG_FILE}"
    fi
    success "sing-box v${latest_tag} 安装和服务设置尝试完成。"
}

# --- Cloudflare Tunnel 配置 ---
# (此函数与协议类型无关，保持不变)
configure_cloudflare_tunnel() {
    info "开始配置 Cloudflare Tunnel..."
    echo -e "${YELLOW}您是否希望使用 Cloudflare Tunnel 将 sing-box 服务暴露到公网?${PLAIN}"
    echo "  1. 是，使用临时的 Cloudflare Tunnel (通常分配随机域名，脚本或终端关闭时隧道终止)"
    echo "  2. 是，使用永久的 Cloudflare Tunnel (需要您从 Cloudflare Zero Trust 面板获取的 Token)"
    echo "  3. 否，不使用 Cloudflare Tunnel (sing-box 将仅监听本地端口)"

    local choice
    while true; do
        printf "${YELLOW}请输入您的选择 [1-3] (默认: 3 不使用): ${PLAIN}"
        read -r choice
        choice=${choice:-3} # 用户直接回车则默认为 3
        case "$choice" in
            1) cf_use_tunnel="temp"; break ;;
            2) cf_use_tunnel="fixed"; break ;;
            3) cf_use_tunnel="no"; break ;;
            *) warn "无效的选择，请输入 1, 2, 或 3。" ;;
        esac
    done

    if [ "${cf_use_tunnel}" = "fixed" ]; then
        printf "${YELLOW}请输入您的 Cloudflare Tunnel Token (输入时不会显示字符): ${PLAIN}"
        read -rs cf_tunnel_token # -s 实现静默输入，不回显
        echo # 读取静默输入后换行，避免后续输出在同一行
        if [ -z "${cf_tunnel_token}" ]; then
            error_exit "固定隧道的 Token 不能为空。"
        fi
    fi

    if [ "${cf_use_tunnel}" = "temp" ] || [ "${cf_use_tunnel}" = "fixed" ]; then
        printf "${YELLOW}请输入用于 Cloudflare Tunnel 的域名/子域名 (例如: myproxy.example.com): ${PLAIN}"
        printf "${YELLOW}(对于临时隧道，若不指定，cloudflared 会尝试分配一个 *.trycloudflare.com 域名): ${PLAIN}"
        read -r cf_domain
        if [ -z "${cf_domain}" ]; then
            if [ "${cf_use_tunnel}" = "fixed" ]; then # 固定隧道必须指定域名
                error_exit "固定隧道使用的域名不能为空。"
            else # 临时隧道可以不指定域名
                info "未指定域名，临时隧道将尝试使用随机的 *.trycloudflare.com 域名。"
                cf_domain="" # 确保为空，以便后续逻辑判断
            fi
        elif ! echo "${cf_domain}" | grep -Pq '^(?!-)[a-zA-Z0-9.-]{1,253}(?<!-)$' || ! echo "${cf_domain}" | grep -q '\.'; then
            error_exit "输入的域名格式似乎无效。应包含至少一个点，且主机名部分不以连字符开头或结尾。"
        fi

        if [ -n "${cf_domain}" ]; then
            info "Cloudflare Tunnel 将尝试使用域名: ${cf_domain}"
        fi
    fi
    success "Cloudflare Tunnel 配置选项已设定。"
}

# --- Cloudflare Tunnel 安装 ---
# (此函数与协议类型无关，保持不变)
install_cloudflare_tunnel() {
    if [ "${cf_use_tunnel}" = "no" ]; then
        info "根据用户选择，跳过 Cloudflare Tunnel 安装。"
        return 0 # 正常退出此函数
    fi

    info "开始安装 Cloudflare Tunnel (cloudflared)..."
    local latest_tag download_url binary_name
    local cf_openrc_script_path="/etc/init.d/${CF_SERVICE_NAME}"
    # local cf_openrc_confd_path="/etc/conf.d/${CF_SERVICE_NAME}" # cloudflared 的 conf.d 通常较少直接由脚本生成

    info "正在获取 cloudflared 最新版本信息..."
    # shellcheck disable=SC2016
    latest_tag=$(curl -s https://api.github.com/repos/cloudflare/cloudflared/releases/latest | jq -r '.tag_name // empty')
    if [ -z "${latest_tag}" ]; then
        warn "自动获取 cloudflared 最新版本失败。请手动输入版本号 (例如: 2024.5.0)，或留空尝试。"
        read -r input_tag
        if [ -n "$input_tag" ]; then
            latest_tag="$input_tag"
        else
            latest_tag="latest" 
            info "将尝试下载标记为 'latest' 的 cloudflared 版本。"
        fi
    fi
    if [[ "$latest_tag" != "latest" ]]; then
        info "准备安装 cloudflared 版本: ${latest_tag}"
    fi

    binary_name="cloudflared-${detected_os}-${detected_arch}"
    if [ "${detected_os}" = "windows" ]; then
        binary_name="${binary_name}.exe"
    fi

    if [[ "$latest_tag" == "latest" ]]; then
        download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/${binary_name}"
    else
        download_url="https://github.com/cloudflare/cloudflared/releases/download/${latest_tag}/${binary_name}"
    fi

    download_file "${download_url}" "${TMP_DIR}/${binary_name}" "cloudflared (${latest_tag})"

    info "正在安装 cloudflared 到 ${CF_INSTALL_PATH}..."
    run_sudo install -m 755 "${TMP_DIR}/${binary_name}" "${CF_INSTALL_PATH}"

    if [ "${cf_use_tunnel}" = "temp" ]; then
        info "正在启动临时的 Cloudflare Tunnel，将本地端口 ${sb_port} 暴露出去..."
        info "此隧道将在脚本退出 (或被清理函数停止) 时关闭。"
        info "隧道日志将输出到: ${TMP_DIR}/cf_temp_tunnel.log"
        local tunnel_hostname_param=""
        # if [ -n "${cf_domain}" ]; then
        #     info "vless 链接将使用域名 '${cf_domain}'。临时隧道本身可能分配一个不同的 *.trycloudflare.com 域名。"
        # fi

        run_sudo nohup "${CF_INSTALL_PATH}" tunnel --url "http://localhost:${sb_port}" \
            --logfile "${TMP_DIR}/cf_temp_tunnel.log" \
            --pidfile "${CF_TEMP_TUNNEL_PID_FILE}" \
            --edge-ip-version auto \
            --no-autoupdate \
            ${tunnel_hostname_param} > "${TMP_DIR}/nohup_cf_stdout.log" 2>&1 &

        info "等待临时隧道启动并创建PID文件 (最多15秒)..."
        local i
        for i in {1..15}; do
            if [ -f "${CF_TEMP_TUNNEL_PID_FILE}" ] && [ -s "${CF_TEMP_TUNNEL_PID_FILE}" ]; then
                if ps -p "$(cat "${CF_TEMP_TUNNEL_PID_FILE}")" > /dev/null ; then
                    success "临时 Cloudflare Tunnel 似乎已启动 (PID: $(cat "${CF_TEMP_TUNNEL_PID_FILE}"))."
                    sleep 3 
                    cf_assigned_temp_domain=$(grep -Eo 'https://[a-z0-9.-]+\.trycloudflare\.com' "${TMP_DIR}/cf_temp_tunnel.log" | head -n 1 | sed 's|https://||')
                    if [ -n "$cf_assigned_temp_domain" ]; then
                        info "检测到 Cloudflare 分配的临时域名: ${cf_assigned_temp_domain}"
                        if [ -z "${cf_domain}" ]; then
                            cf_domain="${cf_assigned_temp_domain}"
                            info "将使用此临时域名 '${cf_domain}' 生成连接链接。"
                        fi
                    else
                        info "未能从日志中自动检测到 Cloudflare 分配的临时域名。"
                        if [ -z "${cf_domain}" ]; then
                             warn "您未指定域名，也未能自动检测到临时域名。生成的连接链接可能不准确。"
                        fi
                    fi
                    break 
                fi
            fi
            echo -n "." 
            sleep 1
        done
        echo 
        if ! ( [ -f "${CF_TEMP_TUNNEL_PID_FILE}" ] && [ -s "${CF_TEMP_TUNNEL_PID_FILE}" ] && ps -p "$(cat "${CF_TEMP_TUNNEL_PID_FILE}")" > /dev/null ); then
            warn "临时 Cloudflare Tunnel 可能未能成功启动或创建PID文件。"
            warn "请检查日志: ${TMP_DIR}/cf_temp_tunnel.log 和 ${TMP_DIR}/nohup_cf_stdout.log"
        fi

    elif [ "${cf_use_tunnel}" = "fixed" ]; then
        info "正在设置永久的 Cloudflare Tunnel (使用提供的 Token)..."
        run_sudo mkdir -p "${CF_CONFIG_DIR}"
        run_sudo chown nobody:nogroup "${CF_CONFIG_DIR}" &>/dev/null || true

        info "尝试使用 'cloudflared service install ${cf_tunnel_token}' 来安装固定隧道服务..."
        if ! run_sudo "${CF_INSTALL_PATH}" service install "${cf_tunnel_token}"; then
            warn "'cloudflared service install TOKEN' 命令执行失败或不受支持。"
            warn "这在非 systemd 系统上可能需要额外配置，或者需要 cloudflared-openrc 包。"
            if [[ "${detected_init_system}" == "openrc" ]]; then
                 warn "对于 OpenRC 上的固定 Cloudflare Tunnel，通常需要手动创建或修改 ${CF_CONFIG_DIR}/config.yml 文件,"
                 warn "并在其中指定隧道 ID 或名称，以及凭据文件路径。"
                 warn "建议参考 Alpine Linux 社区的 cloudflared-openrc 包的配置方式。"
                 info "请在 Cloudflare Dashboard 创建隧道，获取其 ID，然后在 ${CF_CONFIG_DIR}/config.yml 中配置，"
                 info "例如: tunnel: YOUR_TUNNEL_ID\ncredentials-file: /root/.cloudflared/YOUR_TUNNEL_ID.json"
                 info "然后您可以手动创建或使用社区提供的 OpenRC 脚本来启动它。"
             fi
        else
            success "'cloudflared service install TOKEN' 命令已执行。"
            if [[ "${detected_init_system}" == "systemd" ]]; then
                manage_service "enable" "${CF_SERVICE_NAME}" 
                manage_service "start" "${CF_SERVICE_NAME}"  
            elif [[ "${detected_init_system}" == "openrc" ]]; then
                if [ -f "${cf_openrc_script_path}" ]; then # 假设 'service install' 会创建或依赖已有的 OpenRC 脚本
                    manage_service "enable" "${CF_SERVICE_NAME}"
                    manage_service "start" "${CF_SERVICE_NAME}"
                else # 如果脚本不存在，但 service install 成功了，可能 cloudflared 有其他方式管理
                    warn "Cloudflared 已执行 'service install TOKEN'，但 OpenRC 脚本 ${cf_openrc_script_path} 未找到或未被此脚本管理。"
                    info "如果 cloudflared-openrc 包已安装并正确配置，服务可能仍然可以工作。"
                fi
            fi
        fi
        
        if ! manage_service "status" "${CF_SERVICE_NAME}"; then # 即使上面 enable/start 了，这里也再次检查
            warn "Cloudflare Tunnel 固定隧道服务未能成功启动或状态未知。"
            warn "请确保您的域名 ${cf_domain} 的 DNS CNAME 记录指向了正确的隧道地址，"
            warn "并且隧道配置 (例如 ${CF_CONFIG_DIR}/config.yml 和相关的凭据文件) 正确无误。"
        fi
    fi
    success "Cloudflare Tunnel (cloudflared) 安装和配置尝试完成。"
}


# --- 生成输出链接 (根据选择的协议) ---
generate_output_links() {
    info "正在生成 sing-box (${selected_protocol^^}) 连接信息..."
    local proxy_address=""           # 最终连接地址 (域名或IP)
    local proxy_port=""              # 最终连接端口
    local proxy_host_header=""       # WebSocket Host 头部 / SNI
    local proxy_security="none"      # TLS设置: "none" 或 "tls"
    local proxy_sni=""               # SNI，用于 TLS
    local link_remark="sing-box-${selected_protocol}-ws" # 链接备注

    # 根据是否使用 Cloudflare Tunnel 设置通用连接参数
    if [ "${cf_use_tunnel}" != "no" ]; then
        if [ -n "${cf_domain}" ]; then
            proxy_address="${cf_domain}"
            proxy_port="443"
            proxy_host_header="${cf_domain}"
            proxy_security="tls"
            proxy_sni="${cf_domain}"
            link_remark="sing-box_${selected_protocol^^}_CF_${cf_domain}"
        else
            warn "Cloudflare Tunnel 已启用，但未能确定连接域名。"
            warn "生成的 ${selected_protocol^^} 链接中的地址可能需要您手动修改。"
            proxy_address="YOUR_CLOUDFLARE_DOMAIN"
            proxy_port="443"
            proxy_host_header="YOUR_CLOUDFLARE_DOMAIN"
            proxy_security="tls"
            proxy_sni="YOUR_CLOUDFLARE_DOMAIN"
            link_remark="sing-box_${selected_protocol^^}_CF_CheckDomain"
        fi
    else # 不使用 Cloudflare Tunnel
        local server_ip
        server_ip=$(curl -s -m 5 ip.sb || curl -s -m 5 ifconfig.me || hostname -I | awk '{print $1}' || echo "YOUR_SERVER_IP")
        proxy_address="${server_ip}"
        proxy_port="${sb_port}"
        proxy_host_header="${server_ip}"
        proxy_security="none" # 直连，除非 sing-box 内部配置了 TLS
        proxy_sni=""
        link_remark="sing-box_${selected_protocol^^}_Direct_${proxy_address}"
        if [[ "${proxy_address}" == "YOUR_SERVER_IP" ]]; then
             warn "未启用 Cloudflare Tunnel，且未能自动获取服务器公网IP。"
        else
             warn "未启用 Cloudflare Tunnel。以下链接中的地址 '${proxy_address}' 是脚本尝试获取的IP。"
        fi
        warn "您可能需要手动将其修改为服务器的实际公网IP或可访问地址，并确保防火墙允许端口 ${sb_port}。"
    fi

    local final_link=""
    local encoded_ws_path # URL编码后的WebSocket路径
    # shellcheck disable=SC2046 # jq @uri 需要这种方式
    encoded_ws_path=$(echo -n "${sb_ws_path}" | jq -sRr @uri)
    # shellcheck disable=SC2046
    local encoded_remark=$(echo -n "${link_remark}" | jq -sRr @uri)


    if [ "${selected_protocol}" = "vmess" ]; then
        # 生成 VMess 链接
        # VMess 链接的 path 通常不包含 ?ed=2048，因为服务端 early_data_header_name 效果类似
        local vmess_json
        vmess_json=$(jq -n \
            --arg v "2" \
            --arg ps "${link_remark}" \
            --arg add "${proxy_address}" \
            --arg port "${proxy_port}" \
            --arg id "${sb_uuid}" \
            --arg aid "0" \
            --arg scy "auto" \
            --arg net "ws" \
            --arg type "none" \
            --arg host "${proxy_host_header}" \
            --arg path "${sb_ws_path}" \
            --arg tls "${proxy_security}" \
            --arg sni "${proxy_sni}" \
            --arg alpn "" \
            --arg fp "" \
            '{v: $v, ps: $ps, add: $add, port: $port, id: $id, aid: $aid, scy: $scy, net: $net, type: $type, host: $host, path: $path, tls: $tls, sni: $sni, alpn: $alpn, fp: $fp}')
        final_link="vmess://$(echo -n "${vmess_json}" | base64 -w0)"

    elif [ "${selected_protocol}" = "vless" ]; then
        # 生成 VLESS 链接
        local vless_link_params="type=ws" # 传输类型固定为ws
        vless_link_params+="&security=${proxy_security}"
        vless_link_params+="&path=${encoded_ws_path}"

        if [ -n "${proxy_host_header}" ]; then
            vless_link_params+="&host=${proxy_host_header}"
        fi
        if [ -n "${proxy_sni}" ]; then
            vless_link_params+="&sni=${proxy_sni}"
        fi
        # flow 参数，如果服务端配置了，这里也需要加上。当前服务端配置 flow: ""
        # local flow_control="" # 例如 "xtls-rprx-vision"
        # if [ -n "${flow_control}" ]; then
        #    vless_link_params+="&flow=${flow_control}"
        # fi
        final_link="vless://${sb_uuid}@${proxy_address}:${proxy_port}?${vless_link_params}#${encoded_remark}"
    else
        error_exit "内部错误：不支持的协议类型 ${selected_protocol} 用于生成链接。"
    fi


    echo -e "\n${GREEN}================ Sing-box (${selected_protocol^^}) 安装与配置摘要 ================${PLAIN}"
    echo -e "  协议类型:         ${YELLOW}${selected_protocol^^}${PLAIN}"
    echo -e "  Sing-box UUID:     ${YELLOW}${sb_uuid}${PLAIN}"
    echo -e "  Sing-box 端口:    ${YELLOW}${sb_port}${PLAIN}"
    echo -e "  WebSocket 路径:  ${YELLOW}${sb_ws_path}${PLAIN}"
    if [ "${cf_use_tunnel}" != "no" ]; then
        echo -e "  Cloudflare 域名:  ${YELLOW}${cf_domain:- (请查看临时隧道日志或Cloudflare仪表板)}${PLAIN}"
        if [ "${cf_use_tunnel}" = "temp" ] && [ -n "${cf_assigned_temp_domain}" ] && [[ "${cf_domain}" != "${cf_assigned_temp_domain}" ]]; then
             echo -e "  (隧道实际分配域名可能为: ${YELLOW}${cf_assigned_temp_domain}${PLAIN})"
        fi
    else
        echo -e "  Cloudflare Tunnel: ${RED}未使用${PLAIN}"
    fi
    echo -e "\n${GREEN}${selected_protocol^^} 连接链接:${PLAIN}"
    echo -e "${YELLOW}${final_link}${PLAIN}\n"

    if command -v qrencode &>/dev/null; then
        echo -e "${GREEN}${selected_protocol^^} 二维码 (部分终端可能无法完美显示):${PLAIN}"
        qrencode -t ansiutf8 "${final_link}"
    else
        info "未安装 'qrencode'，无法在终端生成二维码。"
        info "您可以复制上面的链接到在线二维码生成工具中使用。"
    fi
    echo -e "${GREEN}====================================================================${PLAIN}\n"

    if [ "${cf_use_tunnel}" = "temp" ]; then
        info "临时的 Cloudflare Tunnel 正在运行。当您关闭此会话或脚本发生错误时，它可能会被清理函数停止。"
        info "隧道日志位于: ${TMP_DIR}/cf_temp_tunnel.log"
        info "要手动停止它: sudo kill \$(cat ${CF_TEMP_TUNNEL_PID_FILE} 2>/dev/null || echo 'PID_NOT_FOUND')"
    fi
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
    mkdir -p "${TMP_DIR}" 
    echo "Installer Log - $(date)" > "${LOG_FILE}"
    info "安装日志将保存在: ${LOG_FILE}"

    detect_environment      
    detect_init_system    
    check_dependencies      

    select_protocol # <--- 新增：调用协议选择函数

    configure_sing_box # <--- 修改：根据 selected_protocol 生成配置
    install_sing_box
    configure_cloudflare_tunnel
    install_cloudflare_tunnel 
    generate_output_links # <--- 修改：根据 selected_protocol 生成链接

    success "所有安装和配置操作已成功完成！"
    info "详细日志请查看: ${LOG_FILE}"
}

# --- 脚本主入口 ---
main() {
    echo -e "\n${GREEN}欢迎使用 sing-box 与 Cloudflare Tunnel 自动化安装脚本${PLAIN}"
    echo -e "版本: ${YELLOW}${SCRIPT_VERSION}${PLAIN}"
    echo -e "此脚本将引导您完成安装或卸载过程。"
    echo -e "作者: (原始脚本作者 + AI 改进与兼容性增强)"
    echo -e "${BLUE}===============================================================${PLAIN}"
    echo

    if [ "$#" -gt 0 ]; then 
        case "$1" in
            uninstall|remove|delete)
                run_sudo echo "卸载操作需要sudo权限..." 
                uninstall_package
                exit 0
                ;;
            help|--help|-h)
                echo "用法: $0 [命令]"
                echo "命令:"
                echo "  (无命令)    执行完整的安装和配置流程。"
                echo "  uninstall   卸载 sing-box 和 (可选的) Cloudflare Tunnel。"
                echo "  help        显示此帮助信息。"
                exit 0
                ;;
            *)
                error_exit "未知参数: '$1'. 使用 '$0 help' 查看可用命令。"
                ;;
        esac
    fi

    run_sudo echo "安装操作需要sudo权限..." 
    run_installation
}

# --- 执行主函数 ---
main "$@"