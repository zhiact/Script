#!/bin/bash
# 使用更严格的错误检查模式
set -euo pipefail # -e: 命令失败时退出, -u: 使用未定义变量时退出, -o pipefail: 管道中命令失败则整个管道失败

# --- 全局配置与变量 (初始化) ---
# 脚本版本
readonly SCRIPT_VERSION="11.0-Enhanced" # 版本号

# 临时目录 (使用PID确保唯一性，避免并发冲突)
TMP_DIR="/tmp/sing-box-installer-$$"
# 日志文件路径 (示例)
LOG_FILE="${TMP_DIR}/installer.log"

# Cloudflare 临时隧道 PID 文件
CF_TEMP_TUNNEL_PID_FILE="${TMP_DIR}/cf_temp_tunnel.pid"

# 安装路径定义 (方便统一修改)
SB_INSTALL_PATH="/usr/local/bin/sing-box"
SB_CONFIG_DIR="/etc/sing-box"
SB_CONFIG_FILE="${SB_CONFIG_DIR}/config.json"
CF_INSTALL_PATH="/usr/local/bin/cloudflared" # 统一到 /usr/local/bin

# 用户配置 (由函数设置)
sb_uuid=""
sb_port=""
cf_use_tunnel="" # "temp", "fixed", "no"
cf_tunnel_token=""
cf_domain=""
detected_os="" # linux, darwin, freebsd
detected_arch="" # amd64, arm64, etc.

# --- 颜色定义 (用于输出美化) ---
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
    echo -e "${timestamp} [${level}] ${message}" | tee -a "${LOG_FILE}" # 同时输出到控制台和日志文件
}

info() {
    _log "${BLUE}INFO${PLAIN}" "$1"
}

success() {
    _log "${GREEN}SUCCESS${PLAIN}" "$1"
}

warn() {
    _log "${YELLOW}WARNING${PLAIN}" "$1" >&2
}

error_exit() {
    _log "${RED}ERROR${PLAIN}" "$1" >&2
    # CLEANUP 函数会自动被 trap 调用
    exit 1
}

# --- 清理函数 ---
CLEANUP() {
    info "执行清理操作..."
    # 停止临时的 Cloudflare tunnel
    if [ -f "${CF_TEMP_TUNNEL_PID_FILE}" ]; then
        info "停止临时的 Cloudflare tunnel (PID: $(cat "${CF_TEMP_TUNNEL_PID_FILE}"))..."
        # shellcheck disable=SC2046 # 我们确实需要这里的 word splitting
        sudo kill $(cat "${CF_TEMP_TUNNEL_PID_FILE}") &>/dev/null || true # 忽略错误
        rm -f "${CF_TEMP_TUNNEL_PID_FILE}"
    fi

    # 删除临时目录
    if [ -d "${TMP_DIR}" ]; then
        rm -rf "${TMP_DIR}"
        info "临时目录 ${TMP_DIR} 已删除。"
    fi
}
# 设置 trap，在脚本退出、收到中断或终止信号时执行清理
trap CLEANUP EXIT SIGINT SIGTERM

# --- Sudo 权限执行封装 ---
# (基本保持原样，但使用 error_exit)
run_sudo() {
    if [ "$(id -ru)" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            sudo "$@"
        else
            error_exit "此脚本需要 sudo 权限，但 sudo 命令未找到。"
        fi
    else
        "$@" # 已经是 root 用户
    fi
}

# --- 依赖检查 ---
check_dependencies() {
    info "开始检查依赖项..."
    local missing_count=0
    # 核心依赖: wget, curl, unzip, grep, jq, tar, uuidgen (新增)
    local core_deps=("wget" "curl" "unzip" "grep" "jq" "tar" "uuidgen")
    for dep in "${core_deps[@]}"; do
        if ! command -v "${dep}" >/dev/null 2>&1; then
            warn "依赖项 '${dep}' 未安装。"
            missing_count=$((missing_count + 1))
        fi
    done

    if [ ${missing_count} -gt 0 ]; then
        error_exit "请先安装缺失的依赖项，然后重新运行脚本。"
    fi

    # 特定于Alpine Linux的依赖 (libc6-compat)
    if [ "${detected_os}" = "linux" ] && command -v apk >/dev/null 2>&1; then
        if ! apk info -e libc6-compat >/dev/null 2>&1; then
            warn "当前为 Alpine Linux 系统，推荐安装 'libc6-compat' 以获得更好的 sing-box 兼容性。"
            info "您可以尝试使用 'sudo apk add libc6-compat' 命令安装。"
            # 这里不强制退出，让用户决定
        fi
    fi
    success "所有核心依赖项均已安装。"
}

# --- 环境检测 ---
detect_environment() {
    info "检测操作系统和架构..."
    # ... (此函数内容与之前版本类似，但会将结果存入 detected_os 和 detected_arch)
    # 示例：
    local machine_arch
    machine_arch=$(uname -m)
    case "$machine_arch" in
        amd64|x86_64) detected_arch="amd64" ;;
        i386|i686)    detected_arch="386" ;;
        aarch64|arm64)detected_arch="arm64" ;;
        armv*)        detected_arch="armv7" ;; # 某些二进制包区分armv7
        *arm*)        detected_arch="arm" ;;   # 通用arm
        s390x)        detected_arch="s390x" ;;
        riscv64)      detected_arch="riscv64" ;;
        mips)         detected_arch="mips" ;;
        mipsle)       detected_arch="mipsle" ;;
        *) error_exit "不支持的系统架构: $machine_arch" ;;
    esac

    local system_name
    system_name=$(uname -s)
    case "$system_name" in
        Linux)   detected_os="linux" ;;
        Darwin)  detected_os="darwin" ;;
        FreeBSD) detected_os="freebsd" ;;
        *) error_exit "不支持的操作系统: $system_name" ;;
    esac
    success "检测到环境: 系统=${detected_os}, 架构=${detected_arch}"
}

# --- 下载文件封装 ---
download_file() {
    local url="$1"
    local output_path="$2"
    local file_description="$3"
    local checksum_url="$4" # 可选的校验和文件URL
    local expected_checksum="$5" # 可选的预期校验和值

    info "正在下载 ${file_description} 从 ${url} ..."
    if command -v curl &>/dev/null; then
        if ! curl -L --connect-timeout 20 --retry 3 --retry-delay 5 -o "${output_path}" "${url}"; then
            error_exit "使用 curl 下载 ${file_description} 失败。"
        fi
    elif command -v wget &>/dev/null; then
        if ! wget --timeout=20 --tries=3 --waitretry=5 -O "${output_path}" "${url}"; then
            error_exit "使用 wget 下载 ${file_description} 失败。"
        fi
    else
        error_exit "未找到 curl 或 wget，无法下载文件。"
    fi
    success "${file_description} 下载成功。"

    # 可选的校验和验证
    if [ -n "${checksum_url}" ] && [ -n "${expected_checksum}" ]; then
        # 实际项目中，这里会下载校验和文件或使用预期的校验和进行比对
        info "校验和验证未在此示例中完全实现，但已预留位置。"
        # local downloaded_checksum
        # downloaded_checksum=$(sha256sum "${output_path}" | awk '{print $1}')
        # if [ "${downloaded_checksum}" != "${expected_checksum}" ]; then
        #     rm -f "${output_path}"
        #     error_exit "${file_description} 校验和不匹配！文件可能已损坏或被篡改。"
        # fi
        # success "${file_description} 校验和验证通过。"
    fi
}

# --- Sing-box 配置 ---
configure_sing_box() {
    info "开始配置 sing-box..."
    local input_uuid
    local input_port

    # UUID 配置 (强制使用 uuidgen)
    sb_uuid=$(uuidgen)
    info "已自动生成 sing-box UUID: ${sb_uuid}"
    printf "${YELLOW}您希望使用此 UUID 吗? (Y/n) 或输入您自己的 UUID: ${PLAIN}"
    read -r input_uuid
    if [[ "${input_uuid,,}" == "n" ]] || [[ "${input_uuid,,}" == "no" ]]; then
        printf "${YELLOW}请输入您的自定义 UUID: ${PLAIN}"
        read -r input_uuid
        # 严格的 UUID 格式校验
        if [[ ! "${input_uuid}" =~ ^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$ ]]; then
            error_exit "输入的 UUID 格式无效。"
        fi
        sb_uuid="${input_uuid}"
    elif [ -n "${input_uuid}" ] && [[ ! "${input_uuid,,}" == "y" ]] && [[ ! "${input_uuid,,}" == "yes" ]]; then
        if [[ ! "${input_uuid}" =~ ^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$ ]]; then
            error_exit "输入的 UUID 格式无效。"
        fi
        sb_uuid="${input_uuid}"
    fi
    info "sing-box 将使用 UUID: ${sb_uuid}"

    # 端口配置
    printf "${YELLOW}请输入 sing-box 监听端口 (默认: 8008): ${PLAIN}"
    read -r input_port
    sb_port=${input_port:-8008}
    if ! [[ "${sb_port}" =~ ^[0-9]+$ ]] || [ "${sb_port}" -lt 1 ] || [ "${sb_port}" -gt 65535 ]; then
        error_exit "端口号无效。必须是 1-65535 之间的整数。"
    fi
    info "sing-box 将监听端口: ${sb_port}"

    # 创建配置目录并设置权限
    run_sudo mkdir -p "${SB_CONFIG_DIR}"
    run_sudo chmod 700 "${SB_CONFIG_DIR}" # 限制访问

    # 生成 sing-box 配置文件 (config.json)
    info "正在生成 sing-box 配置文件: ${SB_CONFIG_FILE}"
    local vmess_ws_path="/${sb_uuid}-vm" # WebSocket 路径
    # 使用 jq 生成 JSON，提高可读性和可靠性
    # 注意：early_data_header_name 用于实现类似 ed=2048 的早期数据混淆
    if ! run_sudo sh -c "jq -n \
        --arg uuid \"${sb_uuid}\" \
        --argjson port \"${sb_port}\" \
        --arg path \"${vmess_ws_path}\" \
        '{
            \"log\": {
                \"level\": \"info\",
                \"timestamp\": true,
                \"output\": \"${SB_CONFIG_DIR}/sing-box.log\"
            },
            \"dns\": {
                \"servers\": [{\"address\": \"8.8.8.8\"}, {\"address\": \"1.1.1.1\"}]
            },
            \"inbounds\": [
                {
                    \"type\": \"vmess\",
                    \"tag\": \"vmess-ws-in\",
                    \"listen\": \"::\",
                    \"listen_port\": \$port,
                    \"users\": [
                        { \"uuid\": \$uuid, \"alterId\": 0 }
                    ],
                    \"transport\": {
                        \"type\": \"ws\",
                        \"path\": \$path,
                        \"early_data_header_name\": \"Sec-WebSocket-Protocol\"
                    }
                }
            ]
        }' > '${SB_CONFIG_FILE}'"; then
        error_exit "生成 sing-box 配置文件失败。"
    fi
    run_sudo chmod 600 "${SB_CONFIG_FILE}" # 限制配置文件访问权限
    success "sing-box 配置完成。"
}

# --- Sing-box 安装 ---
install_sing_box() {
    info "开始安装 sing-box..."
    local latest_tag download_url archive_name extracted_dir binary_in_archive

    # 获取最新版本标签 (SagerNet/sing-box)
    info "正在获取 sing-box 最新版本..."
    latest_tag=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name // empty' | sed 's/^v//') # 移除可能存在的 'v' 前缀
    if [ -z "${latest_tag}" ]; then
        warn "自动获取最新版本失败。请手动输入 sing-box 版本号 (例如: 1.9.0):"
        read -r latest_tag
        if [ -z "${latest_tag}" ]; then
            error_exit "未提供版本号，安装中止。"
        fi
    fi
    info "将安装 sing-box 版本: v${latest_tag}"

    # 构建下载链接和文件名
    # 注意: SagerNet 的命名规则可能包含 'v' 也可能不包含，这里统一处理
    archive_name="sing-box-${latest_tag}-${detected_os}-${detected_arch}.tar.gz"
    download_url="https://github.com/SagerNet/sing-box/releases/download/v${latest_tag}/${archive_name}"

    # 针对 armv7架构的特殊处理 (SagerNet 可能用 'arm' 而非 'armv7')
    if [ "${detected_arch}" = "armv7" ]; then
        if ! curl --output /dev/null --silent --head --fail "${download_url}"; then
            info "armv7 特定名称的压缩包未找到，尝试使用通用 'arm' 名称..."
            archive_name="sing-box-${latest_tag}-${detected_os}-arm.tar.gz"
            download_url="https://github.com/SagerNet/sing-box/releases/download/v${latest_tag}/${archive_name}"
        fi
    fi

    # 下载
    download_file "${download_url}" "${TMP_DIR}/${archive_name}" "sing-box v${latest_tag} 压缩包"

    # 解压
    info "正在解压 sing-box 压缩包..."
    extracted_dir="${TMP_DIR}/sing-box-extracted"
    mkdir -p "${extracted_dir}"
    if ! tar -xzf "${TMP_DIR}/${archive_name}" -C "${extracted_dir}"; then
        error_exit "解压 sing-box 压缩包失败。文件可能已损坏。"
    fi

    # 在解压目录中查找 sing-box 二进制文件 (通常在与压缩包同名的子目录内)
    binary_in_archive=$(find "${extracted_dir}" -type f -name "sing-box" | head -n 1)
    if [ -z "${binary_in_archive}" ]; then
        error_exit "在解压的目录中未找到 'sing-box' 二进制文件。"
    fi
    info "找到 sing-box 二进制文件: ${binary_in_archive}"

    # 安装二进制文件
    info "正在安装 sing-box 到 ${SB_INSTALL_PATH}..."
    run_sudo install -m 755 "${binary_in_archive}" "${SB_INSTALL_PATH}"

    # 服务管理: 卸载旧服务 -> 安装新服务 -> 启用并启动
    info "正在设置 sing-box 系统服务..."
    # 尝试卸载任何已存在的服务 (忽略错误)
    run_sudo "${SB_INSTALL_PATH}" service -c "${SB_CONFIG_FILE}" uninstall &>/dev/null || true

    # 安装新服务
    if ! run_sudo "${SB_INSTALL_PATH}" service -c "${SB_CONFIG_FILE}" install; then
        error_exit "安装 sing-box 服务失败。"
    fi

    # 启用并启动服务 (systemd)
    if command -v systemctl &>/dev/null; then
        info "正在启用并启动 sing-box 服务 (使用 systemd)..."
        run_sudo systemctl enable sing-box
        run_sudo systemctl daemon-reload # 确保 systemd 读取到新的服务文件
        run_sudo systemctl restart sing-box # 使用 restart 确保应用最新配置

        # 检查服务状态
        sleep 2 # 等待服务启动
        if run_sudo systemctl is-active --quiet sing-box; then
            success "sing-box 服务已成功启动并运行。"
        else
            warn "sing-box 服务可能启动失败。请检查日志: journalctl -u sing-box -n 50 --no-pager 或 ${SB_CONFIG_DIR}/sing-box.log"
        fi
    else
        warn "未检测到 systemd。sing-box 服务已安装，但您可能需要手动管理它。"
        info "您可以尝试使用以下命令运行: sudo ${SB_INSTALL_PATH} run -c ${SB_CONFIG_FILE}"
    fi
    success "sing-box v${latest_tag} 安装完成。"
}


# --- Cloudflare Tunnel 配置 ---
configure_cloudflare_tunnel() {
    info "开始配置 Cloudflare Tunnel..."
    echo -e "${YELLOW}您是否希望使用 Cloudflare Tunnel 将 sing-box 服务暴露到公网?${PLAIN}"
    echo "  1. 是，使用临时的 Cloudflare Tunnel (脚本或终端关闭时隧道终止，或系统重启后失效)"
    echo "  2. 是，使用永久的 Cloudflare Tunnel (需要 Cloudflare Zero Trust 面板提供的 Token)"
    echo "  3. 否，不使用 Cloudflare Tunnel (sing-box 将仅监听本地端口)"

    local choice
    while true; do
        printf "${YELLOW}请输入您的选择 [1-3] (默认: 3): ${PLAIN}"
        read -r choice
        choice=${choice:-3} # 默认为3 (不使用)
        case "$choice" in
            1) cf_use_tunnel="temp"; break ;;
            2) cf_use_tunnel="fixed"; break ;;
            3) cf_use_tunnel="no"; break ;;
            *) warn "无效的选择，请输入 1, 2, 或 3。" ;;
        esac
    done

    if [ "${cf_use_tunnel}" = "fixed" ]; then
        printf "${YELLOW}请输入您的 Cloudflare Tunnel Token (输入时不会显示字符): ${PLAIN}"
        # shellcheck disable=SC2034 # token 被后续使用
        read -rs cf_tunnel_token # -s 实现静默输入
        echo # 读取静默输入后换行
        if [ -z "${cf_tunnel_token}" ]; then
            error_exit "固定隧道的 Token 不能为空。"
        fi
    fi

    if [ "${cf_use_tunnel}" = "temp" ] || [ "${cf_use_tunnel}" = "fixed" ]; then
        printf "${YELLOW}请输入用于 Cloudflare Tunnel 的域名/子域名 (例如: myproxy.example.com): ${PLAIN}"
        read -r cf_domain
        if [ -z "${cf_domain}" ]; then
            if [ "${cf_use_tunnel}" = "temp" ]; then
                info "未指定域名，临时隧道将尝试使用随机的 *.trycloudflare.com 域名。"
                cf_domain="" # 明确置空
            else # 固定隧道必须有域名
                error_exit "固定隧道使用的域名不能为空。"
            fi
        # 基础的域名格式校验 (允许 - 但不能在开头结尾，允许数字字母)
        elif ! echo "${cf_domain}" | grep -Pq '^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))+$'; then
            error_exit "输入的域名格式无效。"
        fi
        if [ -n "${cf_domain}" ]; then
            info "Cloudflare Tunnel 将尝试使用域名: ${cf_domain}"
        fi
    fi
    success "Cloudflare Tunnel 配置完成。"
}

# --- Cloudflare Tunnel 安装 ---
install_cloudflare_tunnel() {
    if [ "${cf_use_tunnel}" = "no" ]; then
        info "根据用户选择，跳过 Cloudflare Tunnel 安装。"
        return 0
    fi

    info "开始安装 Cloudflare Tunnel (cloudflared)..."
    local latest_tag download_url binary_name

    # 获取最新版本 (cloudflared)
    # Cloudflare 的 release tag 通常不带 'v'
    latest_tag=$(curl -s https://api.github.com/repos/cloudflare/cloudflared/releases/latest | jq -r '.tag_name // empty')
    if [ -z "${latest_tag}" ]; then
        warn "自动获取 cloudflared 最新版本失败。请手动输入版本号 (例如: 2024.5.0):"
        read -r latest_tag
        if [ -z "${latest_tag}" ]; then
            error_exit "未提供 cloudflared 版本号，安装中止。"
        fi
    fi
    info "将安装 cloudflared 版本: ${latest_tag}"

    # 构建下载链接和文件名
    binary_name="cloudflared-${detected_os}-${detected_arch}"
    if [ "${detected_os}" = "windows" ]; then # 尽管脚本主要目标是Unix-like
        binary_name="${binary_name}.exe"
    fi
    download_url="https://github.com/cloudflare/cloudflared/releases/download/${latest_tag}/${binary_name}"

    # 下载
    download_file "${download_url}" "${TMP_DIR}/${binary_name}" "cloudflared ${latest_tag}"

    # 安装
    info "正在安装 cloudflared 到 ${CF_INSTALL_PATH}..."
    run_sudo install -m 755 "${TMP_DIR}/${binary_name}" "${CF_INSTALL_PATH}"

    # 配置并启动隧道
    if [ "${cf_use_tunnel}" = "temp" ]; then
        info "正在启动临时的 Cloudflare Tunnel，将本地端口 ${sb_port} 暴露出去..."
        info "此隧道将在脚本退出或您手动停止 (Ctrl+C) 时关闭。"
        info "如果未指定域名，cloudflared 会尝试分配一个随机的 *.trycloudflare.com 域名。"
        info "隧道日志将输出到: ${TMP_DIR}/cf_temp_tunnel.log"

        # 使用 nohup 将其置于后台，并将PID存入文件以便后续清理
        # --edge-ip-version auto: 让 cloudflared 自动选择 IP 版本
        # --pidfile: 让 cloudflared 自己管理 PID 文件，更可靠
        # --logfile: 指定日志文件
        # --no-autoupdate: 避免在脚本运行时自动更新导致意外
        # --url: 指定本地服务地址
        # 如果 cf_domain 为空, cloudflared 会尝试分配 trycloudflare.com 域名
        # 如果 cf_domain 非空, cloudflared 会尝试使用该域名 (需要DNS正确配置，或为 trycloudflare.com 服务)
        local tunnel_hostname_arg=""
        if [ -n "${cf_domain}" ]; then
             # 对于临时隧道使用自定义域名，通常需要登录。
             # 若只想用作SNI/Host，则客户端配置此域名，隧道本身可能仍是随机域名。
             # 这里假设用户希望用此域名访问。
             # tunnel_hostname_arg="--hostname ${cf_domain}" # Cloudflared 的这个选项通常用于固定隧道或需要登录的场景
             info "临时隧道将尝试监听请求中的 Host header 为 ${cf_domain} 的流量，或分配随机域名。"
        fi

        # nohup 将确保即使终端关闭，只要脚本的父进程（如果 nohup 由脚本启动）还在，它就可能继续运行。
        # 但由于我们有 trap CLEANUP，脚本退出时会尝试 kill 它。
        run_sudo nohup "${CF_INSTALL_PATH}" tunnel --url "http://localhost:${sb_port}" --logfile "${TMP_DIR}/cf_temp_tunnel.log" --pidfile "${CF_TEMP_TUNNEL_PID_FILE}" --edge-ip-version auto --no-autoupdate ${tunnel_hostname_arg} > "${TMP_DIR}/nohup_cf.out" 2>&1 &
        # 等待PID文件创建和隧道启动
        info "等待临时隧道启动 (最多15秒)..."
        for i in {1..15}; do
            if [ -f "${CF_TEMP_TUNNEL_PID_FILE}" ] && [ -s "${CF_TEMP_TUNNEL_PID_FILE}" ]; then
                if ps -p "$(cat "${CF_TEMP_TUNNEL_PID_FILE}")" > /dev/null ; then
                    success "临时 Cloudflare Tunnel 似乎已启动 (PID: $(cat "${CF_TEMP_TUNNEL_PID_FILE}"))."
                    # 尝试从日志中提取分配的域名
                    sleep 3 # 给日志一点时间写入
                    local assigned_domain
                    assigned_domain=$(grep -Eo 'https://[a-z0-9-]+.trycloudflare.com' "${TMP_DIR}/cf_temp_tunnel.log" | head -n 1)
                    if [ -n "$assigned_domain" ]; then
                        info "检测到 Cloudflare 分配的临时域名: ${assigned_domain}"
                        # 如果用户未指定cf_domain，我们可以用这个
                        if [ -z "${cf_domain}" ]; then
                            cf_domain=$(echo "${assigned_domain}" | sed 's|https://||')
                            info "将使用此域名生成连接链接: ${cf_domain}"
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
            warn "临时 Cloudflare Tunnel 可能未能成功启动。请检查日志: ${TMP_DIR}/cf_temp_tunnel.log 和 ${TMP_DIR}/nohup_cf.out"
        fi

    elif [ "${cf_use_tunnel}" = "fixed" ]; then
        info "正在设置永久的 Cloudflare Tunnel (使用提供的 Token)..."
        info "此过程通常会将 cloudflared 安装为一个系统服务，并使用 Token 进行认证和连接。"
        info "如果这是第一次使用此 Token，可能需要一些时间与 Cloudflare 进行握手。"
        # cloudflared tunnel run --token <TOKEN>
        # 这个命令通常会在前台运行，除非它自己daemonize并安装服务。
        # 如果需要它作为后台服务，用户可能需要使用 screen/tmux，或者脚本应辅助创建服务文件。
        # 许多情况下，`cloudflared service install` 是在获取 token 并创建隧道后手动执行的。
        # `tunnel run --token` 的行为更像是一次性的运行和注册。
        info "正在执行: sudo ${CF_INSTALL_PATH} tunnel --no-autoupdate run --token ${cf_tunnel_token}"
        warn "请注意: cloudflared 可能会在前台运行。如果需要后台运行，请使用 screen/tmux 或确保 cloudflared 自行注册为服务。"
        warn "成功连接后，您可能需要按 Ctrl+C 来使脚本继续（如果 cloudflared 未自动后台化）。"
        warn "或者，您也可以在新终端运行此脚本以完成后续步骤。"
        # 执行命令，但不等待其完成，因为 `tunnel run` 可能会阻塞
        # 更好的做法是指导用户如何创建命名的隧道并作为服务运行。
        # 为了简化脚本，我们假设用户会处理 `tunnel run` 的前台行为。
        # 或者，提示用户在新终端执行。
        # 实际上， `cloudflared tunnel run --token YOUR_TOKEN` 应该会尝试连接，如果成功，它可能会保持在前台。
        # 这对于自动化脚本来说是一个挑战。
        # 一种可能是先尝试创建隧道服务，但那通常不直接用 token。
        #
        # 简化处理：让用户知道它可能在前台运行。
        if ! run_sudo "${CF_INSTALL_PATH}" tunnel --label "sing-box-tunnel" --no-autoupdate service install "${cf_tunnel_token}"; then
             error_exit "使用 Token 安装 Cloudflare Tunnel 服务失败。请检查 cloudflared 日志。"
        fi
        run_sudo systemctl enable "cloudflared@sing-box-tunnel.service" || run_sudo systemctl enable cloudflared # 尝试通用名称
        run_sudo systemctl start "cloudflared@sing-box-tunnel.service" || run_sudo systemctl start cloudflared

        # 验证服务是否成功
        sleep 3
        if run_sudo systemctl is-active --quiet "cloudflared@sing-box-tunnel.service" || run_sudo systemctl is-active --quiet cloudflared; then
            success "Cloudflare Tunnel 服务已安装并尝试启动。"
            info "请确保您的域名 ${cf_domain} 的 DNS CNAME 记录指向了正确的隧道地址 (通常是 <UUID>.cfargotunnel.com)。"
        else
            warn "Cloudflare Tunnel 服务可能未能成功启动。请手动检查服务状态和日志。"
            info "您可能需要手动运行: sudo cloudflared tunnel run --token YOUR_TOKEN --name your-tunnel-name"
            info "并确保DNS配置正确。"
        fi
    fi
    success "Cloudflare Tunnel (cloudflared) 安装和配置尝试完成。"
}

# --- 生成输出链接 ---
generate_output_links() {
    info "正在生成 sing-box 连接信息..."
    local vmess_address="${sb_port}" # 默认地址
    local vmess_port="${sb_port}"    # 默认端口
    local vmess_host_header=""       # WebSocket Host 头部
    local vmess_path="/${sb_uuid}-vm" # 与 sing-box 配置一致
    local vmess_security="none"      # 默认无 TLS
    local vmess_sni=""               # SNI，用于 TLS
    local vmess_remark="sing-box-ws"

    if [ "${cf_use_tunnel}" != "no" ] && [ -n "${cf_domain}" ]; then
        vmess_address="${cf_domain}"
        vmess_port="443" # Cloudflare 默认使用 443 HTTPS
        vmess_host_header="${cf_domain}"
        vmess_security="tls"
        vmess_sni="${cf_domain}"
        vmess_remark="sing-box_CF_${cf_domain}"
    elif [ "${cf_use_tunnel}" = "no" ]; then
        # 如果没有隧道，提示用户可能需要用公网IP替换
        local server_ip
        # 尝试获取公网IP (方法可能不完全可靠)
        server_ip=$(curl -s ip.sb || curl -s ifconfig.me || hostname -I | awk '{print $1}')
        if [ -n "$server_ip" ]; then
            vmess_address="$server_ip"
        else
            vmess_address="YOUR_SERVER_IP" # 提示用户替换
        fi
        warn "未启用 Cloudflare Tunnel。以下链接中的地址 '${vmess_address}' 可能需要您手动修改为服务器的公网IP地址。"
        vmess_remark="sing-box_direct_${vmess_address}"
    else
        warn "Cloudflare Tunnel 已启用但域名信息不明确，生成的链接可能需要手动调整。"
        vmess_remark="sing-box_CF_manual_check"
    fi

    # VMess JSON 结构
    # 关于 path 中的 ?ed=2048:
    # 这是早期数据混淆参数，如果 sing-box 服务端配置了 "early_data_header_name"，
    # 客户端通常不需要在 path 中显式加入 "?ed=2048"。
    # 这里我们保持 path 纯净，与服务端配置一致。
    local vmess_json
    vmess_json=$(jq -n \
        --arg v "2" \
        --arg ps "${vmess_remark}" \
        --arg add "${vmess_address}" \
        --arg port "${vmess_port}" \
        --arg id "${sb_uuid}" \
        --arg aid "0" \
        --arg scy "auto" \
        --arg net "ws" \
        --arg type "none" \
        --arg host "${vmess_host_header}" \
        --arg path "${vmess_path}" \
        --arg tls "${vmess_security}" \
        --arg sni "${vmess_sni}" \
        --arg alpn "" \
        --arg fp "" \
        '{v: $v, ps: $ps, add: $add, port: $port, id: $id, aid: $aid, scy: $scy, net: $net, type: $type, host: $host, path: $path, tls: $tls, sni: $sni, alpn: $alpn, fp: $fp}')

    local vmess_link="vmess://$(echo -n "${vmess_json}" | base64 -w0)" # 使用 echo -n 避免末尾换行符

    echo -e "\n${GREEN}================ Sing-box 安装完成 ================${PLAIN}"
    echo -e "  Sing-box UUID:  ${YELLOW}${sb_uuid}${PLAIN}"
    echo -e "  Sing-box 端口: ${YELLOW}${sb_port}${PLAIN}"
    if [ "${cf_use_tunnel}" != "no" ]; then
        echo -e "  Cloudflare 域名: ${YELLOW}${cf_domain:- (临时隧道可能动态分配，请查看日志)}${PLAIN}"
    else
        echo -e "  Cloudflare Tunnel: ${RED}未使用${PLAIN}"
    fi
    echo -e "\n${GREEN}VMess 连接链接:${PLAIN}"
    echo -e "${YELLOW}${vmess_link}${PLAIN}\n"

    # 生成二维码 (如果 qrencode 已安装)
    if command -v qrencode &>/dev/null; then
        echo -e "${GREEN}VMess 二维码 (部分终端可能无法完美显示):${PLAIN}"
        qrencode -t ansiutf8 "${vmess_link}"
    else
        info "未安装 'qrencode'，无法在终端生成二维码。"
        info "您可以复制上面的链接到二维码生成工具中使用。"
    fi
    echo -e "${GREEN}==================================================${PLAIN}\n"

    if [ "${cf_use_tunnel}" = "temp" ]; then
        info "临时的 Cloudflare Tunnel 正在运行。当您关闭此会话或脚本发生错误时，它可能会停止。"
        info "您可以查看 ${TMP_DIR}/cf_temp_tunnel.log 获取隧道信息和日志。"
        info "要手动停止它: sudo kill $(cat ${CF_TEMP_TUNNEL_PID_FILE} 2>/dev/null || echo 'PID_NOT_FOUND')"
    fi
}

# --- 卸载功能 ---
uninstall_package() {
    info "开始执行卸载流程..."

    # 卸载 sing-box
    if [ -f "${SB_INSTALL_PATH}" ]; then
        info "正在卸载 sing-box 服务..."
        run_sudo "${SB_INSTALL_PATH}" service -c "${SB_CONFIG_FILE}" uninstall &>/dev/null || true # 忽略错误
        info "正在移除 sing-box 二进制文件: ${SB_INSTALL_PATH}"
        run_sudo rm -f "${SB_INSTALL_PATH}"
    else
        info "未找到 sing-box 二进制文件 (${SB_INSTALL_PATH})，跳过。"
    fi

    # 移除 sing-box 配置文件和目录
    if [ -f "${SB_CONFIG_FILE}" ]; then
        info "正在移除 sing-box 配置文件: ${SB_CONFIG_FILE}"
        run_sudo rm -f "${SB_CONFIG_FILE}"
    fi
    if [ -d "${SB_CONFIG_DIR}" ]; then
        # 仅当目录为空时尝试移除，避免误删日志等
        if [ -z "$(ls -A "${SB_CONFIG_DIR}")" ]; then
            info "正在移除空的 sing-box 配置目录: ${SB_CONFIG_DIR}"
            run_sudo rmdir "${SB_CONFIG_DIR}" &>/dev/null || true
        else
            info "sing-box 配置目录 ${SB_CONFIG_DIR} 非空，未删除 (可能包含日志等)。"
        fi
    fi

    # 卸载 Cloudflare Tunnel (cloudflared)
    printf "${YELLOW}是否同时卸载 Cloudflare Tunnel (cloudflared)? [y/N]: ${PLAIN}"
    read -r choice
    if [[ "${choice,,}" == "y" ]] || [[ "${choice,,}" == "yes" ]]; then
        if [ -f "${CF_INSTALL_PATH}" ]; then
            info "正在尝试停止并卸载 Cloudflare Tunnel 服务..."
            # 尝试使用 cloudflared 自身的卸载命令 (如果存在且支持)
            # `cloudflared service uninstall` 通常用于通过 `service install TOKEN` 安装的服务
            # 或者命名隧道 `cloudflared service uninstall --name your-tunnel-name`
            # 由于我们可能不知道具体的服务名，尝试通用卸载
            run_sudo "${CF_INSTALL_PATH}" service uninstall &>/dev/null || true # 通用卸载尝试

            # 如果是 systemd 系统，尝试更明确地停止和禁用服务
            if command -v systemctl &>/dev/null; then
                # 查找可能的 cloudflared 服务名
                local cf_services
                cf_services=$(systemctl list-units --full --all --type=service | grep -Eo 'cloudflared@[^.]+\.service|cloudflared\.service' || true)
                if [ -n "${cf_services}" ]; then
                    for service_name in ${cf_services}; do
                        info "正在停止并禁用 systemd 服务: ${service_name}"
                        run_sudo systemctl stop "${service_name}" &>/dev/null || true
                        run_sudo systemctl disable "${service_name}" &>/dev/null || true
                    done
                    run_sudo systemctl daemon-reload
                else
                    info "未通过 systemctl 找到明确的 cloudflared 服务单元。"
                fi
            fi
            info "正在移除 cloudflared 二进制文件: ${CF_INSTALL_PATH}"
            run_sudo rm -f "${CF_INSTALL_PATH}"
        else
            info "未找到 cloudflared 二进制文件 (${CF_INSTALL_PATH})，跳过。"
        fi
        info "Cloudflare Tunnel 卸载尝试完成。您可能还需要在 Cloudflare Dashboard 中手动清理隧道配置和DNS记录。"
    fi

    # 清理 trap 可能会再次运行，确保是安全的
    # CLEANUP 函数已通过 trap 注册，会在脚本退出时自动调用
    success "卸载流程已完成。"
    info "部分文件或服务可能需要重启系统才能完全清除。"
}

# --- 主安装流程 ---
run_installation() {
    # 0. 初始化和环境准备
    mkdir -p "${TMP_DIR}" # 确保临时目录存在
    info "安装日志将保存在: ${LOG_FILE}"
    detect_environment
    check_dependencies

    # 1. 配置 sing-box
    configure_sing_box

    # 2. 安装 sing-box
    install_sing_box

    # 3. 配置 Cloudflare Tunnel (可选)
    configure_cloudflare_tunnel

    # 4. 安装 Cloudflare Tunnel (如果选择)
    install_cloudflare_tunnel # 函数内部会判断 cf_use_tunnel

    # 5. 生成并显示连接信息
    generate_output_links

    success "所有安装和配置操作已成功完成！"
}

# --- 脚本主入口 ---
main() {
    echo -e "${GREEN}欢迎使用 sing-box 与 Cloudflare Tunnel 自动化安装脚本${PLAIN}"
    echo -e "版本: ${YELLOW}${SCRIPT_VERSION}${PLAIN}"
    echo -e "作者: (原作者 + AI 改进)"
    echo -e "========================================================="
    echo # 空行

    # 处理命令行参数 (例如: uninstall)
    if [ "$#" -gt 0 ]; then
        case "$1" in
            uninstall|remove|delete)
                uninstall_package
                exit 0
                ;;
            help|--help|-h)
                echo "用法: $0 [uninstall]"
                echo "  无参数: 执行安装流程。"
                echo "  uninstall: 执行卸载流程。"
                exit 0
                ;;
            *)
                error_exit "未知参数: $1. 使用 'uninstall' 或 'help'."
                ;;
        esac
    fi

    # 执行主安装流程
    run_installation
}

# --- 执行主函数 ---
# 将所有标准输出和标准错误重定向到 tee，一份到控制台，一份到日志文件
# 但这会使得 trap 中的 echo 也进入日志，可能需要更细致的控制
# 为了简化，我们让 _log 函数自己处理 tee
main "$@"