#!/bin/bash
set -e
set -u
TMP_DIR="/tmp/sing-box-tmp"
CLEANUP() {
    rm -rf "$TMP_DIR"
    sudo rm -f "$sbxcfg_path"
}
trap CLEANUP EXIT

export LANG=en_US.UTF-8
sbxcfg_path="/etc/sing-box/config.json"


red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

err() {
    printf "${red}%s${plain}\n" "$*" >&2
}

success() {
    printf "${green}%s${plain}\n" "$*"
}

info() {
	printf "${yellow}%s${plain}\n" "$*"
}

sudo() {
    myEUID=$(id -ru)
    if [ "$myEUID" -ne 0 ]; then
        if command -v sudo > /dev/null 2>&1; then
            command sudo "$@"
        else
            err "ERROR: sudo is not installed on the system, the action cannot be proceeded."
            exit 1
        fi
    else
        "$@"
    fi
}
deps_check() {
    local deps=("wget" "curl" "unzip" "grep" "jq")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null; then
            err "依赖 '$dep' 未安装"
            exit 1
        fi
    done
    # 检查 libc6-compat（多平台）
    if [ "$os" = "linux" ]; then
        if command -v dpkg >/dev/null && ! dpkg -l libc6-compat >/dev/null; then
            err "请安装 libc6-compat: sudo apt install libc6-compat"
            exit 1
        elif command -v apk >/dev/null && ! apk info libc6-compat >/dev/null; then
            err "请安装 libc6-compat: sudo apk add libc6-compat"
            exit 1
        fi
    fi
}     


env_check() {
    mach=$(uname -m)
    case "$mach" in
        amd64|x86_64)
            os_arch="amd64"
            ;;
        i386|i686)
            os_arch="386"
            ;;
        aarch64|arm64)
            os_arch="arm64"
            ;;
        *arm*)
            os_arch="arm"
            ;;
        s390x)
            os_arch="s390x"
            ;;
        riscv64)
            os_arch="riscv64"
            ;;
        mips)
            os_arch="mips"
            ;;
        mipsel|mipsle)
            os_arch="mipsle"
            ;;
        *)
            err "Unknown architecture: $mach"
            exit 1
            ;;
    esac

    system=$(uname)
    case "$system" in
        *Linux*)
            os="linux"
            ;;
        *Darwin*)
            os="darwin"
            ;;
        *FreeBSD*)
            os="freebsd"
            ;;
        *)
            err "Unknown architecture: $system"
            exit 1
            ;;
    esac
}

init() {
    env_check
    deps_check

}
set_singbox_cfg(){
    local sx_uuid sx_port
    echo "setting sing-box cfg..."
    printf "请输入UUID：（默认自动生成）: "
    while true; do 
        read -r sx_uuid
        if [ -z "$sx_uuid" ]; then
            sx_uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || head -c 16 /dev/urandom | md5sum | cut -d' ' -f1)
            if ! [[ "$sx_uuid" =~ ^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$ ]]; then
                err "UUID 生成失败"
                exit 1
            fi
            break
        elif [[ "$sx_uuid" =~ ^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$ ]]; then
            break
        else
            err "输入的 UUID 格式错误，请重新输入"
        fi 
    done
    printf "请输入暴露端口: (默认 8008)"
    while true; do
        read -r sx_port
        sx_port=${sx_port:-8008}
        if [[ "$sx_port" =~ ^[0-9]+$ ]] && [ "$sx_port" -ge 1 ] && [ "$sx_port" -le 65535 ]; then
            break
    fi
    err "端口号必须为 1-65535 之间的整数"
    done

    sudo mkdir -p "/etc/sing-box"
    sudo chmod 700 "/etc/sing-box"
    sudo mkdir -p "/etc/sing-box"
    jq -n \
    --arg uuid "$sx_uuid" \
    --argjson port "$sx_port" \
    '{
        "log": { "disabled": false, "level": "info" },
        "inbounds": [{
            "type": "vmess",
            "listen_port": $port,
            "users": [ { "uuid": $uuid } ],
            "transport": { "type": "ws", "path": "\($uuid)-vm" }
        }]
    }' | sudo tee "$sbxcfg_path" >/dev/null
    echo "set sing-box cfg success."

}
install_singbox(){ 
    echo "Installing sing-box..."
    latest=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep '"tag_name":' | cut -d '"' -f 4 | sed 's/v//')
    url="https://github.com/SagerNet/sing-box/releases/download/v$latest/sing-box-$latest-$os-$os_arch.tar.gz"
    mkdir -p "$TMP_DIR"
    cd "$TMP_DIR"
    wget_args=(
        "-T" "60"
        "-O" "$TMP_DIR/sing-box-$latest-$os-$os_arch.tar.gz"
        "$url"
    )
    if ! wget "${wget_args[@]}" >/dev/null 2>&1; then
        err "Download sing-box release failed, check your network connectivity"
        exit 1
    fi
    sxb_path="/usr/local/bin/sing-box" 
    if ! tar -xzf "sing-box-$latest-$os-$os_arch.tar.gz"; then
        err "解压失败，文件可能损坏"
        exit 1
    fi
    cd sing-box-${latest}-$os-$os_arch
    sudo install -m 755 sing-box "$sxb_path"

    # 卸载服务
    sudo "$sxb_path" service -c "$sbxcfg_path" uninstall >/dev/null 2>&1

    # 安装服务
    _cmd=(
        "$sxb_path"
        "service"
        "-c"
        "$sbxcfg_path"
        "install"
    )
    if ! sudo "${_cmd[@]}"; then
        err "Install sing-box service failed"
        sudo "$sxb_path service -c $sbxcfg_path" uninstall >/dev/null 2>&1
        exit 1
    fi
    echo "Install sing-box success！"

}

set_cloudflare_cfg(){
    echo "使用cloudflare隧道"
    echo "1. 临时隧道"
    echo "2. 固定隧道"
    echo "3. 不使用"
    while true; do
        printf "请输入选项 [1-3]"
        read -r option
        case "${option}" in
            1)
                sx_trust=1
                break
                ;;
            2)
                sx_trust=2
                break
                ;;
            3)
                sx_trust=3
                break
                ;;
            *)
                err "请输入正确的选项 [1-3]"
                ;;
        esac
    done
    if [ "$sx_trust" = 2 ]; then
        echo "输入固定隧道token:"
        read -r trust_token  # 修正变量名
    fi
    if [ "$sx_trust" != 3 ]; then
        echo "请输入隧道映射域名:"
        read -r cf_domain
    fi
}

install_cloudflare(){ 
    echo "Installing cloudflare..."
    url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-$os-$os_arch"
    cf_path="/usr/bin/cloudflared"
    curl_args=(
        "-L" 
        "$url"
        "-o" 
        "$cf_path"
    )
    if ! curl "${curl_args[@]}" >/dev/null 2>&1; then
        err "Download cloudflare release failed, check your network connectivity"
        exit 1
    fi
    chmod +x  "$cf_path"
    #临时隧道
    if [ "$sx_trust" = 1 ]; then
        nohup sudo "$cf_path" tunnel run --url "http://localhost:$sx_port" >/dev/null 2>&1 &

    fi
    #固定隧道
    if [ "$sx_trust" = 2 ]; then
        _cmd=(
            "$cf_path"
            "tunnel"
            "run"
            "--token"
            "$trust_token"
        )
        if ! sudo "${_cmd[@]}"; then
            err "Install tunnel service failed"
            exit 1
        fi
    fi  

    echo "Install cloudflare success！"

}
install() {
    set_singbox_cfg
    install_singbox

    set_cloudflare_cfg
    if [ "$sx_trust" = 3 ]; then
        exit 1
    fi
    install_cloudflare

}
outputstr(){
    cf_domain=${cf_domain:-''}
    vmatls_link1="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"vmess-ws-tls-\", \"add\": \"$cf_domain\", \"port\": \"443\", \"id\": \"$sx_uuid\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$cf_domain\", \"path\": \"/$sx_uuid-vm?ed=2048\", \"tls\": \"tls\", \"sni\": \"$cf_domain\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)"
    echo  "$vmatls_link1"
}
uninstall() {
    info "正在卸载 sing-box..."
    sudo "$sxb_path" service -c "$sbxcfg_path" uninstall >/dev/null 2>&1 || true
    sudo rm -f "/usr/local/bin/sing-box"
    sudo rm -rf "/etc/sing-box"
    info "卸载完成"
}

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" 
echo "简化sing-box和cloudflare隧道部署脚本"
echo "当前版本：10.1 测试beta1版"
if [ "$1" = "uninstall" ]; then
    uninstall
    exit
fi

init
install
outputstr