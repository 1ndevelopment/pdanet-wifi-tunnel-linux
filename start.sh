#!/bin/bash

IP="192.168.49.1"
PORT="8000"
PROXY_SERVER="$IP:$PORT"

logo() { echo "
            __              __      __
   ___  ___/ /__ ____  ___ / /_  __/ /_
  / _ \/ _  / _ \`/ _ \/ -_) __/ /_  __/
 / .__/\_,_/\_,_/_//_/\__/\__/   /_/
/_/      _ ____         __      __  __
 _    __(_) _(_) ____  / /____ / /_/ /  ___ ____
| |/|/ / / _/ / /___/ / __/ -_) __/ _ \/ -_) __/
|__,__/_/_//_/        \__/\__/\__/_//_/\__/_/ ~ v0.3
                          full system-proxy

\\\ Hotspot IP: ${IP}
\\\ Proxy Server Port: ${PORT}"
}

rootcheck() { [[ "$(id -u)" -ne 0 ]] && { echo -e "\n* run as superuser."; exit 1; } ; }

WORKSPACE=$(dirname "$(realpath "$0")")
SCRIPT_NAME=$(basename "$0")

silent() { "$@" > /dev/null 2>&1; }

set_proxy() {
  # set proxy for terminal session
  export http_proxy="https://$PROXY_SERVER" https_proxy="$http_proxy" ftp_proxy="$http_proxy" no_proxy="localhost,127.0.0.1,.localhost"
  # set http proxy for git
  git config --global http.proxy http://$PROXY_SERVER ; git config --global https.proxy http://$PROXY_SERVER
  # set http proxy for wget
  echo -e "http-proxy=http://$PROXY_SERVER/\nhttps-proxy=http://$PROXY_SERVER/\nftp-proxy=http://$PROXY_SERVER/\nuse_proxy=on\n" | sudo tee /etc/wgetrc > /dev/null 2>&1
  echo -e "!!! NOT WORKING YET # * Proxy applied to wget\n"
  # set http proxy for docker
  echo -e "[Service]\nEnvironment=\"HTTP_PROXY=http://$PROXY_SERVER/\"\nEnvironment=\"HTTPS_PROXY=http://$PROXY_SERVER/\"\n" | sudo tee /etc/systemd/system/docker.service.d/http-proxy.conf > /dev/null 2>&1
  echo -e "* Proxy applied to docker daemon\n"
  systemctl daemon-reload && systemctl restart docker
}

set_pkgman_proxy() {
if command -v apt > /dev/null 2>&1; then
  # set http proxy for apt and apt-get
  touch /etc/apt/apt.conf.d/proxy.conf
  echo "Acquire{HTTP::proxy \"http://$PROXY_SERVER/\";HTTPS::proxy \"http://$PROXY_SERVER/\";}" | sudo tee /etc/apt/apt.conf.d/proxy.conf > /dev/null 2>&1
  echo -e "* Apt is now using the proxy\n"

elif command -v pacman > /dev/null 2>&1; then
  echo "* Pacman is now using the proxy"

elif command -v nix > /dev/null 2>&1; then
  echo -e "networking.proxy.default = \"http://$PROXY_SERVER/\"\nnetworking.proxy.noProxy = \"127.0.0.1,localhost\"" | sudo tee /etc/nix/nix.conf
  echo "* Nix is now using the proxy"

else
  echo "* Package manager not detected."

fi
}

exec_tunnel() {
  # Tunnel interface setup
  ip tuntap add mode tun dev tun0 > /dev/null 2>&1
  ip addr add 192.168.1.1/24 dev tun0 > /dev/null 2>&1
  ip link set dev tun0 up > /dev/null 2>&1
  ip route del default > /dev/null 2>&1
  ip route add default via 192.168.1.1 dev tun0 metric 1 > /dev/null 2>&1
  ip route add default via $IP dev wlan0 metric 10 > /dev/null 2>&1
  # Disable rp_filter to receive packets from other interfaces
  sysctl -w net.ipv4.conf.all.rp_filter=0 > /dev/null 2>&1
  # Create a configuration file for HevSocks5Tunnel
cat << EOF > $WORKSPACE/config.yml
tunnel:
  name: tun0
  mtu: 8500
  ipv4: 192.168.1.1
socks5:
  address: $IP
  port: $PORT
  udp: tcp
misc:
  log-file: $WORKSPACE/logs/.log
  log-level: info
EOF
  # Run HevSocks5Tunnel
  $WORKSPACE/hev-socks5-tunnel-linux-$ARCH config.yml > /dev/null 2>&1 &
  echo -e "!!! Socks5 tunnel initiated via 192.168.1.1 (tun0) !!!\n\n" && sleep 1
  tail -f $WORKSPACE/logs/.log | grep -E 'handshake|udp|tcp' | awk '{print $1,$2,$5,$7,$8,$9}'
}

cleanup() {
  chmod 777 $WORKSPACE/logs/*.log
  echo -e "\n\ncleaning up..."
  silent kill -9 $(sudo pgrep -f hev-socks5-tunnel-linux-x86_64)
  # unset proxy variables
  unset {http,https,ftp,no}_proxy
  # unset proxy for git
  git config --global --unset http.proxy ; git config --global --unset https.proxy
  # kill tunnel binary
  rm -fr $WORKSPACE/config.yml /etc/apt/apt.conf.d/proxy.conf /etc/wgetrc /etc/systemd/system/docker.service.d/http-proxy.conf
  systemctl daemon-reload ; systemctl restart docker
  # output logs
  silent mv $WORKSPACE/logs/.log $WORKSPACE/logs/socks5-tun_$PROXY_SERVER_$(date +'%Y-%m-%d.%T').log
  echo -e "\nFull tunnel log saved to: $WORKSPACE/logs/socks5-tun_$PROXY_SERVER_$(date +'%Y-%m-%d.%T').log" || rm -rf $WORKSPACE/logs/*.log
  exit 0
}
trap cleanup SIGINT

init() {
  if [ -f "$WORKSPACE/hev-socks5-tunnel-linux-$ARCH" ]; then
    echo -e "* Hev Socks5 Tunnel binary found\n"
    set_pkgman_proxy ; set_proxy ;
    echo -e "* Proxy is set via $PROXY_SERVER (wlan0)\n"
    echo -e "- press enter to begin socks5 tunnel -\n"; read input
    exec_tunnel
  else
    URL="https://github.com/heiher/hev-socks5-tunnel/releases/download/2.7.5/hev-socks5-tunnel-linux-$ARCH"
    echo -e "! Hev Socks5 Tunnel binary not found !\n\nFetching latest version...\n"
    wget -q --show-progress -e use_proxy=yes -e https_proxy=http://$PROXY_SERVER -P $WORKSPACE/ $URL ; echo ""
    chmod +x $WORKSPACE/hev-socks5-tunnel-linux-$ARCH ; init
  fi
}

detect_arch() {
  logo ; rootcheck
  export ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64) echo -e "\n* 64-bit architecture detected"; init;;
    i686|i386) echo -e "\n* 32-bit architecture detected"; init;;
    arm64|aarch64) echo -e "\n* Arm64 architecture detected"; init;;
    *) echo -e "\nUnknown architecture: $ARCH"; exit 1;;
  esac
}
detect_arch
