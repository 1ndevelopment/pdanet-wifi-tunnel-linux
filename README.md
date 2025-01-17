# pdanet-wifi-tunnel-linux

![Screenshot](https://files.1ndev.com/api/public/dl/WSYIR1n4/images/pdanet-wifi-tether-screenshot.png)

# Features

!! Achieves 200mbps down && 15mbps up on 5g networks !!

+ Detects CPU architecture
+ Incorporated superuser root check
+ Fetches a more efficient tun2socks fork ([hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel))
+ Can route packets via UDP & TCP
+ Grouped commands into their respective functions
+ No hard coded paths
+ Detects package managers 
+ Currently only sets proxy for apt/pacman/git/wget
+ Cleans up upon exit
++ various other additions

++ Tested on x86_64 Debian & Arch Linux with a paid version of pdanet+ running on Android 14.

# How to use

Simply run script as superuser:

`git clone https://git.1ndev.com/1ndevelopment/pdanet-wifi-tunnel-linux`

`cd pdanet-wifi-tunnel-linux`

`chmod +x start.sh`

`sudo ./start.sh`

# To-do

* Choose specific tun2socks binary fork
* Detect other package managers (dnf,nix,etc)
* Implement non-interactive state
* Add some flags
* Auto reconnect network interface in case of disconnect
