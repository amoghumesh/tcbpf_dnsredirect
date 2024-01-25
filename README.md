# Using TC-BPF to redirect DNS traffic.

A set of two tcbpf programs that can be used to redirect dns traffic accross interfaces.
## Setup the build environment
```
sudo apt-get install -y build-essential clang llvm libelf-dev libpcap-dev \
gcc-multilib linux-tools-$(uname -r) linux-headers-$(uname -r) linux-tools-common \
linux-tools-generic libbpf-dev
```

## Change the parameters in dns_redirect.c as required
```
#define LOOPBACK 2130706433
#define DOCKERD_IP 2130706485
#define DOCKERD_PORT 41552
#define APP_CONTAINER_IP 3232266762
#define DNS_SERVER_IP 3232266753
#define DNS_SERVER_PORT 53
#define LOOPBACK_INTERFACE_INDEX 1
#define ETH0_INTERFACE_INDEX 2
```

## Load the TC programs
```
sudo ./load_bpf.sh
```

## To remove the bpf programs
```
sudo ./remove_bpf.sh
```