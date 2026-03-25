# 🛡️ XDP/eBPF Drop Lab with Containerlab

> A hands-on laboratory demonstrating **packet filtering at wire-speed** using **eBPF/XDP** in a virtualized network environment powered by **Containerlab**.

[![Containerlab](https://img.shields.io/badge/Containerlab-v0.50+-blue?logo=linux)](https://containerlab.dev)
[![Docker](https://img.shields.io/badge/Docker-required-blue?logo=docker)](https://www.docker.com)
[![eBPF](https://img.shields.io/badge/eBPF-XDP-orange)](https://ebpf.io)
[![License](https://img.shields.io/badge/license-GPL--2.0-green)](LICENSE)

---

## 📖 Overview

This lab showcases one powerful features of the Linux kernel: **XDP (eXpress Data Path)**. By attaching a small eBPF program directly to a network interface, we can drop packets **before they ever reach the network stack**, making filtering virtually free in terms of CPU overhead.

**What this lab demonstrates:**
- Compiling an eBPF C program to BPF bytecode using a Docker-based build environment.
- Deploying a 2-node virtual network with Containerlab.
- Loading an XDP program onto a network interface using `bpftool`.
- Blocking ICMP (ping) traffic at line rate.
- Reading packet drop counters from a **BPF Map** in real time.

---

## 🗺️ Topology

```
┌─────────────────────────────────────────┐
│               Host Machine              │
│                                         │
│  ┌──────────┐ eth1   eth1 ┌──────────┐  │
│  │  node-a  ├─────────────┤  node-b  │  │
│  │10.0.0.1  │             │10.0.0.2  │  │
│  └──────────┘             └──────────┘  │
│    (sender)             (XDP filter) 🛡️  │
└─────────────────────────────────────────┘
```

| Node   | IP Address   | Role                          |
|--------|-------------|-------------------------------|
| node-a | `10.0.0.1`  | Packet sender (ping origin)   |
| node-b | `10.0.0.2`  | XDP filter — drops ICMP packets |

---

## 🔧 Prerequisites

### 1. Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

> Log out and back in after adding your user to the `docker` group.

### 2. Install Containerlab

```bash
bash -c "$(curl -sL https://get.containerlab.dev)"
```

Verify the installation:

```bash
containerlab version
```

---

## 🐝 Getting the Lab

Clone the repository and navigate to the lab directory:

```bash
git clone https://github.com/your-user/ebpf-lab.git
cd ebpf-lab
```

> 📁 The key files are:
> - `lab-ebpf.clab.yml` — Containerlab topology definition
> - `xdp_drop.c` — the eBPF/XDP source code
> - `compile.sh` — Docker-based cross-compilation script

---

## 🐝 Step 1 — Compile the eBPF Program

The `compile.sh` script uses an **Ubuntu 22.04 Docker container as a build environment**, so you don't need to install any compiler tools on your host.

```bash
./compile.sh
```

<details>
<summary>What does compile.sh do?</summary>

It runs a temporary Docker container that:
1. Installs `clang`, `llvm`, `libbpf-dev`, and `gcc-multilib`.
2. Cross-compiles `xdp_drop.c` targeting the **BPF virtual machine** (`-target bpf`).
3. Outputs the BPF object file `xdp_drop.o` in the current directory.
4. Removes the build container automatically (`--rm`).

</details>

**Expected output:**
```
Success! xdp_drop.o created.🍻🍻🍻
```

---

## 🌐 Step 2 — Deploy the Topology

```bash
sudo containerlab deploy -t lab-ebpf.clab.yml --reconfigure
```

This will:
- Create two Linux containers (`node-a` and `node-b`) using the `nicolaka/netshoot` image.
- Configure IPs on their `eth1` interfaces.
- Mount `xdp_drop.o` into `node-b` at `/xdp_drop.o`.
- Create a direct virtual link between their `eth1` interfaces.

Verify the lab is running:

```bash
docker ps --filter "label=containerlab=ebpf-lab"
```

---

## ✅ Step 3 — Verify Baseline Connectivity

Before loading the XDP filter, confirm both nodes can ping each other:

```bash
docker exec clab-ebpf-lab-node-a ping -c 3 10.0.0.2
```

**Expected output:** `0% packet loss` ✅

---

## 🛡️ Step 4 — Activate the XDP Filter

### 4.1 Install bpftool on node-b

```bash
docker exec clab-ebpf-lab-node-b apk add bpftool
```

### 4.2 Load and pin the XDP program

```bash
# Remove any previous pin (avoids errors on re-runs)
docker exec clab-ebpf-lab-node-b rm -f /sys/fs/bpf/xdp_test

# Load and pin the program to the BPF filesystem
docker exec clab-ebpf-lab-node-b \
  bpftool prog load /xdp_drop.o /sys/fs/bpf/xdp_test type xdp

# Attach it to the eth1 interface
docker exec clab-ebpf-lab-node-b \
  ip link set dev eth1 xdpgeneric pinned /sys/fs/bpf/xdp_test
```

> **Why pin?** Pinning the program to `/sys/fs/bpf/` keeps the BPF map alive in memory, allowing you to read the drop counter even after the loading command exits.

---

## 🧪 Step 5 — Test & Verify

### 5.1 Confirm ICMP is blocked

```bash
docker exec clab-ebpf-lab-node-a ping -c 5 10.0.0.2
```

**Expected output:** `100% packet loss` 🚫

### 5.2 Read the drop counter from the BPF Map

```bash
docker exec clab-ebpf-lab-node-b bpftool map dump name packet_count_ma
```

**Expected output:**
```json
[{
    "key": 0,
    "value": 5
}]
```

> The counter increments atomically for each ICMP packet dropped — safe even across multiple CPU cores.

---

## 🔓 Step 6 — Deactivate the Filter

To restore normal ICMP traffic:

```bash
docker exec clab-ebpf-lab-node-b ip link set dev eth1 xdpgeneric off
```

Verify connectivity is restored:

```bash
docker exec clab-ebpf-lab-node-a ping -c 3 10.0.0.2
```

**Expected output:** `0% packet loss` ✅

---

## 🔬 Bonus — Performance Experiment: XDP vs iptables

One of the main advantages of XDP is processing packets **before** the kernel network stack. This experiment lets you compare drop performance against the traditional `iptables` approach.

**Flood node-b with UDP packets from node-a:**

```bash
docker exec clab-ebpf-lab-node-a \
  hping3 --flood --udp -p 80 10.0.0.2
```

Monitor CPU and packet drop rates with and without XDP to observe the difference in overhead.

---

## 🧹 Cleanup

Destroy the lab and remove all containers:

```bash
sudo containerlab destroy -t lab-ebpf.clab.yml
```

---

## 📂 Project Structure

```
ebpf-lab/
├── lab-ebpf.clab.yml        # Containerlab topology definition
├── xdp_drop.c               # eBPF/XDP source code (ICMP drop + counter)
├── xdp_drop.o               # Compiled BPF object file (generated)
├── compile.sh               # Docker-based eBPF compilation script
├── ativation-test.md        # Quick reference activation guide
└── clab-ebpf-lab/           # Runtime files generated by Containerlab
    ├── ansible-inventory.yml
    ├── nornir-simple-inventory.yml
    ├── authorized_keys
    └── topology-data.json
```

---

## 📚 References

- [eBPF Official Documentation](https://ebpf.io/what-is-ebpf/)
- [Containerlab Documentation](https://containerlab.dev/quickstart/)
- [XDP Tutorial (kernel.org)](https://github.com/xdp-project/xdp-tutorial)
- [libbpf GitHub](https://github.com/libbpf/libbpf)
- [nicolaka/netshoot — Network Troubleshooting Container](https://github.com/nicolaka/netshoot)
