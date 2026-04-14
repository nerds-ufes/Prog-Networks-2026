#!/bin/bash

# ./start.sh                # sem tmux
# ./start.sh --tmux         # tmux padrão (todos)
# ./start.sh --tmux PC1 PC2 # apenas alguns nós


set -e  # Para o script se algum comando falhar

LAB="lab-04"
TOPOLOGY="topology-04.yml"

# =========================
# Argumentos
# =========================
USE_TMUX=false
TMUX_NODES=()

if [[ "$1" == "--tmux" ]]; then
    USE_TMUX=true
    shift
    TMUX_NODES=("$@")
fi

echo "=== Destruindo laboratório anterior ==="
sudo containerlab destroy -t $TOPOLOGY --cleanup 2>/dev/null || true

echo ""
echo "=== Construindo imagem ebpf-host ==="
cd ebpf-host/
sudo docker build -t ebpf-host:latest .
cd ..

echo ""
echo "=== Implantando topologia ==="
sudo containerlab deploy -t $TOPOLOGY

# Aguardar containers iniciarem
sleep 3

# Verificar se containers existem antes de continuar
echo ""
echo "=== Verificando containers ==="
for container in clab-${LAB}-PC1 clab-${LAB}-PC2 clab-${LAB}-PC3; do
    if sudo docker ps | grep -q $container; then
        echo "✅ $container está rodando"
    else
        echo "❌ $container não encontrado. Abortando."
        exit 1
    fi
done

echo ""
echo "=== Configurando ARP estático ==="
sudo docker exec clab-${LAB}-PC1 ip neigh add 10.0.0.2 lladdr 00:00:00:00:02:02 dev eth1 2>/dev/null || true
sudo docker exec clab-${LAB}-PC1 ip neigh add 10.0.0.3 lladdr 00:00:00:00:03:03 dev eth1 2>/dev/null || true
sudo docker exec clab-${LAB}-PC2 ip neigh add 10.0.0.1 lladdr 00:00:00:00:01:01 dev eth1 2>/dev/null || true
sudo docker exec clab-${LAB}-PC2 ip neigh add 10.0.0.3 lladdr 00:00:00:00:03:03 dev eth1 2>/dev/null || true

sudo docker exec clab-${LAB}-PC3 ip neigh add 10.0.0.1 lladdr 00:00:00:00:01:01 dev eth1 2>/dev/null || true
sudo docker exec clab-${LAB}-PC3 ip neigh add 10.0.0.2 lladdr 00:00:00:00:02:02 dev eth1 2>/dev/null || true

echo ""
echo "=== Copiando TCP-metrics para PC1 ==="
# Verificar se diretório existe
if [ -d "TCP-metrics" ]; then
    sudo docker cp TCP-metrics/ clab-${LAB}-PC1:/root/ 2>/dev/null || true
    sudo docker exec clab-${LAB}-PC1 chmod +x /root/TCP-metrics/load.sh 2>/dev/null || true
    echo "✅ TCP-metrics copiado"
else
    echo "⚠️ Diretório TCP-metrics não encontrado. Pulando."
fi

echo ""
echo "=== Copiando bpf_cubic para PC1 ==="
# Verificar se diretório existe
if [ -d "bpf_cubic" ]; then
    sudo docker cp bpf_cubic/ clab-${LAB}-PC1:/root/ 2>/dev/null || true
    echo "✅ bpf_cubic copiado"
else
    echo "⚠️ Diretório bpf_cubic não encontrado. Pulando."
fi

#sudo docker exec clab-${LAB}-PC1 bash -c "cd /root/bpf_cubic && bpftool struct_ops register bpf_cubic.o"
#echo "=== Ativando algoritmo TCP ==="
#sudo docker exec clab-${LAB}-PC1 sysctl -w net.ipv4.tcp_congestion_control=bpf_cubic

echo ""
echo "=== Configuração concluída ==="
echo ""
echo "Topologia: PC1 --- SW1 --- SW2 --- PC2"
echo "           PC3 ---/		    "
echo "IP PC1: 10.0.0.1"
echo "IP PC2: 10.0.0.2"
echo "IP PC3: 10.0.0.3"
echo ""

echo ""
echo "=== Iniciando servidor iperf3 (PC2) ==="
sudo docker exec -d clab-${LAB}-PC2 iperf3 -s --port 5201
sudo docker exec -d clab-${LAB}-PC2 iperf3 -s --port 5202

# Pequeno delay para garantir que o servidor subiu
sleep 2

KERNEL=$(uname -r)
sudo docker exec clab-${LAB}-PC1 apt update
sudo docker exec clab-${LAB}-PC1 apt install -y linux-tools-$KERNEL linux-cloud-tools-$KERNEL
#sudo docker exec clab-${LAB}-PC3 apt update
#sudo docker exec clab-${LAB}-PC3 apt install -y linux-tools-$KERNEL linux-cloud-tools-$KERNEL

echo ""
echo "=== Iniciando fluxos TCP simultâneos ==="

# Cliente PC1
# sudo docker exec -d clab-${LAB}-PC1 bash -c "sleep 2; iperf3 -c 10.0.0.2 -t 100 --json >> iperf_pc1.txt"

# Cliente PC3
# sudo docker exec -d clab-${LAB}-PC3 bash -c "sleep 2; iperf3 -c 10.0.0.2 -t 100 --json >> iperf_pc3.txt"



# =========================
# TMUX (opcional)
# =========================
if [ "$USE_TMUX" = true ]; then

    SESSION="basic"

    # Se nenhum nó foi especificado → usar padrão
    if [ ${#TMUX_NODES[@]} -eq 0 ]; then
        TMUX_NODES=("PC1" "PC2" "SW1" "SW2")
    fi

    tmux kill-session -t $SESSION 2>/dev/null || true

    echo "=== Criando sessão tmux ==="
    tmux new-session -d -s $SESSION

    pane_index=0

    for node in "${TMUX_NODES[@]}"; do
        container="clab-${LAB}-${node}"

        if [ $pane_index -eq 0 ]; then
            tmux send-keys -t $SESSION "docker exec -it $container bash" C-m
        else
            tmux split-window -t $SESSION
            tmux send-keys -t $SESSION "docker exec -it $container bash" C-m
        fi

        pane_index=$((pane_index + 1))
    done

    tmux select-layout tiled

    echo "=== Abrindo tmux ==="
    tmux attach -t $SESSION

fi
