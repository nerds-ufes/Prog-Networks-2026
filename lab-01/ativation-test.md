# eBPF Activation Test Guide

Este documento descreve como reproduzir o ambiente de testes de eBPF (ICMP Drop).

## 1. Preparação (Compilação)

Compile o código C (`xdp_drop.c`) para bytecode BPF (`xdp_drop.o`) usando o script fornecido.

```bash
# cd ~/redes/ebpf-lab # Se não estiver no diretório
./compile.sh
```

**Verificação**: Certifique-se de que o arquivo `xdp_drop.o` foi criado com sucesso.

## 2. Deploy da Topologia

Suba o laboratório com Containerlab.

```bash
sudo containerlab deploy -t lab-ebpf.clab.yml --reconfigure
```

Isso iniciará `node-a` e `node-b`. O arquivo `xdp_drop.o` será montado automaticamente dentro do `node-b` em `/xdp_drop.o`.

## 3. Preparação do Ambiente (Node-B)

Instale o `bpftool` no `node-b` para poder inspecionar os mapas BPF.

```bash
sudo docker exec clab-ebpf-lab-node-b apk add bpftool
```


## 4. Ativação do Programa XDP

Carregue o programa XDP na interface de rede do `node-b`. Utilizaremos o `bpftool` para carregar e piná-lo, garantindo persistência dos mapas.

```bash
# Remover pin anterior (se existir) para evitar erros
sudo docker exec clab-ebpf-lab-node-b rm -f /sys/fs/bpf/xdp_test

# Carregar e pinar o programa
sudo docker exec clab-ebpf-lab-node-b bpftool prog load /xdp_drop.o /sys/fs/bpf/xdp_test type xdp

# Anexar à interface
sudo docker exec clab-ebpf-lab-node-b ip link set dev eth1 xdpgeneric pinned /sys/fs/bpf/xdp_test
```

## 5. Teste e Verificação

### Teste de Conectividade (Ping)
Realize um teste de ping a partir do `node-a` em direção ao `node-b`.

```bash
sudo docker exec clab-ebpf-lab-node-a ping -c 5 10.0.0.2
```

**Resultado Esperado**: 100% packet loss.

### Verificação do Contador (Map)
Verifique se o contador de pacotes descartados foi incrementado.

```bash
sudo docker exec clab-ebpf-lab-node-b bpftool map dump name packet_count_ma
```
*(Nota: O nome do mapa pode estar truncado como `packet_count_ma` ou você pode usar o ID listado por `bpftool map show`)*

**Resultado Esperado**:
```json
[{
        "key": 0,
        "value": 5
    }
]
```


## 6. Desativação (Restaurar Ping)

Para remover o programa XDP e permitir que o tráfego ICMP flua novamente:

```bash
sudo docker exec clab-ebpf-lab-node-b ip link set dev eth1 xdpgeneric off
```

**Verificação**:
Execute o ping novamente. Ele deve funcionar (0% packet loss).

## 7. Limpeza (Opcional)

Para destruir o laboratório:

```bash
sudo containerlab destroy -t lab-ebpf.clab.yml
```


# Teste de performance XDP vs iptables

### Análise de Performance: Comparar o descarte via XDP versus o descarte tradicional via stack do kernel (iptables/nftables).


# Inunda o node-b com pacotes UDP (mais rápido que ICMP)
sudo docker exec clab-ebpf-lab-node-a hping3 --flood --udp -p 80 10.0.0.2

