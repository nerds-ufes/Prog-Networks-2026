# start.sh — Orquestrador do lab-04

Script de inicialização completa do laboratório `lab-04`. Automatiza desde a destruição de instâncias anteriores até o disparo de fluxos TCP simultâneos entre os hosts, com suporte opcional a sessões `tmux` para acesso interativo aos containers.

---

## Sumário

1. [Uso](#1-uso)
2. [Pré-requisitos](#2-pré-requisitos)
3. [Estrutura de diretórios esperada](#3-estrutura-de-diretórios-esperada)
4. [Etapas de execução](#4-etapas-de-execução)
   - [1. Destruição do lab anterior](#etapa-1--destruição-do-lab-anterior)
   - [2. Build da imagem Docker](#etapa-2--build-da-imagem-docker)
   - [3. Deploy da topologia](#etapa-3--deploy-da-topologia)
   - [4. Health check dos containers](#etapa-4--health-check-dos-containers)
   - [5. Configuração de ARP estático](#etapa-5--configuração-de-arp-estático)
   - [6. Cópia de artefatos para PC1](#etapa-6--cópia-de-artefatos-para-pc1)
   - [7. Fluxos TCP com iperf3](#etapa-7--fluxos-tcp-com-iperf3)
   - [8. Sessão tmux (opcional)](#etapa-8--sessão-tmux-opcional)
5. [Variáveis de configuração](#5-variáveis-de-configuração)
6. [Saída esperada](#6-saída-esperada)
7. [Carregamento manual do bpf_cubic](#7-carregamento-manual-do-bpf_cubic)
8. [Notas e observações](#8-notas-e-observações)

---

## 1. Uso

```bash
# Execução padrão (sem tmux)
./start.sh

# Com tmux — abre sessão para todos os nós padrão (PC1, PC2, SW1, SW2)
./start.sh --tmux

# Com tmux — abre sessão apenas para nós específicos
./start.sh --tmux PC1 PC2
./start.sh --tmux PC1 SW1 SW2
```

Torne o script executável antes do primeiro uso:

```bash
chmod +x start.sh
```

> ⚠️ O script requer `sudo`. Certifique-se de que seu usuário tem permissões para executar `docker` e `containerlab` com privilégios.

---

## 2. Pré-requisitos

| Ferramenta      | Finalidade                                      |
|-----------------|-------------------------------------------------|
| `containerlab`  | Deploy e destroy da topologia                   |
| `docker`        | Build da imagem e execução dos containers       |
| `tmux`          | Sessões interativas (apenas com `--tmux`)       |
| `iperf3`        | Disponível **dentro** da imagem `ebpf-host`     |

Verifique as dependências:

```bash
containerlab version
docker --version
tmux -V        # apenas se usar --tmux
```

---

## 3. Estrutura de diretórios esperada

O script pressupõe a seguinte organização no diretório de trabalho:

```
.
├── start.sh               # Este script
├── topology-04.yml        # Definição da topologia containerlab
├── ebpf-host/             # Contexto de build da imagem Docker
│   └── Dockerfile
├── bpf_cubic/             # Programa eBPF (copiado para PC1)
│   └── bpf_cubic.o
└── TCP-metrics/           # Scripts de coleta de métricas (copiado para PC1)
    └── load.sh
```

> ℹ️ Os diretórios `bpf_cubic/` e `TCP-metrics/` são **opcionais**. O script verifica a existência de cada um antes de tentar copiá-los e emite um aviso caso não sejam encontrados, sem interromper a execução.

---

## 4. Etapas de execução

### Etapa 1 — Destruição do lab anterior

```bash
sudo containerlab destroy -t topology-04.yml --cleanup
```

Remove containers, interfaces virtuais e redes criadas por execuções anteriores. Erros são ignorados (`|| true`), permitindo a execução mesmo que nenhum lab esteja ativo.

---

### Etapa 2 — Build da imagem Docker

```bash
cd ebpf-host/
sudo docker build -t ebpf-host:latest .
```

Reconstrói a imagem `ebpf-host:latest` a partir do `Dockerfile` local. O build é executado a cada inicialização para garantir que alterações no Dockerfile sejam aplicadas.

---

### Etapa 3 — Deploy da topologia

```bash
sudo containerlab deploy -t topology-04.yml
```

Cria todos os containers e interconexões definidos em `topology-04.yml`. Após o deploy, aguarda 3 segundos para que os containers inicializem completamente.

---

### Etapa 4 — Health check dos containers

Verifica se os três hosts estão em execução antes de prosseguir:

```bash
for container in clab-lab-04-PC1 clab-lab-04-PC2 clab-lab-04-PC3; do
    docker ps | grep -q $container || exit 1
done
```

Se qualquer container não for encontrado, o script **aborta imediatamente** (`set -e`).

---

### Etapa 5 — Configuração de ARP estático

Popula as tabelas ARP de todos os hosts com entradas estáticas, evitando broadcasts ARP e garantindo resolução imediata:

| Host | Vizinho | IP          | MAC                 |
|------|---------|-------------|---------------------|
| PC1  | PC2     | `10.0.0.2`  | `00:00:00:00:02:02` |
| PC1  | PC3     | `10.0.0.3`  | `00:00:00:00:03:03` |
| PC2  | PC1     | `10.0.0.1`  | `00:00:00:00:01:01` |
| PC2  | PC3     | `10.0.0.3`  | `00:00:00:00:03:03` |
| PC3  | PC1     | `10.0.0.1`  | `00:00:00:00:01:01` |
| PC3  | PC2     | `10.0.0.2`  | `00:00:00:00:02:02` |

> ℹ️ Os MACs são fixos e definidos no `topology-04.yml`, o que torna essa configuração determinística e reprodutível entre execuções.

---

### Etapa 6 — Cópia de artefatos para PC1

Dois diretórios são copiados para `/root/` no container PC1:

#### `TCP-metrics/`

```bash
docker cp TCP-metrics/ clab-lab-04-PC1:/root/
docker exec clab-lab-04-PC1 chmod +x /root/TCP-metrics/load.sh
```

Scripts de coleta de métricas TCP. O `load.sh` tem permissão de execução garantida automaticamente.

#### `bpf_cubic/`

```bash
docker cp bpf_cubic/ clab-lab-04-PC1:/root/
```

Objeto ELF compilado do programa eBPF CUBIC. O registro no kernel é feito **manualmente** após o boot (ver [seção 7](#7-carregamento-manual-do-bpf_cubic)).

---

### Etapa 7 — Fluxos TCP com iperf3

Inicia um servidor `iperf3` em PC2 e dois clientes simultâneos em PC1 e PC3:

```bash
# Servidor (PC2) — em background
docker exec -d clab-lab-04-PC2 iperf3 -s

# Cliente PC1 — com delay inicial de 2s, duração 100s, saída em JSON
docker exec -d clab-lab-04-PC1 bash -c "sleep 2; iperf3 -c 10.0.0.2 -t 100 --json >> iperf_pc1.txt"

# Cliente PC3 — mesma configuração
docker exec -d clab-lab-04-PC3 bash -c "sleep 2; iperf3 -c 10.0.0.2 -t 100 --json >> iperf_pc3.txt"
```

| Parâmetro    | Valor                          |
|--------------|--------------------------------|
| Destino      | `10.0.0.2` (PC2)              |
| Duração      | 100 segundos                   |
| Formato      | JSON                           |
| Saída PC1    | `iperf_pc1.txt` (no container) |
| Saída PC3    | `iperf_pc3.txt` (no container) |

Para recuperar os resultados após o teste:

```bash
docker cp clab-lab-04-PC1:/root/iperf_pc1.txt ./iperf_pc1.txt
docker cp clab-lab-04-PC3:/root/iperf_pc3.txt ./iperf_pc3.txt
```

---

### Etapa 8 — Sessão tmux (opcional)

Ativada com o flag `--tmux`. Cria uma sessão chamada `basic` com um painel por nó, em layout `tiled`:

```bash
./start.sh --tmux              # Nós padrão: PC1, PC2, SW1, SW2
./start.sh --tmux PC1 SW1      # Apenas PC1 e SW1
```

**Comportamento:**

- Qualquer sessão `basic` existente é destruída antes de criar a nova.
- Cada painel executa `docker exec -it <container> bash` automaticamente.
- O layout `tiled` distribui os painéis igualmente na tela.
- Ao final, o script chama `tmux attach` e passa o controle para o terminal.

**Atalhos úteis dentro do tmux:**

| Ação                        | Atalho           |
|-----------------------------|------------------|
| Navegar entre painéis       | `Ctrl+b` + setas |
| Desanexar sessão            | `Ctrl+b` + `d`   |
| Reanexar sessão             | `tmux attach -t basic` |
| Fechar painel               | `exit`           |

---

## 5. Variáveis de configuração

Definidas no topo do script:

| Variável    | Valor padrão      | Descrição                              |
|-------------|-------------------|----------------------------------------|
| `LAB`       | `lab-04`          | Nome do laboratório containerlab       |
| `TOPOLOGY`  | `topology-04.yml` | Arquivo de topologia                   |
| `USE_TMUX`  | `false`           | Ativado via flag `--tmux`              |
| `TMUX_NODES`| `()`              | Lista de nós para abrir no tmux        |

---

## 6. Saída esperada

Ao final de uma execução bem-sucedida sem `--tmux`:

```
=== Destruindo laboratório anterior ===
=== Construindo imagem ebpf-host ===
=== Implantando topologia ===
=== Verificando containers ===
✅ clab-lab-04-PC1 está rodando
✅ clab-lab-04-PC2 está rodando
✅ clab-lab-04-PC3 está rodando
=== Configurando ARP estático ===
=== Copiando TCP-metrics para PC1 ===
✅ TCP-metrics copiado
=== Copiando bpf_cubic para PC1 ===
✅ bpf_cubic copiado
=== Configuração concluída ===

Topologia: PC1 --- SW1 --- SW2 --- PC2
           PC3 ---/
IP PC1: 10.0.0.1
IP PC2: 10.0.0.2
IP PC3: 10.0.0.3

=== Iniciando servidor iperf3 (PC2) ===
=== Iniciando fluxos TCP simultâneos ===
```

---

## 7. Carregamento manual do `bpf_cubic`

O registro do programa eBPF e a ativação do algoritmo TCP estão **comentados** no script. Após o boot do lab, execute manualmente em PC1:

```bash
docker exec -it clab-lab-04-PC1 bash
```

Dentro do container:

```bash
# Registrar o struct_ops no kernel
cd /root/bpf_cubic
bpftool struct_ops register bpf_cubic.o

# Confirmar registro
bpftool struct_ops show

# Ativar como algoritmo padrão
sysctl -w net.ipv4.tcp_congestion_control=bpf_cubic

# Confirmar
sysctl net.ipv4.tcp_congestion_control
```

> Para detalhes completos sobre compilação, carregamento e configuração dinâmica de parâmetros, consulte o [README do bpf_cubic](../bpf_cubic/README.md).

---

## 8. Notas e observações

- **`set -e`** — o script aborta imediatamente se qualquer comando retornar erro não tratado. Os comandos que podem falhar intencionalmente usam `|| true` para suprimir o erro.

- **Build a cada execução** — a imagem `ebpf-host:latest` é reconstruída sempre. Para acelerar reexecuções sem alterações no Dockerfile, comente o bloco de build ou use `docker build --cache-from`.

- **Saída do iperf3 dentro do container** — os arquivos `iperf_pc1.txt` e `iperf_pc3.txt` são gravados no sistema de arquivos do container em `/root/`. Use `docker cp` para extraí-los após o teste.

- **Clientes iperf3 em background** — os clientes são iniciados com `docker exec -d` (detached). O progresso não é exibido no terminal; use `docker logs` ou acesse o container via tmux para acompanhar.

- **PC3 sem ARP para PC2→PC3** — a tabela ARP de PC2 não possui entrada para PC3. Caso seja necessário tráfego direto entre PC2 e PC3, adicione manualmente:

  ```bash
  docker exec clab-lab-04-PC2 ip neigh add 10.0.0.3 lladdr 00:00:00:00:03:03 dev eth1
  ```
