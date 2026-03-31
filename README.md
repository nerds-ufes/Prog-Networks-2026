# 📡 Redes Programáveis (PINF-107)

**Universidade Federal do Espírito Santo (UFES)**  
**Programa de Pós-Graduação em Informática**  
📍 Campus Goiabeiras  
📅 Período: 2026/01  
🎓 Nível: Mestrado em Informática / Doutorado em Ciência da Computação  
👨‍🏫 Docente: Magnos Martinello  

---

## 📖 Sobre a Disciplina

A disciplina **Redes Programáveis** aborda os fundamentos e práticas da programabilidade de redes modernas, com foco em:

- Softwarização de redes (SDN/NFV)
- Programação do plano de dados (P4 e eBPF)
- Arquiteturas modernas (PISA)
- Integração com controladores SDN
- Aplicações avançadas (5G, slicing, segurança, observabilidade)

A proposta combina **fundamentação teórica sólida com forte abordagem prática**, explorando ambientes reais e ferramentas open-source.

---

## 🎯 Objetivos

Ao final da disciplina, o aluno será capaz de:

- Compreender o funcionamento do plano de dados no Linux
- Desenvolver aplicações com eBPF/XDP
- Projetar soluções de rede como:
  - Roteamento
  - Firewall
  - Load balancing
  - Mitigação de ataques (ex: DDoS)
- Utilizar:
  - Mapas BPF
  - Tail calls
  - Verificação de segurança
- Implementar telemetria de alto desempenho
- Avaliar desempenho (latência, vazão, CPU, perdas)
- Integrar conceitos de IA/ML em redes
- Comparar abordagens:
  - eBPF/XDP (kernel/NIC)
  - P4 (switch/ASIC)

---

## 🧠 Conteúdo Programático

### 📌 Parte 1 – Fundamentos (30h)

#### 🔹 Programabilidade de Redes
- SDN e ambientes como Mininet
- Tendências em redes programáveis
- Edge computing e redes distribuídas

#### 🔹 Linux Networking Stack
- Caminho do pacote no kernel
- Hooks do eBPF
- Comparação: Netfilter vs TC vs XDP

#### 🔹 eBPF
- Conceitos fundamentais
- Verificador e segurança
- Mapas BPF
- Ferramentas:
  - `clang/llvm`
  - `bpftool`
  - `libbpf`

#### 🔹 XDP (eXpress Data Path)
- Processamento no driver/NIC
- Modos:
  - Generic
  - Native
  - Offload
- Casos de uso de alto desempenho

---

### 🧪 Parte 2 – Laboratório (30h)

#### 🔬 Ambiente
- Linux com suporte a eBPF
- Desenvolvimento de programas XDP
- Medições de desempenho

#### ⚙️ Projetos e Aplicações

- Processamento de pacotes (parsing manual)
- Stateful packet processing
- Uso avançado de mapas

Aplicações práticas:

- 🔥 Firewall em XDP
- 🛡️ Mitigação de DDoS
- ⚖️ Load balancing L4
- 🌐 NAT simplificado
- 📊 Monitoramento de fluxo
- 📡 Engenharia de tráfego
- 🎛️ QoS + integração com TC
- 👁️ Observabilidade e telemetria

---

## 🔬 Metodologia

- Aulas presenciais
- Laboratórios práticos
- Desenvolvimento incremental de aplicações
- Uso de ferramentas open-source
- Discussão de artigos científicos

### 📌 Projeto em Grupo

Cada grupo deverá:

- Selecionar um artigo recente
- Reproduzir experimentos
- Medir métricas:
  - Vazão
  - Latência
  - CPU
  - Perdas
- Produzir relatório técnico contendo:
  - Ambiente experimental
  - Resultados
  - Discussão crítica

---

## 📊 Avaliação

| Componente | Descrição | Peso |
|----------|--------|------|
| 🧪 Trabalho (T) | Implementação em eBPF/XDP + relatório | 70% |
| 📄 Artigo (A) | Apresentação e análise crítica | 30% |

### 📈 Cálculo

```text
MP = 0.7T + 0.3A
