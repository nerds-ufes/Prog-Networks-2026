## Ementa

Conceitos fundamentais de redes programáveis e softwarização de redes. Arquiteturas baseadas em SDN (Software Defined Networking) e NFV (Network Function Virtualization). Introdução à linguagem de programação P4 e à arquitetura PISA (Protocol Independent Switch Architecture). Estrutura e elementos de um programa em P4 e eBPF. Pipeline de processamento e controle de fluxo em dispositivos programáveis. Compilação, execução e depuração de programas P4. Ambientes de teste e simulação: mininet, bmv2, containerlab e testbeds P4Lab/RARE/freeRtr. Integração de controladores SDN (ex.: ONOS, Ryu) com data planes programáveis. 

Casos de uso: monitoramento ativo, segurança, slicing, 5G e redes definidas por intenção. Ferramentas de automação e uso de IA/LLMs para configuração, verificação e validação de redes programáveis. 

## Objetivos Específicos
O propósito da disciplina é explorar os princípios de redes programáveis com foco na programabilidade do plano de dados no kernel Linux por meio da linguagem eBPF (extended Berkeley Packet Filter) e do framework XDP (eXpress Data Path).
A disciplina terá forte componente prático, utilizando ambientes Linux, máquinas virtuais e ferramentas open-source. Ao final da disciplina, o estudante será capaz de:
Compreender a arquitetura do plano de dados no Linux e o papel do eBPF/XDP na aceleração do processamento de pacotes.


Projetar e implementar aplicações de rede em eBPF/XDP para roteamento, firewall, monitoramento, balanceamento de carga e mitigação de ataques.


Utilizar mapas BPF, tail calls e mecanismos de verificação para desenvolver aplicações seguras e eficientes.


Instrumentar telemetria de alto desempenho utilizando eBPF.


Avaliar desempenho (vazão, latência, uso de CPU, drops) em comparação com abordagens tradicionais.


Integrar modelos simples de ML/AI ao plano de dados.


Compreender o modelo P4 como abordagem alternativa de programabilidade (nível de switch ASIC) e comparar com eBPF/XDP (nível kernel/NIC).


Conteúdo Programático


### Parte 1 : Fundamentos de Redes Programáveis e Arquitetura eBPF/XDP (30 h)

Programabilidade em Redes de Computadores 
Controladores e o ambiente de prototipação Mininet
Network Programmability: The Road Ahead
Programmable Networking for a Distributed Edge 
In the age of deep network programmability
The three tales of correct network...
		b.	Arquitetura Linux Networking Stack
Caminho do pacote no kernel, 
Hooks do eBPF, 
Comparação entre Netfilter, TC e XDP

	c.	Introdução ao eBPF
Conceitos básicos
         Verificador e segurança
Mapas BPF
Ferramentas: clang/llvm, bpftool, libbpf


	d. 	XDP (eXpress Data Path)
			Processamento no driver/NIC
			Modos: XDP generic, native e offload
			Casos de uso de alto desempenho




### Parte 2 – Laboratório e Desenvolvimento de Aplicações de Rede com eBPF/XDP (30h)
		Laboratório
			Ambiente Linux com suporte a eBPF
			Primeiros programas XDP
			Medição de desempenho básica
			
Trabalho Experimental e Reprodutibilidade 
	Tópicos Sugeridos:  
	Processamento de Pacotes
		Parsing manual de headers
					Stateful packet processing
					Uso avançado de mapas
			Firewall em XDP
	Mitigação de DDoS
	Load balancing L4
	NAT simplificado
	Monitoramento e telemetria de fluxo
	Engenharia de tráfego baseada em métricas de congestionamento
	QoS e controle de filas via integração com TC
	Observabilidade e Telemetria
		Contadores e métricas
		Exportação para user-space
		Integração com ferramentas de monitoramento

Essa parte consolida o aprendizado técnico com formação científica, preparando o aluno para pesquisa aplicada e publicação.
