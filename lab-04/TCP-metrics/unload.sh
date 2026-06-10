#!/bin/bash

# Script para desanexar e limpar o programa BPF sockops
# Uso: ./bpf_sockops_cleanup.sh

set -e  # Sai imediatamente se qualquer comando falhar
set -u  # Trata variáveis não definidas como erro

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configurações
BPFTOOL="bpftool"
PROG_NAME="tcp_sockops_metrics"
BPF_PIN_PATH="/sys/fs/bpf/${PROG_NAME}"
CGROUP_PATH="/sys/fs/cgroup"
OBJECT_FILE="${PROG_NAME}.o"
HEADER_FILE="vmlinux.h"

# Função para imprimir mensagens
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Função para verificar se é root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Este script precisa ser executado como root (sudo)"
        exit 1
    fi
}

# Função para verificar se bpftool está disponível
check_bpftool() {
    if ! command -v $BPFTOOL &> /dev/null; then
        print_error "bpftool não encontrado"
        exit 1
    fi
}

# Função para verificar se o programa está carregado
is_program_loaded() {
    $BPFTOOL prog show pinned $BPF_PIN_PATH &> /dev/null
    return $?
}

# Função para verificar se está anexado ao cgroup
is_attached_to_cgroup() {
    $BPFTOOL cgroup show $CGROUP_PATH 2>/dev/null | grep -q "$BPF_PIN_PATH"
    return $?
}

# Função para desanexar do cgroup
detach_from_cgroup() {
    print_step "Desanexando do cgroup v2..."
    
    if is_attached_to_cgroup; then
        print_info "Programa está anexado ao cgroup $CGROUP_PATH"
        
        # Tentar desanexar com multi flag
        if $BPFTOOL cgroup detach $CGROUP_PATH sock_ops pinned $BPF_PIN_PATH multi 2>/dev/null; then
            print_info "✓ Desanexado com sucesso (multi)"
        else
            # Tentar sem a flag multi
            print_warning "Tentando desanexar sem a flag multi..."
            if $BPFTOOL cgroup detach $CGROUP_PATH sock_ops pinned $BPF_PIN_PATH 2>/dev/null; then
                print_info "✓ Desanexado com sucesso"
            else
                print_error "Falha ao desanexar do cgroup"
                return 1
            fi
        fi
        
        # Verificar se realmente foi desanexado
        sleep 1
        if ! is_attached_to_cgroup; then
            print_info "✓ Verificado: programa não está mais anexado ao cgroup"
        else
            print_warning "Aviso: programa ainda parece estar anexado"
        fi
    else
        print_info "Programa não está anexado ao cgroup. Nada a fazer."
    fi
}

# Função para descarregar o programa BPF
unload_bpf() {
    print_step "Descarregando programa BPF..."
    
    if is_program_loaded; then
        print_info "Programa encontrado em $BPF_PIN_PATH"
        
        # Mostrar informações antes de remover
        print_info "Informações do programa:"
        $BPFTOOL prog show pinned $BPF_PIN_PATH 2>/dev/null || true
        
        # Remover o pin do BPF
        if rm -f $BPF_PIN_PATH 2>/dev/null; then
            print_info "✓ Programa descarregado com sucesso"
        else
            print_error "Falha ao remover o pin do programa"
            return 1
        fi
        
        # Verificar se foi removido
        sleep 1
        if ! is_program_loaded; then
            print_info "✓ Verificado: programa não está mais carregado"
        else
            print_warning "Aviso: programa ainda parece estar carregado"
        fi
    else
        print_info "Programa não está carregado em $BPF_PIN_PATH. Nada a fazer."
    fi
}

# Função para remover arquivos temporários
cleanup_files() {
    print_step "Limpando arquivos temporários..."
    
    local files_to_remove=""
    
    # Verificar e marcar arquivos para remoção
    if [ -f "$OBJECT_FILE" ]; then
        files_to_remove="$files_to_remove $OBJECT_FILE"
        print_info "Arquivo objeto encontrado: $OBJECT_FILE"
    fi
    
    if [ -f "$HEADER_FILE" ]; then
        files_to_remove="$files_to_remove $HEADER_FILE"
        print_info "Arquivo header encontrado: $HEADER_FILE"
    fi
    
    # Remover arquivos se existirem
    if [ -n "$files_to_remove" ]; then
        rm -f $files_to_remove
        print_info "✓ Arquivos removidos:${files_to_remove}"
    else
        print_info "Nenhum arquivo temporário encontrado"
    fi
}

# Função para verificar se há outros programas BPF relacionados
check_other_programs() {
    print_step "Verificando outros programas BPF relacionados..."
    
    # Listar todos os programas BPF carregados com nome similar
    local similar_progs=$($BPFTOOL prog show 2>/dev/null | grep -i "$PROG_NAME" || true)
    
    if [ -n "$similar_progs" ]; then
        print_warning "Encontrados outros programas BPF com nome similar:"
        echo "$similar_progs"
    else
        print_info "Nenhum outro programa BPF relacionado encontrado"
    fi
}

# Função para mostrar status atual
show_current_status() {
    print_step "Status atual dos recursos BPF:"
    
    # Verificar cgroup attachments
    echo -e "\n${BLUE}Attachments do cgroup:${NC}"
    if $BPFTOOL cgroup show $CGROUP_PATH 2>/dev/null; then
        :
    else
        echo "  Nenhum attachment encontrado"
    fi
    
    # Verificar programas carregados
    echo -e "\n${BLUE}Programas BPF carregados relacionados:${NC}"
    $BPFTOOL prog show 2>/dev/null | grep -i "$PROG_NAME" || echo "  Nenhum programa encontrado"
    
    # Verificar pins
    echo -e "\n${BLUE}Pins em /sys/fs/bpf/:${NC}"
    ls -la /sys/fs/bpf/ 2>/dev/null | grep -i "$PROG_NAME" || echo "  Nenhum pin encontrado"
}

# Função para confirmar ação do usuário
confirm_cleanup() {
    if [ -t 0 ]; then  # Se estiver em terminal interativo
        echo -e "\n${YELLOW}Esta operação irá:${NC}"
        echo "  • Desanexar o programa do cgroup"
        echo "  • Descarregar o programa BPF"
        echo "  • Remover arquivos temporários ($OBJECT_FILE, $HEADER_FILE)"
        echo ""
        read -p "Deseja continuar? (s/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Ss]$ ]]; then
            print_info "Operação cancelada pelo usuário"
            exit 0
        fi
    fi
}

# Função de limpeza completa
full_cleanup() {
    print_info "Iniciando limpeza completa do programa BPF $PROG_NAME"
    echo "=========================================="
    
    # Desanexar do cgroup
    detach_from_cgroup
    
    # Descarregar o programa
    unload_bpf
    
    # Remover arquivos temporários
    cleanup_files
    
    # Verificar outros programas relacionados
    check_other_programs
    
    echo "=========================================="
    print_info "✓ Limpeza concluída com sucesso!"
}

# Função para mostrar ajuda
show_help() {
    cat << EOF
Uso: $0 [OPÇÕES]

Opções:
  -h, --help     Mostra esta mensagem de ajuda
  -f, --force    Força a limpeza sem confirmação
  -s, --status   Apenas mostra o status atual sem fazer alterações
  -k, --keep-files Mantém os arquivos temporários (.o e vmlinux.h)

Exemplos:
  sudo $0              # Executa limpeza completa com confirmação
  sudo $0 -f           # Força limpeza sem confirmação
  sudo $0 -s           # Apenas mostra o status atual
  sudo $0 -k           # Limpa mas mantém os arquivos .o e .h

EOF
}

# Função principal com argumentos
main() {
    local force=false
    local status_only=false
    local keep_files=false
    
    # Processar argumentos
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -f|--force)
                force=true
                shift
                ;;
            -s|--status)
                status_only=true
                shift
                ;;
            -k|--keep-files)
                keep_files=true
                shift
                ;;
            *)
                print_error "Opção desconhecida: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Verificar permissões
    check_root
    check_bpftool
    
    # Apenas mostrar status
    if [ "$status_only" = true ]; then
        show_current_status
        exit 0
    fi
    
    # Confirmar ação
    if [ "$force" = false ]; then
        confirm_cleanup
    fi
    
    # Sobrescrever cleanup_files se keep_files for true
    if [ "$keep_files" = true ]; then
        cleanup_files() {
            print_info "Mantendo arquivos temporários conforme solicitado"
        }
    fi
    
    # Executar limpeza
    full_cleanup
    
    # Mostrar status final
    echo ""
    show_current_status
}

# Executar função principal
main "$@"