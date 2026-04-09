#!/bin/bash

LAB="lab-04"
SESSION="basic"

echo "Encerrando sessão tmux..."

sudo docker exec clab-${LAB}-PC1 bash -c "bpftool struct_ops unregister name cubic"

tmux has-session -t $SESSION 2>/dev/null
if [ $? -eq 0 ]; then
    tmux kill-session -t $SESSION
    echo "Sessão tmux encerrada."
else
    echo "Sessão tmux não encontrada."
fi

echo "Destruindo laboratório Containerlab..."

sudo containerlab destroy -t topology-04.yml

echo "Removendo containers remanescentes..."

docker rm -f clab-${LAB}-PC1 2>/dev/null
docker rm -f clab-${LAB}-PC2 2>/dev/null
docker rm -f clab-${LAB}-PC3 2>/dev/null
docker rm -f clab-${LAB}-SW1 2>/dev/null
docker rm -f clab-${LAB}-SW2 2>/dev/null

echo "Removendo redes Docker não utilizadas..."

docker network prune -f

echo "Laboratório finalizado."

sudo containerlab destroy -t topology-04.yml
