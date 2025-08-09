#!/bin/bash

set -euo pipefail

BLUE="\033[34m"
GREEN="\033[32m"
RESET="\033[0m"


source "$HOME/.cargo/env"

echo -e "${BLUE}Test nvidia-smi${RESET}"
rstrace --color --cuda -- nvidia-smi
echo -e "${GREEN}test passed ✔️${RESET}" && sleep 0.5

rstrace --color --cuda -- nvidia-smi -L
echo -e "${GREEN}test passed ✔️${RESET}" && sleep 0.5

echo -e "${BLUE}Test torch${RESET}"
rstrace --color --cuda -- python3 -c "import torch"
echo -e "${GREEN}test passed ✔️${RESET}" && sleep 0.5

rstrace --color --cuda -- python3 -c "import torch; print(torch.cuda.get_device_name(0))"
echo -e "${GREEN}test passed ✔️${RESET}" && sleep 0.5

# Allocate 1GB of memory on the GPU
echo -e "${BLUE}Allocate 1GiB${RESET}"
rstrace --color --cuda-only -- python3 -c "import torch; tensor = torch.zeros(268435456, device='cuda')"
echo -e "${GREEN}test passed ✔️${RESET}" && sleep 0.5

echo -e "${BLUE}Allocate 1GiB in child process${RESET}"
rstrace --color --cuda-only -f -- python3 -c "import torch, multiprocessing
def create_tensor():
    tensor = torch.zeros(268435456, device='cuda')
p = multiprocessing.Process(target=create_tensor)
p.start()
p.join()"
echo -e "${GREEN}test passed ✔️${RESET}" && sleep 0.5
