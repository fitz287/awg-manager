#!/usr/bin/env bash
# ==============================================================================
# AmneziaWG Multi-Node Master Panel — Деинсталляция
# ==============================================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Этот скрипт должен быть запущен с правами root (sudo).${NC}"
    exit 1
fi

echo -e "${RED}${BOLD}==============================================================${NC}"
echo -e "${RED}${BOLD}   Удаление AmneziaWG Multi-Node Master Panel                 ${NC}"
echo -e "${RED}${BOLD}==============================================================${NC}"
echo -e "${YELLOW}Это действие остановит службу панели, удалит файлы и базу данных.${NC}"

if [ -t 0 ]; then
    read -rp "Вы уверены, что хотите полностью удалить панель? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[yYдД]$ ]]; then
        echo -e "${GREEN}[i] Удаление отменено.${NC}"
        exit 0
    fi
fi

echo -e "\n${YELLOW}[1/3] Остановка и отключение службы awg-manager...${NC}"
systemctl stop awg-manager 2>/dev/null || true
systemctl disable awg-manager 2>/dev/null || true
rm -f /etc/systemd/system/awg-manager.service
systemctl daemon-reload

echo -e "\n${YELLOW}[2/3] Удаление каталогов панели (/opt/awg-manager)...${NC}"
rm -rf /opt/awg-manager

echo -e "\n${YELLOW}[3/3] Удаление консольной утилиты awg-manager...${NC}"
rm -f /usr/local/bin/awg-manager

echo -e "\n${GREEN}${BOLD}==============================================================${NC}"
echo -e "${GREEN}${BOLD}   AmneziaWG Panel успешно удалена с сервера!                 ${NC}"
echo -e "${GREEN}${BOLD}==============================================================${NC}"
