#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Пожалуйста, запустите от имени root${NC}"
  exit 1
fi

echo -e "${YELLOW}Остановка и удаление службы awg-manager...${NC}"
systemctl stop awg-manager.service 2>/dev/null || true
systemctl disable awg-manager.service 2>/dev/null || true
rm -f /etc/systemd/system/awg-manager.service
systemctl daemon-reload

read -p "Удалить каталог программы /opt/awg-manager (включая базу данных)? (y/N): " CONFIRM
if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
  rm -rf /opt/awg-manager
  echo -e "${GREEN}Каталог /opt/awg-manager удален.${NC}"
else
  echo "Каталог /opt/awg-manager сохранен."
fi

echo -e "${GREEN}Служба awg-manager успешно удалена.${NC}"
