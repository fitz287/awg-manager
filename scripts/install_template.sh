#!/usr/bin/env bash
# ==============================================================================
# AmneziaWG Multi-Node Master Panel — One-Line Installer
# Target OS: Ubuntu 20.04/22.04/24.04, Debian 11/12 (x86_64, aarch64)
# ==============================================================================
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "=============================================================="
echo "    AmneziaWG Multi-Node Web Panel — Установка в 1 клик       "
echo "=============================================================="
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Этот скрипт должен быть запущен с правами root (sudo).${NC}"
    exit 1
fi

INSTALL_DIR="/opt/awg-manager"
export PYTHONPATH="$INSTALL_DIR"
CONFIG_DIR="/etc/amnezia/amneziawg"
SYS_CONF="/etc/sysctl.d/99-awg.conf"
PANEL_PORT="${PANEL_PORT:-8090}"
PANEL_HOST="${PANEL_HOST:-0.0.0.0}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-password}"

echo -e "${YELLOW}[1/7] Проверка системы и архитектуры...${NC}"
ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ] && [ "$ARCH" != "aarch64" ] && [ "$ARCH" != "arm64" ]; then
    echo -e "${RED}[!] Неподдерживаемая архитектура: $ARCH. Поддерживаются x86_64 и arm64.${NC}"
    exit 1
fi

OS="unknown"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
fi
echo -e "${GREEN}[✓] ОС: $OS ($VERSION_ID), Архитектура: $ARCH${NC}"

echo -e "\n${YELLOW}[2/7] Обновление пакетов и установка системных утилит...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y -q
apt-get install -y -q \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    tar \
    gzip \
    iptables \
    qrencode \
    openssl \
    ca-certificates \
    software-properties-common

# AmneziaWG / WireGuard tools
echo -e "${YELLOW}[i] Настройка репозитория AmneziaWG...${NC}"
if [ "$OS" = "ubuntu" ]; then
    add-apt-repository -y ppa:amnezia/ppa >/dev/null 2>&1 || true
    apt-get update -y -q >/dev/null 2>&1 || true
    apt-get install -y -q amneziawg amneziawg-tools amneziawg-dkms wireguard-tools >/dev/null 2>&1 || {
        echo -e "${YELLOW}[!] Пакеты amneziawg не установились из PPA, используем wireguard-tools...${NC}"
        apt-get install -y -q wireguard-tools || true
    }
else
    apt-get install -y -q wireguard-tools || true
fi

echo -e "\n${YELLOW}[3/7] Включение IP Forwarding в ядре Linux...${NC}"
cat << 'EOF' > "$SYS_CONF"
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
sysctl -p "$SYS_CONF" >/dev/null 2>&1 || sysctl --system >/dev/null 2>&1 || true
echo -e "${GREEN}[✓] Маршрутизация пакетов (IP Forwarding) активирована.${NC}"

echo -e "\n${YELLOW}[4/7] Развертывание файлов панели в $INSTALL_DIR...${NC}"
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/data" "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# Payload unpacking
AWG_PAYLOAD="__AWG_PAYLOAD_PLACEHOLDER__"

echo "$AWG_PAYLOAD" | base64 -d | tar -xz -C "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/run.py" 2>/dev/null || true
echo -e "${GREEN}[✓] Файлы панели успешно извлечены.${NC}"

echo -e "\n${YELLOW}[5/7] Настройка Python venv и установка зависимостей...${NC}"
if [ ! -d "$INSTALL_DIR/venv" ]; then
    python3 -m venv "$INSTALL_DIR/venv"
fi
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
echo -e "${GREEN}[✓] Зависимости Python установлены.${NC}"

echo -e "\n${YELLOW}[6/7] Конфигурация окружения и базы данных...${NC}"
ENV_FILE="$INSTALL_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    SECRET_KEY=$(openssl rand -hex 24)
    cat << EOF > "$ENV_FILE"
PANEL_HOST=$PANEL_HOST
PANEL_PORT=$PANEL_PORT
SECRET_KEY=$SECRET_KEY
DEFAULT_DNS=1.1.1.1, 8.8.8.8
DEFAULT_MTU=1280
EOF
    echo -e "${GREEN}[✓] Сгенерирован новый $ENV_FILE (Порт: $PANEL_PORT)${NC}"
else
    echo -e "${YELLOW}[i] Проверка существующего $ENV_FILE...${NC}"
    CURRENT_PORT=$(grep "^PANEL_PORT=" "$ENV_FILE" | cut -d'=' -f2)
    if [ "$CURRENT_PORT" = "8080" ] || [ "$CURRENT_PORT" = "8089" ] || [ -z "$CURRENT_PORT" ]; then
        sed -i 's/^PANEL_PORT=.*/PANEL_PORT=8090/' "$ENV_FILE"
        PANEL_PORT="8090"
        echo -e "${GREEN}[✓] Порт переведен на 8090 в $ENV_FILE${NC}"
    else
        PANEL_PORT="$CURRENT_PORT"
        echo -e "${GREEN}[✓] Используется порт $PANEL_PORT из $ENV_FILE${NC}"
    fi
fi

# Initialize DB and set admin credentials if not set
cd "$INSTALL_DIR"
export PYTHONPATH="$INSTALL_DIR"
"$INSTALL_DIR/venv/bin/python3" -c "
import sys
sys.path.insert(0, '$INSTALL_DIR')
from app.database import init_db, get_setting, set_setting
from app.auth import hash_password
init_db()
if not get_setting('admin_username'):
    set_setting('admin_username', '$ADMIN_USER')
if not get_setting('admin_password_hash'):
    set_setting('admin_password_hash', hash_password('$ADMIN_PASS'))
"
echo -e "${GREEN}[✓] База данных SQLite инициализирована.${NC}"

echo -e "\n${YELLOW}[7/7] Настройка системной службы awg-manager.service...${NC}"
cat << 'EOF' > /etc/systemd/system/awg-manager.service
[Unit]
Description=AmneziaWG Multi-Node Master Panel
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/awg-manager
ExecStart=/opt/awg-manager/venv/bin/python run.py
Restart=always
RestartSec=3
LimitNOFILE=65535
EnvironmentFile=/opt/awg-manager/.env

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable awg-manager.service >/dev/null 2>&1
systemctl restart awg-manager.service

# Setup management CLI /usr/local/bin/awg-manager
cat << 'EOF' > /usr/local/bin/awg-manager
#!/usr/bin/env bash
# AmneziaWG Management CLI

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

case "$1" in
    start)
        systemctl start awg-manager
        echo -e "${GREEN}[✓] Панель запущена.${NC}"
        ;;
    stop)
        systemctl stop awg-manager
        echo -e "${YELLOW}[✓] Панель остановлена.${NC}"
        ;;
    restart)
        systemctl restart awg-manager
        echo -e "${GREEN}[✓] Панель перезапущена.${NC}"
        ;;
    status)
        systemctl status awg-manager
        ;;
    logs)
        journalctl -u awg-manager -f -n 50
        ;;
    reset-password)
        read -rp "Введите новый логин администратора [admin]: " new_user
        new_user="${new_user:-admin}"
        read -rsp "Введите новый пароль администратора: " new_pass
        echo ""
        if [ -z "$new_pass" ]; then
            echo -e "${RED}[!] Пароль не может быть пустым.${NC}"
            exit 1
        fi
        PYTHONPATH=/opt/awg-manager /opt/awg-manager/venv/bin/python3 -c "
import sqlite3, bcrypt
h = bcrypt.hashpw('$new_pass'.encode(), bcrypt.gensalt()).decode()
conn = sqlite3.connect('/opt/awg-manager/data/awg_panel.db')
conn.execute(\"INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_username', ?)\", ('$new_user',))
conn.execute(\"INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password_hash', ?)\", (h,))
conn.commit()
print('Учетные данные администратора успешно обновлены!')
"
        systemctl restart awg-manager
        ;;
    set-port)
        new_port="$2"
        if [ -z "$new_port" ]; then
            read -rp "Введите новый порт для панели (1-65535): " new_port
        fi
        if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
            echo -e "${RED}[!] Некорректный номер порта: $new_port${NC}"
            exit 1
        fi
        sed -i "s/^PANEL_PORT=.*/PANEL_PORT=$new_port/" /opt/awg-manager/.env
        systemctl restart awg-manager
        echo -e "${GREEN}[✓] Порт изменен на $new_port. Служба перезапущена.${NC}"
        ;;
    info)
        PORT=$(grep "^PANEL_PORT=" /opt/awg-manager/.env 2>/dev/null | cut -d'=' -f2 || echo "8090")
        IP=$(curl -s --max-time 3 https://api.ipify.org || hostname -I | awk '{print $1}')
        ADMIN_U=$(PYTHONPATH=/opt/awg-manager /opt/awg-manager/venv/bin/python3 -c "from app.database import get_setting; print(get_setting('admin_username', 'admin'))" 2>/dev/null || echo "admin")
        echo -e "${CYAN}====================================================${NC}"
        echo -e "${CYAN}   AmneziaWG Multi-Node Web Panel Info              ${NC}"
        echo -e "${CYAN}====================================================${NC}"
        echo -e "URL:     ${BLUE}http://${IP}:${PORT}${NC}"
        echo -e "Логин:   ${GREEN}${ADMIN_U}${NC}"
        echo -e "Статус:  $(systemctl is-active awg-manager)"
        echo -e "${CYAN}====================================================${NC}"
        ;;
    uninstall)
        echo -e "${RED}${BOLD}Внимание! Это действие полностью остановит и удалит AmneziaWG Panel с сервера.${NC}"
        read -rp "Вы действительно хотите удалить панель и базу данных? (y/N): " confirm
        if [[ "$confirm" =~ ^[yYдД]$ ]]; then
            echo -e "${YELLOW}[*] Остановка и отключение службы...${NC}"
            systemctl stop awg-manager 2>/dev/null || true
            systemctl disable awg-manager 2>/dev/null || true
            rm -f /etc/systemd/system/awg-manager.service
            systemctl daemon-reload
            echo -e "${YELLOW}[*] Удаление файлов панели из /opt/awg-manager...${NC}"
            rm -rf /opt/awg-manager
            echo -e "${YELLOW}[*] Удаление команды awg-manager...${NC}"
            rm -f /usr/local/bin/awg-manager
            echo -e "${GREEN}[✓] Панель AmneziaWG успешно удалена с сервера.${NC}"
            exit 0
        else
            echo -e "${GREEN}[i] Удаление отменено.${NC}"
        fi
        ;;
    *)
        echo -e "${CYAN}Управление AmneziaWG Web Panel:${NC}"
        echo -e "  awg-manager status          - Проверить статус службы"
        echo -e "  awg-manager restart         - Перезапустить панель"
        echo -e "  awg-manager logs            - Смотреть логи в реальном времени"
        echo -e "  awg-manager reset-password  - Сбросить логин/пароль администратора"
        echo -e "  awg-manager set-port <порт> - Изменить веб-порт панели"
        echo -e "  awg-manager info            - Показать информацию о подключении"
        echo -e "  awg-manager uninstall       - Полное удаление панели с сервера"
        echo -e "  awg-manager stop / start    - Остановка / Запуск"
        ;;
esac
EOF
chmod +x /usr/local/bin/awg-manager

# Determine Server IP
SERVER_IP=$(curl -s --max-time 4 https://api.ipify.org || hostname -I | awk '{print $1}')

echo -e "\n${GREEN}${BOLD}==============================================================${NC}"
echo -e "${GREEN}${BOLD}   Поздравляем! AmneziaWG Panel успешно установлена!          ${NC}"
echo -e "${GREEN}${BOLD}==============================================================${NC}"
echo -e "Веб-панель доступна по адресу:"
echo -e "👉 ${BLUE}${BOLD}http://${SERVER_IP}:${PANEL_PORT}${NC}"
echo ""
echo -e "Данные для входа:"
echo -e "👤 Логин:   ${BOLD}${ADMIN_USER}${NC}"
echo -e "🔑 Пароль:  ${BOLD}${ADMIN_PASS}${NC}"
echo ""
echo -e "Управление через консоль сервера:"
echo -e "🛠  Команда:  ${YELLOW}awg-manager${NC} (меню, сброс пароля, смена порта, логи)"
echo -e "📜 Логи:     ${YELLOW}journalctl -u awg-manager -f${NC}"
echo -e "${GREEN}${BOLD}==============================================================${NC}"
