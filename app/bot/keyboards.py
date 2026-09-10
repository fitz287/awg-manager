from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from typing import List, Dict, Any

def get_main_menu_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="📊 Статус интерфейсов", callback_data="menu:interfaces"),
            InlineKeyboardButton(text="👥 Список пользователей", callback_data="menu:users")
        ],
        [
            InlineKeyboardButton(text="➕ Создать пользователя", callback_data="user:create"),
            InlineKeyboardButton(text="📱 Добавить конфиг", callback_data="config:create")
        ],
        [
            InlineKeyboardButton(text="🔄 Обновить", callback_data="menu:refresh")
        ]
    ])

def get_interfaces_keyboard(interfaces: List[Dict[str, Any]]) -> InlineKeyboardMarkup:
    buttons = []
    for iface in interfaces:
        name = iface["name"]
        is_active = iface["is_active"]
        status_icon = "🟢" if is_active else "🔴"
        toggle_action = "stop" if is_active else "start"
        toggle_icon = "⏹️ Стоп" if is_active else "▶️ Старт"

        buttons.append([
            InlineKeyboardButton(
                text=f"{status_icon} {name} ({iface.get('protocol_version', 'v2.0')})",
                callback_data=f"iface:info:{name}"
            ),
            InlineKeyboardButton(
                text=f"{toggle_icon}",
                callback_data=f"iface:{toggle_action}:{name}"
            )
        ])

    buttons.append([InlineKeyboardButton(text="« Главное меню", callback_data="menu:main")])
    return InlineKeyboardMarkup(inline_keyboard=buttons)

def get_interface_select_keyboard(interfaces: List[str]) -> InlineKeyboardMarkup:
    buttons = []
    for iface in interfaces:
        buttons.append([InlineKeyboardButton(text=f"🌐 {iface}", callback_data=f"select_iface:{iface}")])
    buttons.append([InlineKeyboardButton(text="❌ Отмена", callback_data="menu:main")])
    return InlineKeyboardMarkup(inline_keyboard=buttons)

def get_users_keyboard(users: List[Dict[str, Any]]) -> InlineKeyboardMarkup:
    buttons = []
    for u in users:
        configs_count = len(u.get("configs", []))
        buttons.append([
            InlineKeyboardButton(
                text=f"👤 {u['username']} ({u['subnet']}) — {configs_count} устр.",
                callback_data=f"user:view:{u['id']}"
            )
        ])

    buttons.append([
        InlineKeyboardButton(text="➕ Новый пользователь", callback_data="user:create"),
        InlineKeyboardButton(text="« Главное меню", callback_data="menu:main")
    ])
    return InlineKeyboardMarkup(inline_keyboard=buttons)

def get_user_detail_keyboard(user_id: int, configs: List[Dict[str, Any]]) -> InlineKeyboardMarkup:
    buttons = []
    for c in configs:
        online_icon = "🟢" if c.get("is_online") else "⚪"
        buttons.append([
            InlineKeyboardButton(
                text=f"{online_icon} {c['label']} ({c['device_ip']})",
                callback_data=f"config:view:{c['id']}"
            )
        ])

    buttons.append([
        InlineKeyboardButton(text="📱 + Добавить устройство", callback_data=f"config:add_for_user:{user_id}"),
        InlineKeyboardButton(text="🗑️ Удалить пользователя", callback_data=f"user:delete_confirm:{user_id}")
    ])
    buttons.append([InlineKeyboardButton(text="« К списку пользователей", callback_data="menu:users")])
    return InlineKeyboardMarkup(inline_keyboard=buttons)

def get_config_detail_keyboard(config_id: int, user_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="📥 Скачать .conf", callback_data=f"config:download:{config_id}"),
            InlineKeyboardButton(text="📷 Показать QR-код", callback_data=f"config:qr:{config_id}")
        ],
        [
            InlineKeyboardButton(text="🗑️ Удалить этот конфиг", callback_data=f"config:delete_confirm:{config_id}")
        ],
        [
            InlineKeyboardButton(text="« Назад к пользователю", callback_data=f"user:view:{user_id}")
        ]
    ])

def get_delete_confirm_keyboard(entity_type: str, entity_id: int, back_callback: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="⚠️ Да, подтверждаю удаление", callback_data=f"{entity_type}:delete_do:{entity_id}")
        ],
        [
            InlineKeyboardButton(text="❌ Отмена", callback_data=back_callback)
        ]
    ])
