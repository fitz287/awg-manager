"""
AmneziaWG Telegram Bot for User Self-Service
Allows authorized users (matched by Telegram ID in DB) to:
- Browse their VPN connections / nodes
- Download .conf configs
- Download Amnezia .vpn files and copy vpn:// strings
- Receive QR codes for quick camera import
- Download all configs as a single ZIP archive
- Get personal subscription / web portal URL
"""

import asyncio
import io
import json
import logging
import os
import sys
import zipfile
from typing import Optional

from aiogram import Bot, Dispatcher, F, types
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    BufferedInputFile,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

# Ensure project root in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import (
    get_db,
    get_setting,
    get_user_by_telegram_id,
    get_user_by_id,
    get_user_peers,
    get_peer_by_id,
    get_connection_by_id,
    get_server_by_id,
    init_db,
)
from app.awg_manager import generate_client_config_text, generate_amnezia_vpn_data

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("awg_bot")

dp = Dispatcher()


def get_panel_domain() -> str:
    """Returns external panel domain or default."""
    url = get_setting("panel_url", "").strip()
    if url:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"https://{url}"
        return url.rstrip("/")
    return "https://awg.fitz.su"


def make_main_keyboard(user: dict) -> InlineKeyboardMarkup:
    """Builds main menu keyboard with user's connections."""
    peers = get_user_peers(user["id"])
    buttons = []

    for p in peers:
        srv = p.get("server_name") or "Сервер"
        conn_name = p.get("connection_name") or "AWG"
        label = p.get("label") or "Девайс"
        btn_text = f"📍 {srv} ({conn_name}) • {label}"
        buttons.append([InlineKeyboardButton(text=btn_text, callback_data=f"peer:{p['id']}")])

    extra_row = []
    if peers:
        extra_row.append(InlineKeyboardButton(text="📦 Скачать всё (ZIP)", callback_data="act:zip"))
    extra_row.append(InlineKeyboardButton(text="🔗 Моя подписка", callback_data="act:sub"))
    buttons.append(extra_row)

    return InlineKeyboardMarkup(inline_keyboard=buttons)


def make_peer_keyboard(peer_id: int) -> InlineKeyboardMarkup:
    """Keyboard for specific peer actions."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="📥 Скачать .conf", callback_data=f"conf:{peer_id}"),
                InlineKeyboardButton(text="📱 QR-код", callback_data=f"qr:{peer_id}"),
            ],
            [
                InlineKeyboardButton(text="🛡 Скачать Amnezia .vpn", callback_data=f"vpn:{peer_id}"),
            ],
            [
                InlineKeyboardButton(text="◀️ Назад ко всем подключениям", callback_data="act:menu"),
            ],
        ]
    )


@dp.message(CommandStart())
async def cmd_start(message: Message):
    tg_id = str(message.from_user.id)
    user = get_user_by_telegram_id(tg_id)

    if not user:
        text = (
            "⛔ <b>Доступ запрещён</b>\n\n"
            f"Ваш Telegram ID: <code>{tg_id}</code>\n\n"
            "Вы не зарегистрированы в системе или ваш аккаунт деактивирован.\n"
            "Скопируйте этот ID и отправьте его администратору для получения доступа."
        )
        await message.answer(text, parse_mode=ParseMode.HTML)
        return

    username = user.get("username", "Пользователь")
    text = (
        f"👋 Привет, <b>{username}</b>!\n\n"
        "Добро пожаловать в сервис управления подключениями <b>AmneziaWG</b>.\n\n"
        "Выберите подключение ниже, чтобы скачать конфигурацию или получить QR-код для настройки на смартфоне:"
    )
    kb = make_main_keyboard(user)
    await message.answer(text, reply_markup=kb, parse_mode=ParseMode.HTML)


@dp.message(Command("help"))
async def cmd_help(message: Message):
    tg_id = str(message.from_user.id)
    user = get_user_by_telegram_id(tg_id)

    if not user:
        await message.answer(
            f"⛔ Доступ запрещён. Ваш Telegram ID: <code>{tg_id}</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    text = (
        "💡 <b>Как настроить AmneziaWG:</b>\n\n"
        "1. Установите официальное приложение <b>AmneziaWG</b> (для Android, iOS, Windows, macOS).\n"
        "2. Нажмите в боте на нужное подключение.\n"
        "3. Выберите <b>«📱 QR-код»</b> для сканирования камерой телефона, либо <b>«📥 Скачать .conf»</b> для импорта файла.\n"
        "4. Для официального клиента <i>Amnezia VPN</i> выберите <b>«🛡 Скачать Amnezia .vpn»</b>.\n\n"
        "Команда /start — открыть главное меню."
    )
    await message.answer(text, parse_mode=ParseMode.HTML)


@dp.callback_query(F.data == "act:menu")
async def cb_menu(call: CallbackQuery):
    tg_id = str(call.from_user.id)
    user = get_user_by_telegram_id(tg_id)
    if not user:
        await call.answer("Доступ запрещён", show_alert=True)
        return

    username = user.get("username", "Пользователь")
    text = f"👋 Ваши подключения, <b>{username}</b>:\nВыберите нужное устройство/локацию:"
    kb = make_main_keyboard(user)
    try:
        await call.message.edit_text(text, reply_markup=kb, parse_mode=ParseMode.HTML)
    except Exception:
        await call.message.answer(text, reply_markup=kb, parse_mode=ParseMode.HTML)
    await call.answer()


@dp.callback_query(F.data.startswith("peer:"))
async def cb_peer_detail(call: CallbackQuery):
    tg_id = str(call.from_user.id)
    user = get_user_by_telegram_id(tg_id)
    if not user:
        await call.answer("Доступ запрещён", show_alert=True)
        return

    peer_id = int(call.data.split(":")[1])
    peer = get_peer_by_id(peer_id)
    if not peer or peer["user_id"] != user["id"]:
        await call.answer("Подключение не найдено", show_alert=True)
        return

    conn = get_connection_by_id(peer["connection_id"]) or {}
    server = get_server_by_id(conn.get("server_id", 1)) or {}

    server_name = server.get("name", "Основной сервер")
    conn_name = conn.get("name", "AWG")
    proto = conn.get("protocol_version", "3.1")
    label = peer.get("label", "Девайс")
    client_ip = peer.get("client_ip", "")

    text = (
        f"📍 <b>{server_name}</b> (Подключение: <code>{conn_name}</code>)\n"
        f"• Устройство: <b>{label}</b>\n"
        f"• Протокол: <b>AmneziaWG {proto}</b>\n"
        f"• Внутренний IP: <code>{client_ip}</code>\n\n"
        "Выберите формат для получения конфига:"
    )
    kb = make_peer_keyboard(peer_id)
    try:
        await call.message.edit_text(text, reply_markup=kb, parse_mode=ParseMode.HTML)
    except Exception:
        await call.message.answer(text, reply_markup=kb, parse_mode=ParseMode.HTML)
    await call.answer()


@dp.callback_query(F.data.startswith("conf:"))
async def cb_send_conf(call: CallbackQuery):
    tg_id = str(call.from_user.id)
    user = get_user_by_telegram_id(tg_id)
    if not user:
        await call.answer("Доступ запрещён", show_alert=True)
        return

    peer_id = int(call.data.split(":")[1])
    peer = get_peer_by_id(peer_id)
    if not peer or peer["user_id"] != user["id"]:
        await call.answer("Подключение не найдено", show_alert=True)
        return

    try:
        conf_text = generate_client_config_text(peer_id)
        conn = get_connection_by_id(peer["connection_id"]) or {}
        server = get_server_by_id(conn.get("server_id", 1)) or {}

        filename = f"{user['username']}_{conn.get('name', 'awg')}_{peer.get('label', 'device')}.conf".replace(" ", "_")
        file_bytes = conf_text.encode("utf-8")
        doc = BufferedInputFile(file_bytes, filename=filename)

        caption = f"📄 Конфигурация для <b>{server.get('name', 'Сервер')}</b> ({conn.get('name', 'AWG')})\nИмпортируйте этот файл в приложение <b>AmneziaWG</b>."
        await call.message.answer_document(doc, caption=caption, parse_mode=ParseMode.HTML)
        await call.answer("Файл отправлен!")
    except Exception as e:
        logger.exception("Failed to send conf: %s", e)
        await call.answer(f"Ошибка: {e}", show_alert=True)


@dp.callback_query(F.data.startswith("qr:"))
async def cb_send_qr(call: CallbackQuery):
    tg_id = str(call.from_user.id)
    user = get_user_by_telegram_id(tg_id)
    if not user:
        await call.answer("Доступ запрещён", show_alert=True)
        return

    peer_id = int(call.data.split(":")[1])
    peer = get_peer_by_id(peer_id)
    if not peer or peer["user_id"] != user["id"]:
        await call.answer("Подключение не найдено", show_alert=True)
        return

    try:
        import qrcode

        conf_text = generate_client_config_text(peer_id)
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=2,
        )
        qr.add_data(conf_text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        bio = io.BytesIO()
        img.save(bio, "PNG")
        bio.seek(0)

        photo = BufferedInputFile(bio.getvalue(), filename=f"qr_{peer_id}.png")
        conn = get_connection_by_id(peer["connection_id"]) or {}
        server = get_server_by_id(conn.get("server_id", 1)) or {}

        caption = (
            f"📱 QR-код для <b>{server.get('name', 'Сервер')}</b> ({conn.get('name', 'AWG')} - {peer.get('label', 'Девайс')})\n\n"
            "Откройте приложение <b>AmneziaWG</b> на смартфоне, нажмите <b>«+»</b> и выберите <b>«Сканировать QR-код»</b>."
        )
        await call.message.answer_photo(photo, caption=caption, parse_mode=ParseMode.HTML)
        await call.answer()
    except Exception as e:
        logger.exception("Failed to send QR: %s", e)
        await call.answer(f"Ошибка генерации QR: {e}", show_alert=True)


@dp.callback_query(F.data.startswith("vpn:"))
async def cb_send_vpn(call: CallbackQuery):
    tg_id = str(call.from_user.id)
    user = get_user_by_telegram_id(tg_id)
    if not user:
        await call.answer("Доступ запрещён", show_alert=True)
        return

    peer_id = int(call.data.split(":")[1])
    peer = get_peer_by_id(peer_id)
    if not peer or peer["user_id"] != user["id"]:
        await call.answer("Подключение не найдено", show_alert=True)
        return

    try:
        vpn_dict, vpn_url = generate_amnezia_vpn_data(peer_id)
        conn = get_connection_by_id(peer["connection_id"]) or {}
        server = get_server_by_id(conn.get("server_id", 1)) or {}

        filename = f"{user['username']}_{conn.get('name', 'awg')}_{peer.get('label', 'device')}.vpn".replace(" ", "_")
        json_bytes = json.dumps(vpn_dict, indent=2, ensure_ascii=False).encode("utf-8")
        doc = BufferedInputFile(json_bytes, filename=filename)

        caption = (
            f"🛡 Конфиг для официального <b>Amnezia VPN</b> ({server.get('name', 'Сервер')})\n\n"
            f"Строка для импорта из буфера обмена:\n<code>{vpn_url}</code>\n\n"
            "<i>(Скопируйте строку или откройте .vpn файл в приложении Amnezia VPN)</i>"
        )
        await call.message.answer_document(doc, caption=caption, parse_mode=ParseMode.HTML)
        await call.answer("Amnezia .vpn отправлен!")
    except Exception as e:
        logger.exception("Failed to send VPN: %s", e)
        await call.answer(f"Ошибка: {e}", show_alert=True)


@dp.callback_query(F.data == "act:zip")
async def cb_send_zip(call: CallbackQuery):
    tg_id = str(call.from_user.id)
    user = get_user_by_telegram_id(tg_id)
    if not user:
        await call.answer("Доступ запрещён", show_alert=True)
        return

    peers = get_user_peers(user["id"])
    if not peers:
        await call.answer("У вас нет созданных подключений", show_alert=True)
        return

    try:
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in peers:
                conn_name = p.get("connection_name") or "awg"
                server_name = p.get("server_name") or "server"
                label = p.get("label") or "device"
                base_name = f"{user['username']}_{server_name}_{conn_name}_{label}".replace(" ", "_")

                try:
                    conf_text = generate_client_config_text(p["id"])
                    zf.writestr(f"{base_name}.conf", conf_text)
                except Exception as e:
                    logger.warning("Error creating conf for peer %s: %s", p["id"], e)

                try:
                    vpn_dict, _ = generate_amnezia_vpn_data(p["id"])
                    zf.writestr(f"{base_name}.vpn", json.dumps(vpn_dict, indent=2, ensure_ascii=False))
                except Exception as e:
                    logger.warning("Error creating vpn for peer %s: %s", p["id"], e)

        bio.seek(0)
        zip_filename = f"awg_{user['username']}_all_configs.zip"
        doc = BufferedInputFile(bio.getvalue(), filename=zip_filename)
        caption = "📦 Архив со всеми вашими конфигами (.conf и .vpn) для всех серверов."
        await call.message.answer_document(doc, caption=caption, parse_mode=ParseMode.HTML)
        await call.answer("Архив отправлен!")
    except Exception as e:
        logger.exception("Failed to send zip: %s", e)
        await call.answer(f"Ошибка создания архива: {e}", show_alert=True)


@dp.callback_query(F.data == "act:sub")
async def cb_send_sub(call: CallbackQuery):
    tg_id = str(call.from_user.id)
    user = get_user_by_telegram_id(tg_id)
    if not user:
        await call.answer("Доступ запрещён", show_alert=True)
        return

    token = user.get("subscription_token")
    if not token:
        await call.answer("Токен подписки не найден", show_alert=True)
        return

    domain = get_panel_domain()
    sub_url = f"{domain}/sub/{token}"

    text = (
        "🔗 <b>Ваша персональная ссылка подписки:</b>\n\n"
        f"<code>{sub_url}</code>\n\n"
        "• <b>В браузере (телефон/ПК):</b> откройте личный кабинет по ссылке или кнопке ниже, чтобы получить конфигурации для всех ваших серверов, QR-коды и ссылки быстрого импорта.\n"
        "• <b>В клиентах с поддержкой подписок (Karing, NekoBox):</b> скопируйте эту ссылку в раздел «Подписки» приложения."
    )
    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🌐 Открыть личный кабинет", url=sub_url)],
            [InlineKeyboardButton(text="⬅️ Главное меню", callback_data="act:menu")],
        ]
    )
    await call.message.answer(text, reply_markup=kb, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    await call.answer()


async def main():
    init_db()
    logger.info("Initializing AmneziaWG Telegram Bot service...")

    while True:
        token = get_setting("tg_bot_token", "").strip() or os.getenv("TG_BOT_TOKEN", "").strip()
        enabled = get_setting("tg_bot_enabled", "0").strip()
        proxy = get_setting("tg_bot_proxy", "http://127.0.0.1:1080").strip() or os.getenv("TG_BOT_PROXY", "").strip()

        if not token or enabled != "1":
            logger.info("Telegram bot is disabled or token is not configured. Checking again in 15 seconds...")
            await asyncio.sleep(15)
            continue

        if proxy and not (proxy.startswith("http://") or proxy.startswith("https://") or proxy.startswith("socks5://") or proxy.startswith("socks5h://")):
            proxy = f"http://{proxy}"

        logger.info("Starting Telegram bot polling with configured token (proxy: %s)...", proxy or "Direct")
        bot = None
        try:
            session = AiohttpSession(proxy=proxy) if proxy else None
            bot = Bot(token=token, session=session)
            me = await bot.get_me()
            logger.info("Bot successfully authenticated as @%s (%s) via %s", me.username, me.id, proxy or "Direct")
            await dp.start_polling(bot)
        except Exception as e:
            logger.error("Bot encountered error during polling: %s. Re-checking in 15 seconds...", e)
            if bot and bot.session:
                try:
                    await bot.session.close()
                except Exception:
                    pass
            await asyncio.sleep(15)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Bot stopped.")
