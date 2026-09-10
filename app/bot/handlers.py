import io
from aiogram import Router, F
from aiogram.types import Message, CallbackQuery, BufferedInputFile
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.db.database import AsyncSessionLocal
from app.db.models import InterfaceModel, UserModel, ClientConfigModel
from app.services.awg_service import awg_service
from app.services.ip_allocator import IPAllocator
from app.services.key_generator import generate_key_pair, generate_preshared_key
from app.services.ip_detector import get_server_public_ip
from app.services.qr_service import generate_qr_png_bytes
from app.bot.states import CreateUserStates, CreateConfigStates
from app.bot.keyboards import (
    get_main_menu_keyboard,
    get_interfaces_keyboard,
    get_interface_select_keyboard,
    get_users_keyboard,
    get_user_detail_keyboard,
    get_config_detail_keyboard,
    get_delete_confirm_keyboard
)

router = Router()

def is_admin(user_id: int) -> bool:
    if not settings.ADMIN_TELEGRAM_IDS:
        return False
    return user_id in settings.ADMIN_TELEGRAM_IDS

def format_bytes(b: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024.0:
            return f"{b:.1f} {unit}"
        b /= 1024.0
    return f"{b:.1f} PB"

@router.message(CommandStart())
@router.message(Command("menu"))
async def cmd_start(message: Message, state: FSMContext):
    await state.clear()
    user_id = message.from_user.id
    if not is_admin(user_id):
        await message.answer(
            f"⛔ <b>Доступ запрещен</b>\n\n"
            f"Ваш Telegram ID: <code>{user_id}</code>\n\n"
            f"Добавьте этот ID в параметр <code>ADMIN_TELEGRAM_IDS</code> в файле конфигурации <code>.env</code> для управления ботом.",
            parse_mode="HTML"
        )
        return

    # Gather summary
    conf_files = awg_service.list_interface_files()
    ifaces_count = len(conf_files)
    
    async with AsyncSessionLocal() as db:
        users_res = await db.execute(select(UserModel))
        users_count = len(users_res.scalars().all())
        configs_res = await db.execute(select(ClientConfigModel))
        configs_count = len(configs_res.scalars().all())

    public_ip = await get_server_public_ip()

    text = (
        f"⚡ <b>Панель управления AmneziaWG</b>\n\n"
        f"🌐 <b>Сервер:</b> <code>{public_ip}</code>\n"
        f"📁 <b>Интерфейсов:</b> {ifaces_count}\n"
        f"👥 <b>Пользователей:</b> {users_count}\n"
        f"📱 <b>Активных устройств:</b> {configs_count}\n\n"
        f"Выберите раздел для управления:"
    )
    await message.answer(text, reply_markup=get_main_menu_keyboard(), parse_mode="HTML")

@router.callback_query(F.data == "menu:main")
async def cb_main_menu(call: CallbackQuery, state: FSMContext):
    await state.clear()
    if not is_admin(call.from_user.id):
        await call.answer("Доступ запрещен", show_alert=True)
        return

    conf_files = awg_service.list_interface_files()
    async with AsyncSessionLocal() as db:
        users_res = await db.execute(select(UserModel))
        users_count = len(users_res.scalars().all())
        configs_res = await db.execute(select(ClientConfigModel))
        configs_count = len(configs_res.scalars().all())

    public_ip = await get_server_public_ip()
    text = (
        f"⚡ <b>Панель управления AmneziaWG</b>\n\n"
        f"🌐 <b>Сервер:</b> <code>{public_ip}</code>\n"
        f"📁 <b>Интерфейсов:</b> {len(conf_files)}\n"
        f"👥 <b>Пользователей:</b> {users_count}\n"
        f"📱 <b>Активных устройств:</b> {configs_count}\n\n"
        f"Выберите раздел для управления:"
    )
    try:
        await call.message.edit_text(text, reply_markup=get_main_menu_keyboard(), parse_mode="HTML")
    except Exception:
        await call.message.answer(text, reply_markup=get_main_menu_keyboard(), parse_mode="HTML")
    await call.answer()

@router.callback_query(F.data == "menu:refresh")
async def cb_refresh(call: CallbackQuery, state: FSMContext):
    await cb_main_menu(call, state)

# --- УПРАВЛЕНИЕ ИНТЕРФЕЙСАМИ ---

@router.callback_query(F.data == "menu:interfaces")
async def cb_interfaces(call: CallbackQuery):
    if not is_admin(call.from_user.id):
        await call.answer("Доступ запрещен", show_alert=True)
        return

    conf_files = awg_service.list_interface_files()
    if not conf_files:
        await call.message.edit_text(
            "⚠️ В каталоге конфигураций не найдено файлов .conf",
            reply_markup=get_main_menu_keyboard()
        )
        await call.answer()
        return

    ifaces_data = []
    for f in conf_files:
        name = f.replace(".conf", "")
        cfg = awg_service.parse_interface_config(name)
        status = await awg_service.get_interface_status(name)
        ifaces_data.append({
            "name": name,
            "is_active": status["is_active"],
            "protocol_version": cfg.protocol_version if cfg else "v2.0"
        })

    text = "🌐 <b>Интерфейсы AmneziaWG</b>\n\nНажмите на интерфейс для подробностей или кнопку Старт/Стоп:"
    await call.message.edit_text(text, reply_markup=get_interfaces_keyboard(ifaces_data), parse_mode="HTML")
    await call.answer()

@router.callback_query(F.data.startswith("iface:start:"))
async def cb_iface_start(call: CallbackQuery):
    name = call.data.split(":")[2]
    await call.answer(f"Запуск {name}...", show_alert=False)
    success, msg = await awg_service.start_interface(name)
    if success:
        await call.answer(f"✅ {msg}", show_alert=True)
    else:
        await call.answer(f"❌ Ошибка: {msg}", show_alert=True)
    await cb_interfaces(call)

@router.callback_query(F.data.startswith("iface:stop:"))
async def cb_iface_stop(call: CallbackQuery):
    name = call.data.split(":")[2]
    await call.answer(f"Остановка {name}...", show_alert=False)
    success, msg = await awg_service.stop_interface(name)
    if success:
        await call.answer(f"⏹️ {msg}", show_alert=True)
    else:
        await call.answer(f"❌ Ошибка: {msg}", show_alert=True)
    await cb_interfaces(call)

@router.callback_query(F.data.startswith("iface:info:"))
async def cb_iface_info(call: CallbackQuery):
    name = call.data.split(":")[2]
    cfg = awg_service.parse_interface_config(name)
    status = await awg_service.get_interface_status(name)
    if not cfg:
        await call.answer("Конфиг не найден", show_alert=True)
        return

    state_str = "🟢 UP (Работает)" if status["is_active"] else "🔴 DOWN (Остановлен)"
    rx_str = format_bytes(status["total_rx"])
    tx_str = format_bytes(status["total_tx"])

    text = (
        f"🌐 <b>Интерфейс: {name}</b>\n"
        f"Статус: {state_str}\n"
        f"Протокол: <b>{cfg.protocol_version}</b>\n"
        f"Порт: <code>{cfg.listen_port}</code>\n"
        f"Подсеть: <code>{cfg.address}</code>\n"
        f"Пиров онлайн: <b>{status['peers_online']}</b> из {status['peers_count']}\n"
        f"Трафик: ⬇️ {rx_str} | ⬆️ {tx_str}\n"
        f"Публичный ключ:\n<code>{cfg.public_key}</code>\n\n"
        f"<b>Параметры маскировки:</b>\n"
    )
    for k, v in list(cfg.obfuscation_params.items())[:6]:
        text += f"• <i>{k}</i>: <code>{v}</code>\n"

    from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="« К интерфейсам", callback_data="menu:interfaces")]
    ])
    await call.message.edit_text(text, reply_markup=kb, parse_mode="HTML")
    await call.answer()

# --- СПИСОК ПОЛЬЗОВАТЕЛЕЙ И УСТРОЙСТВ ---

@router.callback_query(F.data == "menu:users")
async def cb_users(call: CallbackQuery):
    if not is_admin(call.from_user.id):
        await call.answer("Доступ запрещен", show_alert=True)
        return

    async with AsyncSessionLocal() as db:
        res = await db.execute(select(UserModel).options(selectinload(UserModel.configs)))
        users = res.scalars().all()

    if not users:
        from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="➕ Создать пользователя", callback_data="user:create")],
            [InlineKeyboardButton(text="« Главное меню", callback_data="menu:main")]
        ])
        await call.message.edit_text("👥 Пользователи пока не созданы.", reply_markup=kb)
        await call.answer()
        return

    users_data = []
    for u in users:
        users_data.append({
            "id": u.id,
            "username": u.username,
            "subnet": u.subnet,
            "configs": u.configs
        })

    text = "👥 <b>Список пользователей:</b>\n\nВыберите пользователя для управления его устройствами и подсетью:"
    await call.message.edit_text(text, reply_markup=get_users_keyboard(users_data), parse_mode="HTML")
    await call.answer()

@router.callback_query(F.data.startswith("user:view:"))
async def cb_user_view(call: CallbackQuery):
    user_id = int(call.data.split(":")[2])
    async with AsyncSessionLocal() as db:
        res = await db.execute(
            select(UserModel).options(selectinload(UserModel.configs)).where(UserModel.id == user_id)
        )
        user = res.scalar_one_or_none()

    if not user:
        await call.answer("Пользователь не найден", show_alert=True)
        await cb_users(call)
        return

    status = await awg_service.get_interface_status(user.interface_name)
    rt_peers = status.get("peers_data", {})

    configs_data = []
    for c in user.configs:
        live = rt_peers.get(c.public_key, {})
        configs_data.append({
            "id": c.id,
            "label": c.label,
            "device_ip": c.device_ip,
            "is_online": live.get("is_online", False)
        })

    text = (
        f"👤 <b>Пользователь:</b> {user.username}\n"
        f"🌐 <b>Интерфейс:</b> <code>{user.interface_name}</code>\n"
        f"📡 <b>Персональная подсеть:</b> <code>{user.subnet}</code>\n"
        f"📱 <b>Устройств:</b> {len(user.configs)}\n\n"
        f"<b>Список устройств / конфигов:</b>\n"
    )
    if not user.configs:
        text += "<i>Нет активных устройств</i>\n"
    else:
        for c in configs_data:
            icon = "🟢 В сети" if c["is_online"] else "⚪ Офлайн"
            text += f"• <b>{c['label']}</b> (<code>{c['device_ip']}</code>) — {icon}\n"

    await call.message.edit_text(text, reply_markup=get_user_detail_keyboard(user.id, configs_data), parse_mode="HTML")
    await call.answer()

# --- СОЗДАНИЕ ПОЛЬЗОВАТЕЛЯ (FSM) ---

@router.callback_query(F.data == "user:create")
async def cb_user_create_start(call: CallbackQuery, state: FSMContext):
    if not is_admin(call.from_user.id):
        await call.answer("Доступ запрещен", show_alert=True)
        return

    conf_files = awg_service.list_interface_files()
    ifaces = [f.replace(".conf", "") for f in conf_files]
    if not ifaces:
        await call.answer("Нет доступных интерфейсов!", show_alert=True)
        return

    await state.set_state(CreateUserStates.waiting_for_interface)
    await call.message.edit_text(
        "➕ <b>Создание нового пользователя</b>\n\nШаг 1: Выберите интерфейс для пользователя:",
        reply_markup=get_interface_select_keyboard(ifaces),
        parse_mode="HTML"
    )
    await call.answer()

@router.callback_query(CreateUserStates.waiting_for_interface, F.data.startswith("select_iface:"))
async def cb_user_create_iface(call: CallbackQuery, state: FSMContext):
    iface_name = call.data.split(":")[1]
    await state.update_data(interface_name=iface_name)
    await state.set_state(CreateUserStates.waiting_for_username)

    await call.message.edit_text(
        f"🌐 Выбран интерфейс: <b>{iface_name}</b>\n\n"
        f"Шаг 2: Введите имя нового пользователя (например, <code>fitz</code>):",
        parse_mode="HTML"
    )
    await call.answer()

@router.message(CreateUserStates.waiting_for_username)
async def msg_user_create_name(message: Message, state: FSMContext):
    username = message.text.strip()
    if not username or len(username) > 32:
        await message.answer("Пожалуйста, введите корректное имя (до 32 символов):")
        return

    data = await state.get_data()
    iface_name = data["interface_name"]

    async with AsyncSessionLocal() as db:
        # Check duplicate
        dup = await db.execute(
            select(UserModel).where(UserModel.interface_name == iface_name, UserModel.username == username)
        )
        if dup.scalar_one_or_none():
            await message.answer(f"❌ Пользователь с именем {username} уже существует на {iface_name}. Введите другое имя:")
            return

        cfg = awg_service.parse_interface_config(iface_name)
        if not cfg:
            await message.answer(f"❌ Конфигурация интерфейса {iface_name} не найдена.")
            await state.clear()
            return

        all_users = await db.execute(select(UserModel.subnet_index).where(UserModel.interface_name == iface_name))
        used_indices = [row[0] for row in all_users.all()]

        try:
            idx, subnet = IPAllocator.allocate_user_subnet(used_indices, cfg.address)
        except ValueError as e:
            await message.answer(f"❌ Ошибка: {e}")
            await state.clear()
            return

        user = UserModel(
            username=username,
            interface_name=iface_name,
            subnet=subnet,
            subnet_index=idx
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        created_id = user.id

    await state.clear()
    from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📱 Создать первое устройство", callback_data=f"config:add_for_user:{created_id}")],
        [InlineKeyboardButton(text="👤 Профиль пользователя", callback_data=f"user:view:{created_id}")],
        [InlineKeyboardButton(text="« Главное меню", callback_data="menu:main")]
    ])

    await message.answer(
        f"✅ <b>Пользователь успешно создан!</b>\n\n"
        f"👤 <b>Имя:</b> {username}\n"
        f"🌐 <b>Интерфейс:</b> {iface_name}\n"
        f"📡 <b>Выделенная подсеть:</b> <code>{subnet}</code>\n\n"
        f"Теперь можно добавить конфигурацию (устройство) для этого пользователя.",
        reply_markup=kb,
        parse_mode="HTML"
    )

# --- УДАЛЕНИЕ ПОЛЬЗОВАТЕЛЯ ---

@router.callback_query(F.data.startswith("user:delete_confirm:"))
async def cb_user_delete_confirm(call: CallbackQuery):
    user_id = int(call.data.split(":")[2])
    async with AsyncSessionLocal() as db:
        user = await db.get(UserModel, user_id)
    if not user:
        await call.answer("Пользователь не найден", show_alert=True)
        return

    text = (
        f"⚠️ <b>Внимание! Удаление пользователя:</b> {user.username}\n\n"
        f"Подсеть <code>{user.subnet}</code> будет освобождена, а все связанные устройства "
        f"будут немедленно отозваны из ядра AmneziaWG.\n\n"
        f"Вы уверены?"
    )
    await call.message.edit_text(
        text,
        reply_markup=get_delete_confirm_keyboard("user", user_id, f"user:view:{user_id}"),
        parse_mode="HTML"
    )
    await call.answer()

@router.callback_query(F.data.startswith("user:delete_do:"))
async def cb_user_delete_do(call: CallbackQuery):
    user_id = int(call.data.split(":")[2])
    async with AsyncSessionLocal() as db:
        res = await db.execute(
            select(UserModel).options(selectinload(UserModel.configs)).where(UserModel.id == user_id)
        )
        user = res.scalar_one_or_none()
        if user:
            for c in user.configs:
                try:
                    await awg_service.remove_peer(user.interface_name, c.public_key)
                except Exception:
                    pass
            await db.delete(user)
            await db.commit()

    await call.answer("✅ Пользователь и все конфиги удалены", show_alert=True)
    await cb_users(call)

# --- ДОБАВЛЕНИЕ КОНФИГА / УСТРОЙСТВА ---

@router.callback_query(F.data.startswith("config:add_for_user:"))
async def cb_config_add_for_user(call: CallbackQuery, state: FSMContext):
    user_id = int(call.data.split(":")[2])
    await state.update_data(user_id=user_id)
    await state.set_state(CreateConfigStates.waiting_for_label)

    await call.message.answer(
        "📱 <b>Добавление устройства</b>\n\n"
        "Введите ярлык устройства (например: <code>iPhone</code>, <code>Ноутбук Work</code>, <code>Keenetic</code>):",
        parse_mode="HTML"
    )
    await call.answer()

@router.callback_query(F.data == "config:create")
async def cb_config_create_generic(call: CallbackQuery, state: FSMContext):
    # Select user first
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(UserModel))
        users = res.scalars().all()

    if not users:
        await call.answer("Сначала создайте пользователя!", show_alert=True)
        return

    from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
    buttons = []
    for u in users:
        buttons.append([
            InlineKeyboardButton(text=f"👤 {u.username} ({u.interface_name})", callback_data=f"config:add_for_user:{u.id}")
        ])
    buttons.append([InlineKeyboardButton(text="❌ Отмена", callback_data="menu:main")])

    await call.message.edit_text("Выберите пользователя, для которого создать конфиг:", reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons))
    await call.answer()

@router.message(CreateConfigStates.waiting_for_label)
async def msg_config_label(message: Message, state: FSMContext):
    label = message.text.strip()
    if not label or len(label) > 64:
        await message.answer("Пожалуйста, введите корректный ярлык (до 64 символов):")
        return

    data = await state.get_data()
    user_id = data["user_id"]

    await message.answer("⏳ Генерирую ключи и регистрирую устройство в AmneziaWG...")

    async with AsyncSessionLocal() as db:
        res = await db.execute(
            select(UserModel).options(selectinload(UserModel.configs)).where(UserModel.id == user_id)
        )
        user = res.scalar_one_or_none()
        if not user:
            await message.answer("❌ Пользователь не найден")
            await state.clear()
            return

        existing_ips = [c.device_ip for c in user.configs]
        try:
            device_ip = IPAllocator.allocate_device_ip(user.subnet, existing_ips)
        except ValueError as e:
            await message.answer(f"❌ Ошибка распределения IP: {e}")
            await state.clear()
            return

        priv_key, pub_key = generate_key_pair()
        psk = generate_preshared_key()

        # Add peer live and to conf file
        try:
            await awg_service.add_peer(
                iface_name=user.interface_name,
                public_key=pub_key,
                device_ip=device_ip,
                preshared_key=psk,
                user_comment=f"{user.username} - {label}"
            )
        except Exception as e:
            await message.answer(f"⚠️ Ошибка при добавлении в интерфейс: {e}")

        config = ClientConfigModel(
            user_id=user.id,
            label=label,
            device_ip=device_ip,
            public_key=pub_key,
            private_key=priv_key,
            preshared_key=psk
        )
        db.add(config)
        await db.commit()
        await db.refresh(config)
        config_id = config.id

    await state.clear()

    # Generate file and QR code
    server_public_ip = await get_server_public_ip()
    conf_text = awg_service.generate_client_config(
        iface_name=user.interface_name,
        client_private_key=priv_key,
        device_ip=device_ip,
        server_public_ip=server_public_ip,
        preshared_key=psk
    )
    qr_png = generate_qr_png_bytes(conf_text)

    safe_name = f"{user.username}_{label}_{user.interface_name}.conf"
    doc_file = BufferedInputFile(conf_text.encode("utf-8"), filename=safe_name)
    photo_file = BufferedInputFile(qr_png, filename="qrcode.png")

    caption = (
        f"✅ <b>Конфиг успешно создан!</b>\n\n"
        f"👤 Пользователь: <b>{user.username}</b>\n"
        f"🏷️ Ярлык: <b>{label}</b>\n"
        f"🌐 IP устройства: <code>{device_ip}</code>\n"
        f"📡 Подсеть: <code>{user.subnet}</code>\n\n"
        f"📷 <i>Отсканируйте QR-код в приложении AmneziaWG или импортируйте .conf файл ниже.</i>"
    )

    await message.answer_photo(photo=photo_file, caption=caption, parse_mode="HTML")
    await message.answer_document(
        document=doc_file,
        reply_markup=get_config_detail_keyboard(config_id, user.id)
    )

# --- ПРОСМОТР / СКАЧИВАНИЕ / УДАЛЕНИЕ КОНФИГА ---

@router.callback_query(F.data.startswith("config:view:"))
async def cb_config_view(call: CallbackQuery):
    config_id = int(call.data.split(":")[2])
    async with AsyncSessionLocal() as db:
        res = await db.execute(
            select(ClientConfigModel).options(selectinload(ClientConfigModel.user)).where(ClientConfigModel.id == config_id)
        )
        cfg = res.scalar_one_or_none()

    if not cfg:
        await call.answer("Конфиг не найден", show_alert=True)
        return

    status = await awg_service.get_interface_status(cfg.user.interface_name)
    peer_live = status.get("peers_data", {}).get(cfg.public_key, {})
    is_online = peer_live.get("is_online", False)
    rx_str = format_bytes(peer_live.get("rx_bytes", cfg.rx_bytes))
    tx_str = format_bytes(peer_live.get("tx_bytes", cfg.tx_bytes))

    text = (
        f"📱 <b>Устройство: {cfg.label}</b>\n\n"
        f"👤 Владелец: <b>{cfg.user.username}</b>\n"
        f"🌐 Интерфейс: <code>{cfg.user.interface_name}</code>\n"
        f"📡 IP адрес: <code>{cfg.device_ip}</code>\n"
        f"Статус: {'🟢 В сети' if is_online else '⚪ Офлайн'}\n"
        f"Трафик: ⬇️ {rx_str} | ⬆️ {tx_str}\n"
        f"Публичный ключ:\n<code>{cfg.public_key}</code>\n"
    )
    await call.message.edit_text(text, reply_markup=get_config_detail_keyboard(cfg.id, cfg.user.id), parse_mode="HTML")
    await call.answer()

@router.callback_query(F.data.startswith("config:download:"))
async def cb_config_download(call: CallbackQuery):
    config_id = int(call.data.split(":")[2])
    async with AsyncSessionLocal() as db:
        res = await db.execute(
            select(ClientConfigModel).options(selectinload(ClientConfigModel.user)).where(ClientConfigModel.id == config_id)
        )
        cfg = res.scalar_one_or_none()

    if not cfg:
        await call.answer("Конфиг не найден", show_alert=True)
        return

    server_public_ip = await get_server_public_ip()
    conf_text = awg_service.generate_client_config(
        iface_name=cfg.user.interface_name,
        client_private_key=cfg.private_key,
        device_ip=cfg.device_ip,
        server_public_ip=server_public_ip,
        preshared_key=cfg.preshared_key
    )
    safe_name = f"{cfg.user.username}_{cfg.label}_{cfg.user.interface_name}.conf"
    doc_file = BufferedInputFile(conf_text.encode("utf-8"), filename=safe_name)

    await call.message.answer_document(document=doc_file)
    await call.answer()

@router.callback_query(F.data.startswith("config:qr:"))
async def cb_config_qr(call: CallbackQuery):
    config_id = int(call.data.split(":")[2])
    async with AsyncSessionLocal() as db:
        res = await db.execute(
            select(ClientConfigModel).options(selectinload(ClientConfigModel.user)).where(ClientConfigModel.id == config_id)
        )
        cfg = res.scalar_one_or_none()

    if not cfg:
        await call.answer("Конфиг не найден", show_alert=True)
        return

    server_public_ip = await get_server_public_ip()
    conf_text = awg_service.generate_client_config(
        iface_name=cfg.user.interface_name,
        client_private_key=cfg.private_key,
        device_ip=cfg.device_ip,
        server_public_ip=server_public_ip,
        preshared_key=cfg.preshared_key
    )
    qr_png = generate_qr_png_bytes(conf_text)
    photo_file = BufferedInputFile(qr_png, filename="qrcode.png")

    caption = f"📷 QR-код для <b>{cfg.user.username} ({cfg.label})</b>\nIP: <code>{cfg.device_ip}</code>"
    await call.message.answer_photo(photo=photo_file, caption=caption, parse_mode="HTML")
    await call.answer()

@router.callback_query(F.data.startswith("config:delete_confirm:"))
async def cb_config_delete_confirm(call: CallbackQuery):
    config_id = int(call.data.split(":")[2])
    async with AsyncSessionLocal() as db:
        cfg = await db.get(ClientConfigModel, config_id)
    if not cfg:
        await call.answer("Конфиг не найден", show_alert=True)
        return

    text = f"⚠️ Вы действительно хотите удалить конфиг <b>{cfg.label}</b> ({cfg.device_ip})?"
    await call.message.edit_text(
        text,
        reply_markup=get_delete_confirm_keyboard("config", config_id, f"config:view:{config_id}"),
        parse_mode="HTML"
    )
    await call.answer()

@router.callback_query(F.data.startswith("config:delete_do:"))
async def cb_config_delete_do(call: CallbackQuery):
    config_id = int(call.data.split(":")[2])
    user_id = None
    async with AsyncSessionLocal() as db:
        res = await db.execute(
            select(ClientConfigModel).options(selectinload(ClientConfigModel.user)).where(ClientConfigModel.id == config_id)
        )
        cfg = res.scalar_one_or_none()
        if cfg:
            user_id = cfg.user.id
            try:
                await awg_service.remove_peer(cfg.user.interface_name, cfg.public_key)
            except Exception:
                pass
            await db.delete(cfg)
            await db.commit()

    await call.answer("✅ Конфиг удален", show_alert=True)
    if user_id:
        call.data = f"user:view:{user_id}"
        await cb_user_view(call)
    else:
        await cb_users(call)
