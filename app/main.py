import json
import logging
import os
import platform
import shutil
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, Response, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse, RedirectResponse

from app.auth import (
    create_session_token,
    get_current_auth,
    get_current_user,
    hash_password,
    init_auth,
    require_admin,
    require_auth,
    verify_password,
)
from app.awg_crypto import (
    generate_awg_params,
    generate_keypair,
    generate_preshared_key,
)
from app.awg_manager import (
    generate_amnezia_vpn_data,
    generate_client_config_text,
    generate_server_config_text,
    get_interface_conf_file,
    get_interface_detailed_status,
    get_interface_live_status,
    remove_connection_files,
    remove_peer_from_node,
    restart_connection,
    start_connection,
    stop_connection,
    sync_connection_peers,
    sync_peer_to_node,
    write_server_config,
)
from app.config import (
    BASE_DIR,
    DEFAULT_DNS,
    DEFAULT_MTU,
    IS_LINUX,
)
from app.database import (
    create_connection,
    create_peer,
    create_server,
    create_user,
    delete_connection,
    delete_peer,
    delete_server,
    delete_user,
    get_all_connections,
    get_all_servers,
    get_all_users_with_peers,
    get_connection_by_id,
    get_connection_by_name,
    get_connections_by_server,
    get_next_connection_index,
    get_next_device_k,
    get_next_listen_port,
    get_next_table_and_mark,
    get_next_user_y,
    get_peer_by_id,
    get_server_by_id,
    get_server_install_log,
    get_setting,
    get_user_by_id,
    get_user_by_username,
    get_user_peers,
    get_users_by_connection,
    get_user_by_sub_token,
    get_user_by_telegram_id,
    init_db,
    set_setting,
    toggle_peer,
    update_connection_params,
    update_server_status,
    update_server_system_info,
    update_user_details,
    update_user_password,
    update_user_status,
)
from app.node_client import NodeClient
from app.node_provisioner import start_provisioning

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("awg_panel")

# Initialize database and default auth
init_db()
init_auth()

app = FastAPI(title="AmneziaWG Panel", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    # Public routes
    if (
        path in ("/login", "/api/auth/login", "/install.sh", "/uninstall.sh")
        or path.startswith("/static")
        or path.startswith("/sub")
        or path.startswith("/favicon.ico")
    ):
        return await call_next(request)

    # Check authentication
    user = get_current_user(request)
    if not user:
        if path.startswith("/api/"):
            return JSONResponse(status_code=401, content={"detail": "Необходима авторизация"})
        return RedirectResponse(url="/login", status_code=302)

    return await call_next(request)


# Static and Templates
STATIC_DIR = BASE_DIR / "app" / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR = BASE_DIR / "app" / "templates"
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# ----------------------------------------------------
# Pydantic Request Models
# ----------------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    new_username: Optional[str] = None
    old_password: str
    new_password: str
class CreateServerRequest(BaseModel):
    name: str
    host: str
    ssh_port: int = 22
    ssh_user: str = "root"
    ssh_password: Optional[str] = ""
    ssh_key: Optional[str] = ""
    api_port: int = 8089


class UpdateServerRequest(BaseModel):
    name: str
    host: str
    ssh_port: int = 22
    ssh_user: str = "root"
    ssh_password: Optional[str] = None
    ssh_key: Optional[str] = None
    api_port: int = 8089


class CreateConnectionRequest(BaseModel):
    server_id: int = 1
    name: Optional[str] = None  # e.g. awg1, auto-generated if empty
    protocol_version: str = "1.0"  # "1.0", "2.0", "3.1"
    x_subnet: int = Field(..., ge=1, le=254, description="x in 10.x.0.0/16")
    listen_port: Optional[int] = None
    xray_port: int = 7010
    table_num: Optional[int] = None
    fwmark: Optional[int] = None
    params: Optional[Dict[str, Any]] = None


class UpdateConnectionRequest(BaseModel):
    listen_port: Optional[int] = None
    protocol_version: Optional[str] = None
    params: Optional[Dict[str, Any]] = None


class CreateUserRequest(BaseModel):
    connection_id: Optional[int] = None
    username: str
    notes: Optional[str] = ""
    password: Optional[str] = ""
    telegram_id: Optional[str] = None


class UpdateUserRequest(BaseModel):
    username: Optional[str] = None
    notes: Optional[str] = None
    telegram_id: Optional[str] = None
    is_active: Optional[bool] = None


class ResetUserPasswordRequest(BaseModel):
    password: str


class UserChangeOwnPasswordRequest(BaseModel):
    old_password: str
    new_password: str


class UserCreateOwnDeviceRequest(BaseModel):
    connection_id: Optional[int] = None
    label: str
    use_psk: bool = False


class CreatePeerRequest(BaseModel):
    connection_id: Optional[int] = None
    user_id: int
    label: str
    use_psk: bool = False


class UpdateSettingsRequest(BaseModel):
    server_host: Optional[str] = None
    default_dns: str
    default_mtu: int
    tg_bot_token: Optional[str] = None
    tg_bot_enabled: Optional[str] = None
    tg_bot_proxy: Optional[str] = None



# ----------------------------------------------------
# Helper to detect Public IP
# ----------------------------------------------------
def detect_public_ip() -> str:
    saved = get_setting("server_host", "").strip()
    if saved:
        return saved
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "curl/7.68.0"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            ip = resp.read().decode("utf-8").strip()
            if ip:
                set_setting("server_host", ip)
                return ip
    except Exception:
        pass
    return "127.0.0.1"


# ----------------------------------------------------
# Public One-Line Installer Script
# ----------------------------------------------------
@app.get("/install.sh", response_class=PlainTextResponse)
async def serve_install_script():
    install_path = BASE_DIR / "app" / "static" / "install.sh"
    if not install_path.exists():
        install_path = BASE_DIR / "install.sh"
    if not install_path.exists():
        raise HTTPException(status_code=404, detail="Install script not found")
    with open(install_path, "r", encoding="utf-8") as f:
        content = f.read()
    return PlainTextResponse(content=content, media_type="text/plain; charset=utf-8")


@app.get("/uninstall.sh", response_class=PlainTextResponse)
async def serve_uninstall_script():
    uninstall_path = BASE_DIR / "scripts" / "uninstall.sh"
    if not uninstall_path.exists():
        raise HTTPException(status_code=404, detail="Uninstall script not found")
    with open(uninstall_path, "r", encoding="utf-8") as f:
        content = f.read()
    return PlainTextResponse(content=content, media_type="text/plain; charset=utf-8")


# ----------------------------------------------------
# Authentication Endpoints
# ----------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
async def serve_login(request: Request):
    if get_current_user(request):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse(request=request, name="login.html")


@app.get("/api/auth/me")
async def api_auth_me(request: Request):
    auth = get_current_auth(request)
    if not auth:
        raise HTTPException(status_code=401, detail="Необходима авторизация")
    return auth


@app.post("/api/auth/login")
async def api_login(req: LoginRequest):
    input_user = req.username.strip()
    stored_admin = get_setting("admin_username", "admin")
    stored_hash = get_setting("admin_password_hash", "")

    # 1. Check admin login
    if input_user.lower() == stored_admin.lower() and verify_password(req.password, stored_hash):
        resp = JSONResponse(content={"status": "success", "role": "admin", "username": stored_admin})
        token = create_session_token(stored_admin)
        resp.set_cookie(
            key="session_token",
            value=token,
            max_age=30 * 86400,
            httponly=True,
            samesite="lax",
        )
        return resp

    # 2. Check regular user login
    user = get_user_by_username(input_user)
    if user:
        if not user.get("is_active", 1):
            raise HTTPException(status_code=403, detail="Учетная запись отключена")
        user_pw_hash = user.get("password_hash") or ""
        if not user_pw_hash:
            raise HTTPException(
                status_code=401,
                detail="Пароль для данного пользователя еще не настроен. Обратитесь к администратору.",
            )
        if verify_password(req.password, user_pw_hash):
            resp = JSONResponse(
                content={
                    "status": "success",
                    "role": "user",
                    "username": user["username"],
                    "user_id": user["id"],
                }
            )
            token = create_session_token(user["username"])
            resp.set_cookie(
                key="session_token",
                value=token,
                max_age=30 * 86400,
                httponly=True,
                samesite="lax",
            )
            return resp

    raise HTTPException(status_code=401, detail="Неверный логин или пароль")


@app.post("/api/auth/logout")
async def api_logout():
    resp = JSONResponse(content={"status": "success"})
    resp.delete_cookie(key="session_token", path="/")
    return resp


@app.post("/api/auth/change-password")
async def api_change_password(req: ChangePasswordRequest, request: Request):
    stored_hash = get_setting("admin_password_hash", "")
    if not verify_password(req.old_password, stored_hash):
        raise HTTPException(status_code=400, detail="Текущий пароль указан неверно")

    if len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="Новый пароль должен содержать не менее 6 символов")

    if req.new_username and req.new_username.strip():
        set_setting("admin_username", req.new_username.strip())

    set_setting("admin_password_hash", hash_password(req.new_password))

    # Issue new session
    curr_user = get_setting("admin_username", "admin")
    resp = JSONResponse(content={"status": "success", "message": "Пароль успешно обновлен"})
    token = create_session_token(curr_user)
    resp.set_cookie(
        key="session_token",
        value=token,
        max_age=30 * 86400,
        httponly=True,
        samesite="lax",
    )
    return resp


# ----------------------------------------------------
# Web UI Route
# ----------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def serve_index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


# ----------------------------------------------------
# Server (Node) API Endpoints
# ----------------------------------------------------
@app.get("/api/servers")
async def api_list_servers(request: Request):
    require_admin(request)
    servers = get_all_servers()
    for s in servers:
        # Never override status while provisioning is in progress
        if s.get("status") in ("installing", "pending"):
            continue
        try:
            client = NodeClient(s, timeout=1.5)
            health = client.health()
            if health.get("status") == "ok":
                s["status"] = "online"
                update_server_status(s["id"], "online")
            elif s.get("status") == "online":
                s["status"] = "offline"
                update_server_status(s["id"], "offline")
        except Exception:
            pass
    return servers


@app.post("/api/servers")
async def api_create_server(req: CreateServerRequest, request: Request):
    require_admin(request)
    if not req.name.strip():
        raise HTTPException(status_code=400, detail="Укажите название сервера")
    if not req.host.strip():
        raise HTTPException(status_code=400, detail="Укажите хост или IP сервера")

    server_id = create_server(
        name=req.name.strip(),
        host=req.host.strip(),
        ssh_port=req.ssh_port,
        ssh_user=req.ssh_user.strip() or "root",
        ssh_password=req.ssh_password or "",
        ssh_key=req.ssh_key or "",
        api_port=req.api_port,
        status="installing",
    )

    # Start automated background provisioning
    start_provisioning(server_id)

    return {
        "status": "success",
        "server_id": server_id,
        "message": f"Сервер {req.name} добавлен. Запущено развёртывание ноды.",
    }


@app.get("/api/servers/{server_id}")
async def api_get_server(server_id: int, request: Request):
    require_admin(request)
    server = get_server_by_id(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Сервер не найден")
    return server


@app.get("/api/servers/{server_id}/logs")
async def api_get_server_logs(server_id: int, request: Request):
    require_admin(request)
    server = get_server_by_id(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Сервер не найден")
    logs = get_server_install_log(server_id)
    return {"status": server.get("status", "pending"), "logs": logs}


@app.post("/api/servers/{server_id}/provision")
async def api_reprovision_server(server_id: int, request: Request):
    require_admin(request)
    server = get_server_by_id(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Сервер не найден")

    update_server_status(server_id, "installing")
    start_provisioning(server_id)
    return {"status": "success", "message": f"Запущено повторное развёртывание для {server['name']}"}


@app.get("/api/servers/{server_id}/metrics")
async def api_get_server_metrics(server_id: int, request: Request):
    require_admin(request)
    server = get_server_by_id(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Сервер не найден")

    client = NodeClient(server)
    metrics = client.get_metrics()
    if "error" not in metrics:
        update_server_system_info(server_id, metrics)
    return metrics


@app.delete("/api/servers/{server_id}")
async def api_delete_server(server_id: int, request: Request):
    require_admin(request)
    conns = get_connections_by_server(server_id)
    if conns:
        names = ", ".join([c["name"] for c in conns])
        raise HTTPException(
            status_code=400,
            detail=f"Невозможно удалить сервер: на нём созданы подключения ({names}). Сначала удалите их.",
        )

    ok = delete_server(server_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Ошибка удаления сервера")
    return {"status": "success", "message": "Сервер успешно удален"}


# ----------------------------------------------------
# Connection API Endpoints
# ----------------------------------------------------
@app.get("/api/connections")
async def list_connections(request: Request):
    require_admin(request)
    conns = get_all_connections()
    for c in conns:
        live = get_interface_live_status(c["id"])
        c["live"] = live
    return conns


@app.get("/api/connections/next-defaults")
async def next_connection_defaults(request: Request):
    require_admin(request)
    next_idx = get_next_connection_index()
    next_tbl, next_mrk = get_next_table_and_mark()
    next_port = get_next_listen_port()

    # Suggest next x_subnet (e.g. 10 + next_idx)
    existing_conns = get_all_connections()
    existing_x = {c["x_subnet"] for c in existing_conns}
    suggested_x = 10
    while suggested_x in existing_x:
        suggested_x += 1

    params_v1 = generate_awg_params("1.0")
    params_v2 = generate_awg_params("2.0")
    params_v3 = generate_awg_params("3.1")

    return {
        "suggested_name": f"awg{next_idx}",
        "suggested_index": next_idx,
        "suggested_x_subnet": suggested_x,
        "suggested_table": next_tbl,
        "suggested_fwmark": next_mrk,
        "suggested_listen_port": next_port,
        "suggested_xray_port": 7010,
        "params_preview": {
            "1.0": params_v1,
            "2.0": params_v2,
            "3.1": params_v3,
        },
    }


@app.post("/api/connections")
async def api_create_connection(req: CreateConnectionRequest, request: Request):
    require_admin(request)
    next_idx = get_next_connection_index()
    name = (req.name or f"awg{next_idx}").strip().lower()

    # Validate name
    if not name.startswith("awg"):
        name = f"awg{name}"

    if get_connection_by_name(name):
        raise HTTPException(status_code=400, detail=f"Подключение {name} уже существует")

    # Table and mark auto calculation if not provided
    next_tbl, next_mrk = get_next_table_and_mark()
    table_num = req.table_num if req.table_num is not None else next_tbl
    fwmark = req.fwmark if req.fwmark is not None else next_mrk
    listen_port = req.listen_port if req.listen_port is not None else get_next_listen_port()

    # Protocol parameters: use manual params if provided, otherwise generate
    if req.params:
        params = dict(req.params)
        # Normalize integer fields if passed as strings or ints
        for k in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"):
            if k in params and params[k] is not None:
                try:
                    params[k] = int(params[k])
                except (ValueError, TypeError):
                    pass
        # RandomTrailers normalization
        if "RandomTrailers" in params:
            rt = str(params["RandomTrailers"]).lower()
            params["RandomTrailers"] = 1 if rt in ("1", "true", "on", "yes") else 0
        # If AWG 3.1 and HeaderProtectionKey is missing, auto-generate it
        if req.protocol_version in ("3.0", "3.1") and not params.get("HeaderProtectionKey"):
            from app.awg_crypto import generate_header_protection_key
            params["HeaderProtectionKey"] = generate_header_protection_key()
    else:
        params = generate_awg_params(req.protocol_version)
    params["protocol_version"] = req.protocol_version

    # Keys
    priv, pub = generate_keypair()

    conn_id = create_connection(
        name=name,
        index_num=next_idx,
        protocol_version=req.protocol_version,
        x_subnet=req.x_subnet,
        listen_port=listen_port,
        server_private_key=priv,
        server_public_key=pub,
        xray_port=req.xray_port,
        table_num=table_num,
        fwmark=fwmark,
        params=params,
        server_id=req.server_id,
    )

    # Write config file and symlink
    write_server_config(conn_id)

    return {"status": "success", "id": conn_id, "name": name}


@app.get("/api/connections/{conn_id}/status")
async def api_get_connection_status(conn_id: int, request: Request):
    require_admin(request)
    status_data = get_interface_detailed_status(conn_id)
    if status_data.get("status") == "error":
        raise HTTPException(status_code=404, detail=status_data.get("detail", "Подключение не найдено"))
    return status_data


@app.post("/api/connections/{conn_id}/start")
async def api_start_connection(conn_id: int, request: Request):
    require_admin(request)
    ok, msg = start_connection(conn_id)
    if not ok:
        raise HTTPException(status_code=500, detail=msg)
    return {"status": "success", "message": msg}


@app.post("/api/connections/{conn_id}/stop")
async def api_stop_connection(conn_id: int, request: Request):
    require_admin(request)
    ok, msg = stop_connection(conn_id)
    if not ok:
        raise HTTPException(status_code=500, detail=msg)
    return {"status": "success", "message": msg}


@app.post("/api/connections/{conn_id}/restart")
async def api_restart_connection(conn_id: int, request: Request):
    require_admin(request)
    ok, msg = restart_connection(conn_id)
    if not ok:
        raise HTTPException(status_code=500, detail=msg)
    return {"status": "success", "message": msg}


@app.put("/api/connections/{conn_id}")
async def api_update_connection(conn_id: int, req: UpdateConnectionRequest, request: Request):
    require_admin(request)
    conn = get_connection_by_id(conn_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Подключение не найдено")

    listen_port = req.listen_port if req.listen_port is not None else conn["listen_port"]
    proto = req.protocol_version or conn.get("protocol_version", "1.0")

    current_params = dict(conn.get("params", {}))
    if req.params is not None:
        new_params = dict(req.params)
        # Normalize integer fields
        for k in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"):
            if k in new_params and new_params[k] is not None:
                try:
                    new_params[k] = int(new_params[k])
                except (ValueError, TypeError):
                    pass
        # RandomTrailers normalization
        if "RandomTrailers" in new_params:
            rt = str(new_params["RandomTrailers"]).lower()
            new_params["RandomTrailers"] = 1 if rt in ("1", "true", "on", "yes") else 0

        new_params["protocol_version"] = proto

        # If AWG 3.1 and HeaderProtectionKey is missing, auto-generate it
        if proto in ("3.0", "3.1") and not new_params.get("HeaderProtectionKey"):
            from app.awg_crypto import generate_header_protection_key
            new_params["HeaderProtectionKey"] = generate_header_protection_key()

        current_params = new_params
    else:
        current_params["protocol_version"] = proto

    # Update in database
    update_connection_params(conn_id, current_params, listen_port=listen_port, protocol_version=proto)

    # Re-write server config file
    write_server_config(conn_id)

    # If connection was active (or running), restart it
    restarted = False
    if conn.get("is_active"):
        restart_connection(conn_id)
        restarted = True

    updated_conn = get_connection_by_id(conn_id)
    return {
        "status": "success",
        "message": f"Параметры подключения {conn['name']} обновлены" + (" и интерфейс перезапущен" if restarted else ""),
        "connection": updated_conn,
        "restarted": restarted,
    }


@app.delete("/api/connections/{conn_id}")
async def api_delete_connection(conn_id: int, request: Request):
    require_admin(request)
    conn = get_connection_by_id(conn_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Подключение не найдено")

    name = conn["name"]
    # Stop interface if running
    stop_connection(conn_id)

    # Remove files and symlink
    remove_connection_files(name)

    # Delete from DB
    delete_connection(conn_id)

    return {"status": "success", "message": f"Подключение {name} удалено"}


@app.get("/api/connections/{conn_id}/config", response_class=PlainTextResponse)
async def api_get_server_config(conn_id: int, request: Request):
    require_admin(request)
    conn = get_connection_by_id(conn_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Подключение не найдено")
    return generate_server_config_text(conn_id)


# ----------------------------------------------------
# Users & Peers API Endpoints (Admin)
# ----------------------------------------------------
@app.get("/api/users")
async def api_list_users(request: Request):
    require_admin(request)
    users = get_all_users_with_peers()
    for u in users:
        u["has_password"] = bool(u.get("password_hash"))
        u.pop("password_hash", None)
    return users


@app.post("/api/users")
async def api_create_user(req: CreateUserRequest, request: Request):
    require_admin(request)
    conn = None
    if req.connection_id:
        conn = get_connection_by_id(req.connection_id)
        if not conn:
            raise HTTPException(status_code=404, detail="Подключение AWG не найдено")

    clean_user = req.username.strip()
    if not clean_user:
        raise HTTPException(status_code=400, detail="Имя пользователя не может быть пустым")

    admin_user = get_setting("admin_username", "admin")
    if clean_user.lower() == admin_user.lower():
        raise HTTPException(status_code=400, detail="Имя пользователя не может совпадать с логином администратора")

    if get_user_by_username(clean_user):
        raise HTTPException(status_code=400, detail=f"Пользователь с именем '{clean_user}' уже существует")

    pw_hash = ""
    if req.password and req.password.strip():
        if len(req.password.strip()) < 4:
            raise HTTPException(status_code=400, detail="Пароль должен быть не менее 4 символов")
        pw_hash = hash_password(req.password.strip())

    clean_tg = req.telegram_id.strip() if req.telegram_id and req.telegram_id.strip() else None
    if clean_tg:
        existing_tg = get_user_by_telegram_id(clean_tg)
        if existing_tg:
            raise HTTPException(status_code=400, detail=f"Пользователь с Telegram ID {clean_tg} уже привязан ({existing_tg['username']})")

    user_id = create_user(
        connection_id=req.connection_id,
        username=clean_user,
        notes=req.notes or "",
        password_hash=pw_hash,
        telegram_id=clean_tg,
    )
    user = get_user_by_id(user_id)
    subnet = f"10.{conn['x_subnet']}.{user['user_index_y']}.0/24" if conn else f"10.*.{user['user_index_y']}.0/24"
    return {
        "status": "success",
        "user_id": user_id,
        "username": user["username"],
        "user_index_y": user["user_index_y"],
        "subnet": subnet,
        "has_password": bool(pw_hash),
        "telegram_id": user.get("telegram_id"),
        "subscription_token": user.get("subscription_token"),
    }


@app.put("/api/users/{user_id}")
async def api_update_user(user_id: int, req: UpdateUserRequest, request: Request):
    require_admin(request)
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    if req.username:
        clean_user = req.username.strip()
        if not clean_user:
            raise HTTPException(status_code=400, detail="Имя пользователя не может быть пустым")
        existing = get_user_by_username(clean_user)
        if existing and existing["id"] != user_id:
            raise HTTPException(status_code=400, detail=f"Пользователь с именем '{clean_user}' уже существует")

    if req.telegram_id is not None:
        clean_tg = req.telegram_id.strip() if req.telegram_id.strip() else None
        if clean_tg:
            existing_tg = get_user_by_telegram_id(clean_tg)
            if existing_tg and existing_tg["id"] != user_id:
                raise HTTPException(status_code=400, detail=f"Telegram ID {clean_tg} уже привязан к '{existing_tg['username']}'")

    update_user_details(
        user_id=user_id,
        username=req.username,
        notes=req.notes,
        telegram_id=req.telegram_id,
    )
    if req.is_active is not None:
        update_user_status(user_id, req.is_active)

    return {"status": "success", "message": "Данные пользователя обновлены"}


@app.get("/api/users/{user_id}/export-zip")
async def api_user_export_zip(user_id: int, request: Request):
    auth = get_current_auth(request)
    if not auth:
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    if auth.get("role") != "admin" and auth.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Доступ запрещён")

    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    peers = get_user_peers(user_id)
    import io, zipfile
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
                logger.warning(f"Error creating conf in zip: {e}")
            try:
                vpn_dict, _ = generate_amnezia_vpn_data(p["id"])
                zf.writestr(f"{base_name}.vpn", json.dumps(vpn_dict, indent=2, ensure_ascii=False))
            except Exception as e:
                logger.warning(f"Error creating vpn in zip: {e}")

    bio.seek(0)
    filename = f"awg_{user['username']}_configs.zip"
    return Response(
        content=bio.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )



@app.post("/api/users/{user_id}/reset-password")
async def api_reset_user_password(user_id: int, req: ResetUserPasswordRequest, request: Request):
    require_admin(request)
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if len(req.password.strip()) < 4:
        raise HTTPException(status_code=400, detail="Пароль должен быть не менее 4 символов")
    update_user_password(user_id, hash_password(req.password.strip()))
    return {"status": "success", "message": f"Пароль пользователя {user['username']} успешно обновлен"}


@app.delete("/api/users/{user_id}")
async def api_delete_user(user_id: int, request: Request):
    require_admin(request)
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    peers = get_user_peers(user_id)
    conn_ids = set()
    for p in peers:
        conn_ids.add(p["connection_id"])
        try:
            remove_peer_from_node(p["id"])
        except Exception as e:
            logger.warning(f"Error removing peer {p['id']} from node: {e}")

    delete_user(user_id)

    # Re-sync server config on all affected connections
    for cid in conn_ids:
        try:
            sync_connection_peers(cid)
        except Exception as e:
            logger.warning(f"Error syncing connection {cid}: {e}")

    return {"status": "success", "message": f"Пользователь {user['username']} удален"}


@app.post("/api/peers")
async def api_create_peer(req: CreatePeerRequest, request: Request):
    require_admin(request)
    user = get_user_by_id(req.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    conn_id = req.connection_id or user.get("connection_id")
    conn = get_connection_by_id(conn_id) if conn_id else None
    if not conn:
        conns = get_all_connections()
        if conns:
            conn = conns[0]
        else:
            raise HTTPException(status_code=400, detail="Нет доступных подключений AWG")

    k = get_next_device_k(user["id"], conn["id"])
    if k > 254:
        raise HTTPException(status_code=400, detail="Превышен лимит устройств в подсети пользователя (макс. 254)")

    client_ip = f"10.{conn['x_subnet']}.{user['user_index_y']}.{k}"
    priv, pub = generate_keypair()
    psk = generate_preshared_key() if req.use_psk else None

    peer_id = create_peer(
        user_id=user["id"],
        connection_id=conn["id"],
        label=req.label.strip() or f"Устройство {k}",
        client_ip=client_ip,
        client_private_key=priv,
        client_public_key=pub,
        preshared_key=psk,
        device_index_k=k,
    )

    # Sync with target node
    sync_peer_to_node(peer_id)

    return {
        "status": "success",
        "peer_id": peer_id,
        "client_ip": client_ip,
        "label": req.label.strip() or f"Устройство {k}",
        "connection_id": conn["id"],
        "connection_name": conn["name"],
    }


@app.get("/api/peers/{peer_id}/config", response_class=PlainTextResponse)
async def api_get_peer_config(peer_id: int, request: Request):
    require_admin(request)
    peer = get_peer_by_id(peer_id)
    if not peer:
        raise HTTPException(status_code=404, detail="Конфигурация устройства не найдена")
    return generate_client_config_text(peer_id)


@app.get("/api/peers/{peer_id}/download")
async def api_download_peer_config(peer_id: int, request: Request):
    require_admin(request)
    peer = get_peer_by_id(peer_id)
    if not peer:
        raise HTTPException(status_code=404, detail="Конфигурация устройства не найдена")

    user = get_user_by_id(peer["user_id"])
    username = user["username"] if user else "user"
    clean_label = "".join(c for c in peer["label"] if c.isalnum() or c in ("-", "_")).strip() or "device"
    filename = f"{username}_{clean_label}.conf"

    content = generate_client_config_text(peer_id)
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/peers/{peer_id}/vpn")
async def api_download_peer_vpn(peer_id: int, request: Request):
    auth = get_current_auth(request)
    if not auth:
        raise HTTPException(status_code=401, detail="Требуется авторизация")

    peer = get_peer_by_id(peer_id)
    if not peer:
        raise HTTPException(status_code=404, detail="Конфигурация устройства не найдена")

    if auth.get("role") != "admin" and auth.get("user_id") != peer["user_id"]:
        raise HTTPException(status_code=403, detail="Доступ запрещён")

    user = get_user_by_id(peer["user_id"])
    conn = get_connection_by_id(peer["connection_id"]) or {}
    username = user["username"] if user else "user"
    clean_label = "".join(c for c in peer["label"] if c.isalnum() or c in ("-", "_")).strip() or "device"
    filename = f"{username}_{conn.get('name', 'awg')}_{clean_label}.vpn"

    vpn_dict, vpn_url = generate_amnezia_vpn_data(peer_id)
    return Response(
        content=json.dumps(vpn_dict, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Amnezia-VPN-Url": vpn_url,
        },
    )


@app.get("/api/peers/{peer_id}/vpn-url")
async def api_get_peer_vpn_url(peer_id: int, request: Request):
    auth = get_current_auth(request)
    if not auth:
        raise HTTPException(status_code=401, detail="Требуется авторизация")

    peer = get_peer_by_id(peer_id)
    if not peer:
        raise HTTPException(status_code=404, detail="Конфигурация устройства не найдена")

    if auth.get("role") != "admin" and auth.get("user_id") != peer["user_id"]:
        raise HTTPException(status_code=403, detail="Доступ запрещён")

    _, vpn_url = generate_amnezia_vpn_data(peer_id)
    return {"status": "ok", "vpn_url": vpn_url}



@app.post("/api/peers/{peer_id}/toggle")
async def api_toggle_peer(peer_id: int, request: Request):
    require_admin(request)
    peer = get_peer_by_id(peer_id)
    if not peer:
        raise HTTPException(status_code=404, detail="Конфиг не найден")

    new_state = toggle_peer(peer_id)
    sync_peer_to_node(peer_id)
    return {"status": "success", "is_enabled": new_state}


@app.delete("/api/peers/{peer_id}")
async def api_delete_peer(peer_id: int, request: Request):
    require_admin(request)
    remove_peer_from_node(peer_id)
    peer = delete_peer(peer_id)
    if not peer:
        raise HTTPException(status_code=404, detail="Конфиг не найден")

    return {"status": "success", "message": "Конфигурация удалена"}


# ----------------------------------------------------
# Client Portal API Endpoints (/api/my/*)
# ----------------------------------------------------
@app.get("/api/my/info")
async def api_my_info(request: Request):
    auth = require_auth(request)
    if auth.get("role") != "user":
        raise HTTPException(status_code=400, detail="Только для учетных записей пользователей")

    user = get_user_by_id(auth["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    peers = get_user_peers(user["id"])
    all_conns = get_all_connections()
    connections_list = []
    for c in all_conns:
        if c.get("is_active", 1):
            connections_list.append({
                "id": c["id"],
                "name": c["name"],
                "protocol_version": c.get("protocol_version", "3.1"),
                "server_name": c.get("server_name", "Основной сервер"),
                "server_host": c.get("server_host", ""),
                "subnet": f"10.{c['x_subnet']}.{user['user_index_y']}.0/24",
            })

    conn = get_connection_by_id(user["connection_id"]) if user.get("connection_id") else None
    if not conn and all_conns:
        conn = all_conns[0]

    server_name = conn.get("server_name", "Основной сервер") if conn else "Основной сервер"
    server_host = conn.get("server_host", "") if conn else detect_public_ip()
    subnet = f"10.{conn['x_subnet']}.{user['user_index_y']}.0/24" if conn else f"10.*.{user['user_index_y']}.0/24"

    return {
        "username": user["username"],
        "user_index_y": user["user_index_y"],
        "subnet": subnet,
        "connection_name": conn["name"] if conn else "AWG",
        "server_name": server_name,
        "protocol_version": conn.get("protocol_version", "3.1") if conn else "3.1",
        "server_host": server_host,
        "device_count": len(peers),
        "notes": user.get("notes", ""),
        "connections": connections_list,
    }


@app.get("/api/my/devices")
async def api_my_devices(request: Request):
    auth = require_auth(request)
    if auth.get("role") != "user":
        raise HTTPException(status_code=400, detail="Только для учетных записей пользователей")
    return get_user_peers(auth["user_id"])


@app.post("/api/my/devices")
async def api_my_create_device(req: UserCreateOwnDeviceRequest, request: Request):
    auth = require_auth(request)
    if auth.get("role") != "user":
        raise HTTPException(status_code=400, detail="Только для учетных записей пользователей")

    user = get_user_by_id(auth["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    conn_id = req.connection_id or user.get("connection_id")
    conn = get_connection_by_id(conn_id) if conn_id else None
    if not conn:
        conns = get_all_connections()
        if conns:
            conn = conns[0]
        else:
            raise HTTPException(status_code=400, detail="Нет доступных подключений AWG")

    k = get_next_device_k(user["id"], conn["id"])
    if k > 254:
        raise HTTPException(status_code=400, detail="Превышен лимит устройств (макс. 254)")

    label = req.label.strip() or f"Устройство {k}"
    client_ip = f"10.{conn['x_subnet']}.{user['user_index_y']}.{k}"
    priv, pub = generate_keypair()
    psk = generate_preshared_key() if req.use_psk else None

    peer_id = create_peer(
        user_id=user["id"],
        connection_id=conn["id"],
        label=label,
        client_ip=client_ip,
        client_private_key=priv,
        client_public_key=pub,
        preshared_key=psk,
        device_index_k=k,
    )

    sync_peer_to_node(peer_id)
    return {
        "status": "success",
        "peer_id": peer_id,
        "client_ip": client_ip,
        "label": label,
        "connection_id": conn["id"],
        "connection_name": conn["name"],
    }


@app.get("/api/my/devices/{peer_id}/config", response_class=PlainTextResponse)
async def api_my_device_config(peer_id: int, request: Request):
    auth = require_auth(request)
    peer = get_peer_by_id(peer_id)
    if not peer or peer["user_id"] != auth.get("user_id"):
        raise HTTPException(status_code=404, detail="Устройство не найдено")
    return generate_client_config_text(peer_id)


@app.get("/api/my/devices/{peer_id}/download")
async def api_my_device_download(peer_id: int, request: Request):
    auth = require_auth(request)
    peer = get_peer_by_id(peer_id)
    if not peer or peer["user_id"] != auth.get("user_id"):
        raise HTTPException(status_code=404, detail="Устройство не найдено")

    user = get_user_by_id(peer["user_id"])
    username = user["username"] if user else "user"
    clean_label = "".join(c for c in peer["label"] if c.isalnum() or c in ("-", "_")).strip() or "device"
    filename = f"{username}_{clean_label}.conf"

    content = generate_client_config_text(peer_id)
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/my/devices/{peer_id}/toggle")
async def api_my_device_toggle(peer_id: int, request: Request):
    auth = require_auth(request)
    peer = get_peer_by_id(peer_id)
    if not peer or peer["user_id"] != auth.get("user_id"):
        raise HTTPException(status_code=404, detail="Устройство не найдено")

    new_state = toggle_peer(peer_id)
    sync_peer_to_node(peer_id)
    return {"status": "success", "is_enabled": new_state}


@app.delete("/api/my/devices/{peer_id}")
async def api_my_device_delete(peer_id: int, request: Request):
    auth = require_auth(request)
    peer = get_peer_by_id(peer_id)
    if not peer or peer["user_id"] != auth.get("user_id"):
        raise HTTPException(status_code=404, detail="Устройство не найдено")

    remove_peer_from_node(peer_id)
    delete_peer(peer_id)
    return {"status": "success", "message": "Устройство удалено"}


@app.post("/api/my/change-password")
async def api_my_change_password(req: UserChangeOwnPasswordRequest, request: Request):
    auth = require_auth(request)
    if auth.get("role") != "user":
        raise HTTPException(status_code=400, detail="Только для учетных записей пользователей")

    user = get_user_by_id(auth["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    if not verify_password(req.old_password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Текущий пароль указан неверно")

    if len(req.new_password.strip()) < 4:
        raise HTTPException(status_code=400, detail="Новый пароль должен быть не менее 4 символов")

    update_user_password(user["id"], hash_password(req.new_password.strip()))
    return {"status": "success", "message": "Пароль успешно обновлен"}


# ----------------------------------------------------
# Settings & System API Endpoints (Admin)
# ----------------------------------------------------
@app.get("/api/settings")
async def api_get_settings(request: Request):
    require_admin(request)
    host = detect_public_ip()
    dns = get_setting("default_dns", DEFAULT_DNS)
    mtu = int(get_setting("default_mtu", str(DEFAULT_MTU)))
    tg_token = get_setting("tg_bot_token", "")
    tg_enabled = get_setting("tg_bot_enabled", "0")
    tg_proxy = get_setting("tg_bot_proxy", "http://127.0.0.1:1080")
    return {
        "server_host": host,
        "default_dns": dns,
        "default_mtu": mtu,
        "tg_bot_token": tg_token,
        "tg_bot_enabled": tg_enabled,
        "tg_bot_proxy": tg_proxy,
        "is_linux": IS_LINUX,
        "os_info": f"{platform.system()} {platform.release()}",
    }


@app.post("/api/settings")
async def api_update_settings(req: UpdateSettingsRequest, request: Request):
    require_admin(request)
    if req.server_host is not None:
        set_setting("server_host", req.server_host.strip())
    set_setting("default_dns", req.default_dns.strip())
    set_setting("default_mtu", str(req.default_mtu))
    if req.tg_bot_token is not None:
        set_setting("tg_bot_token", req.tg_bot_token.strip())
    if req.tg_bot_proxy is not None:
        set_setting("tg_bot_proxy", req.tg_bot_proxy.strip())
    if req.tg_bot_enabled is not None:
        set_setting("tg_bot_enabled", req.tg_bot_enabled.strip())
        if IS_LINUX:
            try:
                import subprocess
                if req.tg_bot_enabled.strip() == "1":
                    subprocess.run(["systemctl", "restart", "awg-bot"], check=False)
                else:
                    subprocess.run(["systemctl", "stop", "awg-bot"], check=False)
            except Exception:
                pass

    return {"status": "success", "message": "Настройки сохранены"}


# ----------------------------------------------------
# Telegram Bot Status & Testing API Endpoints
# ----------------------------------------------------
@app.get("/api/bot/status")
async def api_bot_status(request: Request):
    require_admin(request)
    token = get_setting("tg_bot_token", "").strip()
    enabled = get_setting("tg_bot_enabled", "0").strip() == "1"

    service_active = False
    if IS_LINUX:
        try:
            import subprocess
            r = subprocess.run(["systemctl", "is-active", "awg-bot"], capture_output=True, text=True)
            service_active = (r.stdout.strip() == "active")
        except Exception:
            service_active = False

    return {
        "has_token": bool(token),
        "is_enabled": enabled,
        "service_active": service_active,
    }


@app.post("/api/bot/test")
async def api_bot_test(request: Request):
    require_admin(request)
    body = await request.json()
    token = body.get("token", "").strip() or get_setting("tg_bot_token", "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="Токен Telegram-бота не задан")

    proxy = body.get("proxy", "").strip() or get_setting("tg_bot_proxy", "http://127.0.0.1:1080").strip()
    if proxy and not (proxy.startswith("http://") or proxy.startswith("https://") or proxy.startswith("socks5://") or proxy.startswith("socks5h://")):
        proxy = f"http://{proxy}"

    try:
        import httpx
        async with httpx.AsyncClient(proxy=proxy if proxy else None, timeout=10.0) as client:
            res = await client.get(f"https://api.telegram.org/bot{token}/getMe")
            data = res.json()
            if data.get("ok"):
                result = data.get("result", {})
                return {
                    "status": "ok",
                    "username": result.get("username"),
                    "first_name": result.get("first_name"),
                    "bot_id": result.get("id"),
                }
            return {"status": "error", "detail": data.get("description", "Неверный токен")}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


# ----------------------------------------------------
# Backup & Restore API Endpoints (Admin)
# ----------------------------------------------------
@app.get("/api/admin/backup")
async def api_admin_backup(request: Request):
    require_admin(request)
    from app.config import DB_PATH
    import datetime
    if not os.path.exists(DB_PATH):
        raise HTTPException(status_code=500, detail="Файл базы данных не найден")
    with open(DB_PATH, "rb") as f:
        data = f.read()
    now_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"awg_panel_backup_{now_str}.db"
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/admin/restore")
async def api_admin_restore(request: Request, file: UploadFile = File(...)):
    require_admin(request)
    from app.config import DB_PATH
    content = await file.read()
    if len(content) < 100 or not content.startswith(b"SQLite format 3\x00"):
        raise HTTPException(status_code=400, detail="Загруженный файл не является корректной базой данных SQLite")

    if os.path.exists(DB_PATH):
        shutil.copy2(DB_PATH, f"{DB_PATH}.bak")

    with open(DB_PATH, "wb") as f:
        f.write(content)

    init_db()
    init_auth()

    return {"status": "success", "message": "База данных успешно восстановлена из бэкапа"}


# ----------------------------------------------------
# Node Health & Monitoring API Endpoints
# ----------------------------------------------------
@app.get("/api/servers/{server_id}/health")
async def api_server_health(server_id: int, request: Request):
    require_admin(request)
    server = get_server_by_id(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Сервер не найден")
    client = NodeClient(server, timeout=5.0)
    health = client.check_health_with_latency()
    if health.get("status") == "online":
        update_server_status(server_id, "online")
    else:
        update_server_status(server_id, "offline")
    return health


@app.get("/api/servers/health-all")
async def api_servers_health_all(request: Request):
    require_admin(request)
    servers = get_all_servers()
    import asyncio

    async def check_one(srv):
        c = NodeClient(srv, timeout=4.0)
        h = await asyncio.to_thread(c.check_health_with_latency)
        if h.get("status") == "online":
            update_server_status(srv["id"], "online")
        else:
            update_server_status(srv["id"], "offline")
        return srv["id"], h

    results = await asyncio.gather(*(check_one(s) for s in servers))
    return {sid: res for sid, res in results}


# ----------------------------------------------------
# Subscription & Self-Service Portal Endpoints (/sub/*)
# ----------------------------------------------------
@app.get("/sub/{token}")
async def serve_subscription(token: str, request: Request, format: Optional[str] = None):
    user = get_user_by_sub_token(token)
    if not user:
        raise HTTPException(status_code=404, detail="Подписка не найдена или деактивирована")

    peers = get_user_peers(user["id"])
    accept_header = request.headers.get("accept", "").lower()
    user_agent = request.headers.get("user-agent", "").lower()

    is_browser = "text/html" in accept_header and not format
    if is_browser:
        sub_url = str(request.url).split("?")[0]
        for p in peers:
            try:
                _, vpn_url = generate_amnezia_vpn_data(p["id"])
                p["vpn_url"] = vpn_url
            except Exception:
                p["vpn_url"] = ""
        return templates.TemplateResponse(
            request=request,
            name="sub_portal.html",
            context={
                "user": user,
                "peers": peers,
                "sub_url": sub_url,
            },
        )

    if format == "sing-box" or "sing-box" in user_agent:
        outbounds = []
        for p in peers:
            try:
                conn = get_connection_by_id(p["connection_id"]) or {}
                server = get_server_by_id(conn.get("server_id", 1)) or {}
                host = server.get("host") or "127.0.0.1"
                params = conn.get("params", {})
                tag = f"{server.get('name', 'Server')} - {conn.get('name', 'AWG')}"
                outbound = {
                    "type": "amneziawg",
                    "tag": tag,
                    "server": host,
                    "server_port": conn.get("listen_port", 51820),
                    "local_address": [f"{p['client_ip']}/32"],
                    "private_key": p["client_private_key"],
                    "server_public_key": conn.get("server_public_key"),
                    "mtu": int(get_setting("default_mtu", "1200")),
                }
                for k in ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4"):
                    upper_k = k.capitalize() if k in ("jc", "jmin", "jmax") else k.upper()
                    if upper_k in params:
                        outbound[k] = params[upper_k]
                outbounds.append(outbound)
            except Exception:
                continue
        return JSONResponse(content={"outbounds": outbounds})

    # Base64 universal subscription
    import base64
    lines = []
    for p in peers:
        try:
            conn = get_connection_by_id(p["connection_id"]) or {}
            server = get_server_by_id(conn.get("server_id", 1)) or {}
            host = server.get("host") or "127.0.0.1"
            params = conn.get("params", {})
            tag = f"{server.get('name', 'Server')}_{conn.get('name', 'AWG')}".replace(" ", "_")

            query_parts = [
                f"address={p['client_ip']}/32",
                f"publickey={conn.get('server_public_key', '')}",
            ]
            if p.get("preshared_key"):
                query_parts.append(f"presharedkey={p['preshared_key']}")
            for k in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"):
                if k in params:
                    query_parts.append(f"{k.lower()}={params[k]}")

            uri = f"wireguard://{p['client_private_key']}@{host}:{conn.get('listen_port', 51820)}/?{'&'.join(query_parts)}#{tag}"
            lines.append(uri)
        except Exception:
            continue

    body = "\n".join(lines)
    if format == "raw":
        return PlainTextResponse(content=body, media_type="text/plain; charset=utf-8")

    b64_body = base64.b64encode(body.encode("utf-8")).decode("ascii")
    return Response(
        content=b64_body,
        media_type="text/plain; charset=utf-8",
        headers={
            "Subscription-Userinfo": "upload=0; download=0; total=107374182400; expire=0",
            "Profile-Update-Interval": "24",
        },
    )


@app.get("/sub/{token}/conf/{peer_id}")
async def serve_sub_conf(token: str, peer_id: int):
    user = get_user_by_sub_token(token)
    if not user:
        raise HTTPException(status_code=404, detail="Неверная ссылка подписки")
    peer = get_peer_by_id(peer_id)
    if not peer or peer["user_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Конфигурация не найдена")
    conn = get_connection_by_id(peer["connection_id"]) or {}
    filename = f"{user['username']}_{conn.get('name', 'awg')}_{peer.get('label', 'device')}.conf".replace(" ", "_")
    conf_text = generate_client_config_text(peer_id)
    return Response(
        content=conf_text,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/sub/{token}/vpn/{peer_id}")
async def serve_sub_vpn(token: str, peer_id: int):
    user = get_user_by_sub_token(token)
    if not user:
        raise HTTPException(status_code=404, detail="Неверная ссылка подписки")
    peer = get_peer_by_id(peer_id)
    if not peer or peer["user_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Конфигурация не найдена")
    conn = get_connection_by_id(peer["connection_id"]) or {}
    filename = f"{user['username']}_{conn.get('name', 'awg')}_{peer.get('label', 'device')}.vpn".replace(" ", "_")
    vpn_dict, vpn_url = generate_amnezia_vpn_data(peer_id)
    return Response(
        content=json.dumps(vpn_dict, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"', "X-Amnezia-VPN-Url": vpn_url},
    )


@app.get("/sub/{token}/export-zip")
async def serve_sub_zip(token: str):
    user = get_user_by_sub_token(token)
    if not user:
        raise HTTPException(status_code=404, detail="Неверная ссылка подписки")
    peers = get_user_peers(user["id"])
    import io, zipfile
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
            except Exception:
                pass
            try:
                vpn_dict, _ = generate_amnezia_vpn_data(p["id"])
                zf.writestr(f"{base_name}.vpn", json.dumps(vpn_dict, indent=2, ensure_ascii=False))
            except Exception:
                pass
    bio.seek(0)
    filename = f"awg_{user['username']}_configs.zip"
    return Response(
        content=bio.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )



@app.get("/api/system/status")
async def api_system_status(request: Request):
    require_admin(request)
    disk_total, disk_used, disk_free = shutil.disk_usage("/")
    return {
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "is_linux": IS_LINUX,
        "disk_free_gb": round(disk_free / (1024**3), 1),
        "disk_total_gb": round(disk_total / (1024**3), 1),
    }


if __name__ == "__main__":
    import uvicorn
    from app.config import HOST, PORT
    uvicorn.run(app, host=HOST, port=PORT)
