import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.config import DB_PATH, DEFAULT_DNS, DEFAULT_MTU


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            ssh_port INTEGER DEFAULT 22,
            ssh_user TEXT DEFAULT 'root',
            ssh_password TEXT DEFAULT '',
            ssh_key TEXT DEFAULT '',
            api_port INTEGER DEFAULT 8089,
            api_token TEXT NOT NULL,
            status TEXT DEFAULT 'pending',         -- pending, installing, online, offline, error
            is_active INTEGER DEFAULT 1,
            system_info_json TEXT DEFAULT '{}',
            install_log TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER DEFAULT 1 REFERENCES servers (id) ON DELETE CASCADE,
            name TEXT UNIQUE NOT NULL,             -- e.g. awg1, awg2
            index_num INTEGER UNIQUE NOT NULL,      -- e.g. 1, 2
            protocol_version TEXT NOT NULL,        -- 1.0, 2.0, 3.1
            x_subnet INTEGER NOT NULL,             -- x in 10.x.0.0
            listen_port INTEGER NOT NULL,          -- e.g. 51820
            server_private_key TEXT NOT NULL,
            server_public_key TEXT NOT NULL,
            xray_port INTEGER NOT NULL,            -- e.g. 7010
            table_num INTEGER UNIQUE NOT NULL,     -- e.g. 101, 102
            fwmark INTEGER UNIQUE NOT NULL,        -- e.g. 1, 2, 3
            params_json TEXT NOT NULL,             -- Jc, Jmin, S1, H1..
            is_active INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            connection_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            user_index_y INTEGER NOT NULL,         -- y in 10.x.y.0
            notes TEXT DEFAULT '',
            password_hash TEXT DEFAULT '',
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY (connection_id) REFERENCES connections (id) ON DELETE CASCADE,
            UNIQUE(connection_id, user_index_y)
        );

        CREATE TABLE IF NOT EXISTS peer_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            connection_id INTEGER NOT NULL,
            device_index_k INTEGER NOT NULL,       -- k in 10.x.y.k
            label TEXT NOT NULL,                   -- e.g. iPhone, Laptop
            client_ip TEXT NOT NULL,               -- 10.x.y.k
            client_private_key TEXT NOT NULL,
            client_public_key TEXT NOT NULL,
            preshared_key TEXT,
            is_enabled INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (connection_id) REFERENCES connections (id) ON DELETE CASCADE,
            UNIQUE(user_id, device_index_k)
        );
        """)

        # Auto-migrate users table if columns are missing
        user_cols = [col["name"] for col in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "password_hash" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT DEFAULT ''")
        if "is_active" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1")

        # Auto-migrate connections table if server_id is missing
        conn_cols = [col["name"] for col in conn.execute("PRAGMA table_info(connections)").fetchall()]
        if "server_id" not in conn_cols:
            conn.execute("ALTER TABLE connections ADD COLUMN server_id INTEGER DEFAULT 1")

        # Default settings
        cur = conn.cursor()
        cur.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('default_dns', ?)", (DEFAULT_DNS,))
        cur.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('default_mtu', ?)", (str(DEFAULT_MTU),))
        cur.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('server_host', '')")

        # Ensure at least one default server exists if table is empty
        server_count = conn.execute("SELECT COUNT(*) FROM servers").fetchone()[0]
        if server_count == 0:
            import secrets
            cur.execute("""
                INSERT INTO servers (id, name, host, ssh_port, ssh_user, ssh_password, api_port, api_token, status, created_at)
                VALUES (1, 'Швеция #1 (94.103.2.133)', '94.103.2.133', 98, 'root', 'MGWnbc1yg7', 8089, ?, 'online', datetime('now'))
            """, (secrets.token_hex(32),))


# Settings Helpers
def get_setting(key: str, default: str = "") -> str:
    with get_db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with get_db() as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


# Server Helpers
def create_server(
    name: str,
    host: str,
    ssh_port: int = 22,
    ssh_user: str = "root",
    ssh_password: str = "",
    ssh_key: str = "",
    api_port: int = 8089,
    api_token: str = "",
    status: str = "pending",
) -> int:
    import secrets
    if not api_token:
        api_token = secrets.token_hex(32)
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO servers (
                name, host, ssh_port, ssh_user, ssh_password, ssh_key,
                api_port, api_token, status, is_active, system_info_json, install_log, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, '{}', '', ?)
            """,
            (
                name.strip(),
                host.strip(),
                ssh_port,
                ssh_user.strip(),
                ssh_password,
                ssh_key,
                api_port,
                api_token,
                status,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        return cur.lastrowid


def get_all_servers() -> List[Dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM servers ORDER BY id ASC").fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["connections_count"] = conn.execute(
                "SELECT COUNT(*) FROM connections WHERE server_id = ?", (d["id"],)
            ).fetchone()[0]
            try:
                d["system_info"] = json.loads(d["system_info_json"]) if d["system_info_json"] else {}
            except Exception:
                d["system_info"] = {}
            d["has_password"] = bool(d.get("ssh_password"))
            d["has_key"] = bool(d.get("ssh_key"))
            result.append(d)
        return result


def get_server_by_id(server_id: int) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["system_info"] = json.loads(d["system_info_json"]) if d["system_info_json"] else {}
        except Exception:
            d["system_info"] = {}
        d["has_password"] = bool(d.get("ssh_password"))
        d["has_key"] = bool(d.get("ssh_key"))
        return d


def get_server_by_host(host: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM servers WHERE host = ?", (host.strip(),)).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["system_info"] = json.loads(d["system_info_json"]) if d["system_info_json"] else {}
        except Exception:
            d["system_info"] = {}
        return d


def update_server_status(server_id: int, status: str) -> None:
    with get_db() as conn:
        conn.execute("UPDATE servers SET status = ? WHERE id = ?", (status, server_id))


def update_server_system_info(server_id: int, system_info: Dict[str, Any]) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE servers SET system_info_json = ?, status = 'online' WHERE id = ?",
            (json.dumps(system_info), server_id),
        )


def append_server_install_log(server_id: int, chunk: str) -> None:
    with get_db() as conn:
        row = conn.execute("SELECT install_log FROM servers WHERE id = ?", (server_id,)).fetchone()
        existing = row["install_log"] if row and row["install_log"] else ""
        updated = (existing + "\n" + chunk).strip()
        if len(updated) > 50000:
            updated = updated[-50000:]
        conn.execute("UPDATE servers SET install_log = ? WHERE id = ?", (updated, server_id))


def get_server_install_log(server_id: int) -> str:
    with get_db() as conn:
        row = conn.execute("SELECT install_log FROM servers WHERE id = ?", (server_id,)).fetchone()
        return row["install_log"] if row and row["install_log"] else ""


def update_server(
    server_id: int,
    name: str,
    host: str,
    ssh_port: int,
    ssh_user: str,
    ssh_password: Optional[str] = None,
    ssh_key: Optional[str] = None,
    api_port: int = 8089,
) -> None:
    with get_db() as conn:
        if ssh_password is not None and ssh_key is not None:
            conn.execute(
                """UPDATE servers SET name = ?, host = ?, ssh_port = ?, ssh_user = ?,
                   ssh_password = ?, ssh_key = ?, api_port = ? WHERE id = ?""",
                (name.strip(), host.strip(), ssh_port, ssh_user.strip(), ssh_password, ssh_key, api_port, server_id),
            )
        elif ssh_password is not None:
            conn.execute(
                """UPDATE servers SET name = ?, host = ?, ssh_port = ?, ssh_user = ?,
                   ssh_password = ?, api_port = ? WHERE id = ?""",
                (name.strip(), host.strip(), ssh_port, ssh_user.strip(), ssh_password, api_port, server_id),
            )
        else:
            conn.execute(
                """UPDATE servers SET name = ?, host = ?, ssh_port = ?, ssh_user = ?,
                   api_port = ? WHERE id = ?""",
                (name.strip(), host.strip(), ssh_port, ssh_user.strip(), api_port, server_id),
            )


def delete_server(server_id: int) -> bool:
    with get_db() as conn:
        count = conn.execute("SELECT COUNT(*) FROM connections WHERE server_id = ?", (server_id,)).fetchone()[0]
        if count > 0:
            return False
        conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))
        return True


# Connection Helpers
def get_all_connections() -> List[Dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute("""
            SELECT c.*, s.name as server_name, s.host as server_host, s.status as server_status
            FROM connections c
            LEFT JOIN servers s ON c.server_id = s.id
            ORDER BY c.index_num ASC
        """).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["params"] = json.loads(d["params_json"])
            # Peer and user count
            uc = conn.execute("SELECT COUNT(*) FROM users WHERE connection_id = ?", (d["id"],)).fetchone()[0]
            pc = conn.execute("SELECT COUNT(*) FROM peer_configs WHERE connection_id = ?", (d["id"],)).fetchone()[0]
            d["user_count"] = uc
            d["peer_count"] = pc
            result.append(d)
        return result


def get_connection_by_id(conn_id: int) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        row = conn.execute("""
            SELECT c.*, s.name as server_name, s.host as server_host, s.status as server_status
            FROM connections c
            LEFT JOIN servers s ON c.server_id = s.id
            WHERE c.id = ?
        """, (conn_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["params"] = json.loads(d["params_json"])
        return d


def get_connection_by_name(name: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        row = conn.execute("""
            SELECT c.*, s.name as server_name, s.host as server_host, s.status as server_status
            FROM connections c
            LEFT JOIN servers s ON c.server_id = s.id
            WHERE c.name = ?
        """, (name,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["params"] = json.loads(d["params_json"])
        return d


def get_connections_by_server(server_id: int) -> List[Dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM connections WHERE server_id = ? ORDER BY index_num ASC", (server_id,)).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["params"] = json.loads(d["params_json"])
            result.append(d)
        return result


def get_next_connection_index() -> int:
    with get_db() as conn:
        row = conn.execute("SELECT MAX(index_num) as max_idx FROM connections").fetchone()
        if row and row["max_idx"] is not None:
            return row["max_idx"] + 1
        return 1


def get_next_table_and_mark() -> Tuple[int, int]:
    """
    Returns (next_table, next_mark).
    Tables start at 101 (101, 102, 103...).
    Marks start at 1 (1, 2, 3...).
    """
    with get_db() as conn:
        row_table = conn.execute("SELECT MAX(table_num) as max_tbl FROM connections").fetchone()
        row_mark = conn.execute("SELECT MAX(fwmark) as max_mrk FROM connections").fetchone()

        max_tbl = row_table["max_tbl"] if row_table and row_table["max_tbl"] is not None else 100
        max_mrk = row_mark["max_mrk"] if row_mark and row_mark["max_mrk"] is not None else 0

        next_tbl = max(101, max_tbl + 1)
        next_mrk = max(1, max_mrk + 1)
        return next_tbl, next_mrk


def get_next_listen_port() -> int:
    with get_db() as conn:
        row = conn.execute("SELECT MAX(listen_port) as max_port FROM connections").fetchone()
        if row and row["max_port"] is not None:
            return row["max_port"] + 1
        return 51820


def create_connection(
    name: str,
    index_num: int,
    protocol_version: str,
    x_subnet: int,
    listen_port: int,
    server_private_key: str,
    server_public_key: str,
    xray_port: int,
    table_num: int,
    fwmark: int,
    params: Dict[str, Any],
    server_id: int = 1,
) -> int:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO connections (
                server_id, name, index_num, protocol_version, x_subnet, listen_port,
                server_private_key, server_public_key, xray_port, table_num,
                fwmark, params_json, is_active, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
            """,
            (
                server_id,
                name,
                index_num,
                protocol_version,
                x_subnet,
                listen_port,
                server_private_key,
                server_public_key,
                xray_port,
                table_num,
                fwmark,
                json.dumps(params),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        return cur.lastrowid


def update_connection_status(conn_id: int, is_active: bool) -> None:
    with get_db() as conn:
        conn.execute("UPDATE connections SET is_active = ? WHERE id = ?", (1 if is_active else 0, conn_id))


def delete_connection(conn_id: int) -> Optional[str]:
    with get_db() as conn:
        row = conn.execute("SELECT name FROM connections WHERE id = ?", (conn_id,)).fetchone()
        if row:
            name = row["name"]
            conn.execute("DELETE FROM connections WHERE id = ?", (conn_id,))
            return name
        return None


# User Helpers
def get_users_by_connection(connection_id: int) -> List[Dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM users WHERE connection_id = ? ORDER BY user_index_y ASC",
            (connection_id,),
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            peers = conn.execute(
                "SELECT * FROM peer_configs WHERE user_id = ? ORDER BY device_index_k ASC",
                (d["id"],),
            ).fetchall()
            d["peers"] = [dict(p) for p in peers]
            result.append(d)
        return result


def get_all_users_with_peers() -> List[Dict[str, Any]]:
    with get_db() as conn:
        users = conn.execute(
            """
            SELECT u.*, COALESCE(c.name, 'Все подключения') as connection_name,
                   COALESCE(c.x_subnet, 0) as x_subnet,
                   COALESCE(c.protocol_version, '3.1') as protocol_version
            FROM users u
            LEFT JOIN connections c ON u.connection_id = c.id
            ORDER BY u.user_index_y ASC
            """
        ).fetchall()

        result = []
        for u in users:
            d = dict(u)
            peers = conn.execute(
                """
                SELECT p.*, c.name as connection_name, c.protocol_version,
                       COALESCE(s.name, 'Основной сервер') as server_name,
                       COALESCE(s.host, '') as server_host
                FROM peer_configs p
                JOIN connections c ON p.connection_id = c.id
                LEFT JOIN servers s ON c.server_id = s.id
                WHERE p.user_id = ?
                ORDER BY p.device_index_k ASC
                """,
                (d["id"],),
            ).fetchall()
            d["peers"] = [dict(p) for p in peers]
            result.append(d)
        return result


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username.strip(),)).fetchone()
        return dict(row) if row else None


def get_user_peers(user_id: int) -> List[Dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT p.*, c.name as connection_name, c.protocol_version,
                   COALESCE(s.name, 'Основной сервер') as server_name,
                   COALESCE(s.host, '') as server_host
            FROM peer_configs p
            JOIN connections c ON p.connection_id = c.id
            LEFT JOIN servers s ON c.server_id = s.id
            WHERE p.user_id = ?
            ORDER BY p.id ASC
            """,
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_next_user_y(connection_id: Optional[int] = None) -> int:
    with get_db() as conn:
        row = conn.execute("SELECT MAX(user_index_y) as max_y FROM users").fetchone()
        if row and row["max_y"] is not None:
            return row["max_y"] + 1
        return 1


def create_user(
    connection_id_or_user: Any = None,
    username: Optional[str] = None,
    notes: str = "",
    password_hash: str = "",
    connection_id: Optional[int] = None,
    **kwargs,
) -> int:
    """
    Creates user globally. Supports:
    - create_user(username, notes, password_hash)
    - create_user(connection_id, username, notes, password_hash)
    - create_user(connection_id, username="name", ...)
    - create_user(username="name", connection_id=..., ...)
    """
    conn_id = connection_id
    uname = username

    if isinstance(connection_id_or_user, int):
        conn_id = connection_id_or_user
    elif isinstance(connection_id_or_user, str) and not uname:
        uname = connection_id_or_user

    if not uname and "user" in kwargs:
        uname = kwargs["user"]

    if not uname:
        raise ValueError("Имя пользователя не указано")

    y = get_next_user_y()
    with get_db() as conn:
        if not conn_id:
            row = conn.execute("SELECT id FROM connections ORDER BY id ASC LIMIT 1").fetchone()
            conn_id = row["id"] if row else 1

        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO users (connection_id, username, user_index_y, notes, password_hash, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, 1, ?)
            """,
            (conn_id, uname.strip(), y, notes.strip(), password_hash, datetime.now(timezone.utc).isoformat()),
        )
        return cur.lastrowid


def update_user_password(user_id: int, password_hash: str) -> None:
    with get_db() as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))


def update_user_status(user_id: int, is_active: bool) -> None:
    with get_db() as conn:
        conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (1 if is_active else 0, user_id))


def delete_user(user_id: int) -> None:
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


# Peer Helpers
def get_next_device_k(user_id: int) -> int:
    with get_db() as conn:
        row = conn.execute(
            "SELECT MAX(device_index_k) as max_k FROM peer_configs WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        if row and row["max_k"] is not None:
            return row["max_k"] + 1
        return 1


def create_peer(
    user_id: int,
    connection_id: int,
    label: str,
    client_ip: str,
    client_private_key: str,
    client_public_key: str,
    preshared_key: Optional[str] = None,
) -> int:
    k = get_next_device_k(user_id)
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO peer_configs (
                user_id, connection_id, device_index_k, label, client_ip,
                client_private_key, client_public_key, preshared_key, is_enabled, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
            """,
            (
                user_id,
                connection_id,
                k,
                label,
                client_ip,
                client_private_key,
                client_public_key,
                preshared_key,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        return cur.lastrowid


def get_peer_by_id(peer_id: int) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM peer_configs WHERE id = ?", (peer_id,)).fetchone()
        return dict(row) if row else None


def get_peers_by_connection(connection_id: int) -> List[Dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM peer_configs WHERE connection_id = ? AND is_enabled = 1 ORDER BY client_ip ASC",
            (connection_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def delete_peer(peer_id: int) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM peer_configs WHERE id = ?", (peer_id,)).fetchone()
        if row:
            peer = dict(row)
            conn.execute("DELETE FROM peer_configs WHERE id = ?", (peer_id,))
            return peer
        return None


def toggle_peer(peer_id: int) -> Optional[bool]:
    with get_db() as conn:
        row = conn.execute("SELECT is_enabled FROM peer_configs WHERE id = ?", (peer_id,)).fetchone()
        if row:
            new_state = 0 if row["is_enabled"] else 1
            conn.execute("UPDATE peer_configs SET is_enabled = ? WHERE id = ?", (new_state, peer_id))
            return bool(new_state)
        return None
