from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

from app.db.database import get_db
from app.db.models import UserModel, InterfaceModel, ClientConfigModel
from app.services.ip_allocator import IPAllocator
from app.services.awg_service import awg_service
from app.api.deps import get_current_admin

router = APIRouter(prefix="/users", tags=["users"])

class CreateUserRequest(BaseModel):
    username: str
    interface_name: str
    notes: Optional[str] = None

@router.get("", response_model=List[Dict[str, Any]])
async def list_users(
    interface: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(get_current_admin)
):
    query = select(UserModel).options(selectinload(UserModel.configs))
    if interface:
        query = query.where(UserModel.interface_name == interface)
    
    res = await db.execute(query)
    users = res.scalars().all()

    # Query active peers info from AWG to enrich configs
    rt_peers = {}
    for iface_name in {u.interface_name for u in users}:
        status = await awg_service.get_interface_status(iface_name)
        rt_peers.update(status.get("peers_data", {}))

    results = []
    for u in users:
        configs_data = []
        for c in u.configs:
            live = rt_peers.get(c.public_key, {})
            configs_data.append({
                "id": c.id,
                "label": c.label,
                "device_ip": c.device_ip,
                "public_key": c.public_key,
                "preshared_key": c.preshared_key,
                "is_active": c.is_active,
                "is_online": live.get("is_online", False),
                "rx_bytes": live.get("rx_bytes", c.rx_bytes),
                "tx_bytes": live.get("tx_bytes", c.tx_bytes),
                "latest_handshake": live.get("latest_handshake", 0),
                "created_at": c.created_at.isoformat() if c.created_at else None
            })

        results.append({
            "id": u.id,
            "username": u.username,
            "interface_name": u.interface_name,
            "subnet": u.subnet,
            "subnet_index": u.subnet_index,
            "notes": u.notes,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "configs": configs_data
        })

    return results

@router.post("", response_model=Dict[str, Any])
async def create_user(
    req: CreateUserRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(get_current_admin)
):
    # Verify interface exists in config files or DB
    cfg = awg_service.parse_interface_config(req.interface_name)
    if not cfg:
        raise HTTPException(status_code=400, detail=f"Interface {req.interface_name} not found")

    # Check if user with same name exists on this interface
    existing = await db.execute(
        select(UserModel).where(
            UserModel.interface_name == req.interface_name,
            UserModel.username == req.username
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail=f"User {req.username} already exists on interface {req.interface_name}")

    # Allocate next available /24 subnet for this user
    all_users_res = await db.execute(
        select(UserModel.subnet_index).where(UserModel.interface_name == req.interface_name)
    )
    used_indices = [row[0] for row in all_users_res.all()]

    try:
        idx, subnet_str = IPAllocator.allocate_user_subnet(used_indices, cfg.address)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    user = UserModel(
        username=req.username.strip(),
        interface_name=req.interface_name,
        subnet=subnet_str,
        subnet_index=idx,
        notes=req.notes
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return {
        "id": user.id,
        "username": user.username,
        "interface_name": user.interface_name,
        "subnet": user.subnet,
        "subnet_index": user.subnet_index,
        "notes": user.notes,
        "created_at": user.created_at.isoformat()
    }

@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(get_current_admin)
):
    res = await db.execute(
        select(UserModel).options(selectinload(UserModel.configs)).where(UserModel.id == user_id)
    )
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Remove all peers of this user from AWG conf and live interface
    for cfg in user.configs:
        try:
            await awg_service.remove_peer(user.interface_name, cfg.public_key)
        except Exception as e:
            pass

    await db.delete(user)
    await db.commit()
    return {"status": "success", "message": f"User {user.username} and all configs deleted."}
