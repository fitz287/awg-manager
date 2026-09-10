from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Dict, Any

from app.db.database import get_db
from app.db.models import InterfaceModel, UserModel, ClientConfigModel
from app.services.awg_service import awg_service
from app.api.deps import get_current_admin

router = APIRouter(prefix="/interfaces", tags=["interfaces"])

@router.get("", response_model=List[Dict[str, Any]])
async def list_interfaces(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(get_current_admin)
):
    """
    Returns all detected interfaces from /etc/amnezia/amneziawg/ synced with DB state.
    """
    conf_files = awg_service.list_interface_files()
    results = []

    for f in conf_files:
        name = f.replace(".conf", "")
        cfg = awg_service.parse_interface_config(name)
        if not cfg:
            continue

        # Sync interface in DB
        res = await db.execute(select(InterfaceModel).where(InterfaceModel.name == name))
        db_iface = res.scalar_one_or_none()
        if not db_iface:
            db_iface = InterfaceModel(
                name=name,
                address=cfg.address,
                listen_port=cfg.listen_port,
                public_key=cfg.public_key,
                protocol_version=cfg.protocol_version,
                is_active=True
            )
            db.add(db_iface)
            await db.commit()
            await db.refresh(db_iface)
        else:
            # Update fields in case config file was modified
            db_iface.address = cfg.address
            db_iface.listen_port = cfg.listen_port
            db_iface.public_key = cfg.public_key
            db_iface.protocol_version = cfg.protocol_version
            await db.commit()

        # Get runtime status
        rt_status = await awg_service.get_interface_status(name)

        # Count users in DB for this interface
        users_count_res = await db.execute(select(UserModel).where(UserModel.interface_name == name))
        users_count = len(users_count_res.scalars().all())

        results.append({
            "name": name,
            "address": cfg.address,
            "listen_port": cfg.listen_port,
            "public_key": cfg.public_key,
            "protocol_version": cfg.protocol_version,
            "obfuscation_params": cfg.obfuscation_params,
            "is_active": rt_status["is_active"],
            "users_count": users_count,
            "peers_count": rt_status["peers_count"],
            "peers_online": rt_status["peers_online"],
            "total_rx": rt_status["total_rx"],
            "total_tx": rt_status["total_tx"]
        })

    return results

@router.post("/{name}/start")
async def start_interface(
    name: str,
    _: str = Depends(get_current_admin)
):
    success, msg = await awg_service.start_interface(name)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "success", "message": msg}

@router.post("/{name}/stop")
async def stop_interface(
    name: str,
    _: str = Depends(get_current_admin)
):
    success, msg = await awg_service.stop_interface(name)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "success", "message": msg}
