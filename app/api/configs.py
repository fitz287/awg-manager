from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from pydantic import BaseModel
from typing import Optional, Dict, Any

from app.db.database import get_db
from app.db.models import UserModel, ClientConfigModel, InterfaceModel
from app.services.ip_allocator import IPAllocator
from app.services.key_generator import generate_key_pair, generate_preshared_key
from app.services.ip_detector import get_server_public_ip
from app.services.awg_service import awg_service
from app.services.qr_service import generate_qr_base64, generate_qr_png_bytes
from app.api.deps import get_current_admin

router = APIRouter(prefix="/configs", tags=["configs"])

class CreateConfigRequest(BaseModel):
    user_id: int
    label: str
    use_psk: bool = True

@router.post("", response_model=Dict[str, Any])
async def create_client_config(
    req: CreateConfigRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(get_current_admin)
):
    res = await db.execute(
        select(UserModel).options(selectinload(UserModel.configs)).where(UserModel.id == req.user_id)
    )
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Allocate IP within user's assigned subnet (e.g. 10.12.1.2)
    existing_ips = [c.device_ip for c in user.configs]
    try:
        device_ip = IPAllocator.allocate_device_ip(user.subnet, existing_ips)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Generate keys
    priv_key, pub_key = generate_key_pair()
    psk = generate_preshared_key() if req.use_psk else None

    # Hot-reload and persist to AWG interface config
    user_comment = f"{user.username} - {req.label.strip()}"
    try:
        await awg_service.add_peer(
            iface_name=user.interface_name,
            public_key=pub_key,
            device_ip=device_ip,
            preshared_key=psk,
            user_comment=user_comment
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to register peer in AmneziaWG: {e}")

    # Save to database
    config = ClientConfigModel(
        user_id=user.id,
        label=req.label.strip(),
        device_ip=device_ip,
        public_key=pub_key,
        private_key=priv_key,
        preshared_key=psk
    )
    db.add(config)
    await db.commit()
    await db.refresh(config)

    # Generate client config text and QR code
    server_public_ip = await get_server_public_ip()
    conf_content = awg_service.generate_client_config(
        iface_name=user.interface_name,
        client_private_key=priv_key,
        device_ip=device_ip,
        server_public_ip=server_public_ip,
        preshared_key=psk
    )
    qr_b64 = generate_qr_base64(conf_content)

    return {
        "id": config.id,
        "user_id": user.id,
        "username": user.username,
        "interface_name": user.interface_name,
        "label": config.label,
        "device_ip": config.device_ip,
        "public_key": config.public_key,
        "preshared_key": config.preshared_key,
        "created_at": config.created_at.isoformat(),
        "config_content": conf_content,
        "qr_base64": qr_b64
    }

@router.get("/{config_id}")
async def get_client_config_details(
    config_id: int,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(get_current_admin)
):
    res = await db.execute(
        select(ClientConfigModel).options(selectinload(ClientConfigModel.user)).where(ClientConfigModel.id == config_id)
    )
    cfg = res.scalar_one_or_none()
    if not cfg:
        raise HTTPException(status_code=404, detail="Config not found")

    server_public_ip = await get_server_public_ip()
    conf_content = awg_service.generate_client_config(
        iface_name=cfg.user.interface_name,
        client_private_key=cfg.private_key,
        device_ip=cfg.device_ip,
        server_public_ip=server_public_ip,
        preshared_key=cfg.preshared_key
    )
    qr_b64 = generate_qr_base64(conf_content)

    return {
        "id": cfg.id,
        "user_id": cfg.user.id,
        "username": cfg.user.username,
        "interface_name": cfg.user.interface_name,
        "label": cfg.label,
        "device_ip": cfg.device_ip,
        "public_key": cfg.public_key,
        "created_at": cfg.created_at.isoformat() if cfg.created_at else None,
        "config_content": conf_content,
        "qr_base64": qr_b64
    }

@router.get("/{config_id}/download")
async def download_client_config(
    config_id: int,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(get_current_admin)
):
    res = await db.execute(
        select(ClientConfigModel).options(selectinload(ClientConfigModel.user)).where(ClientConfigModel.id == config_id)
    )
    cfg = res.scalar_one_or_none()
    if not cfg:
        raise HTTPException(status_code=404, detail="Config not found")

    server_public_ip = await get_server_public_ip()
    conf_content = awg_service.generate_client_config(
        iface_name=cfg.user.interface_name,
        client_private_key=cfg.private_key,
        device_ip=cfg.device_ip,
        server_public_ip=server_public_ip,
        preshared_key=cfg.preshared_key
    )

    safe_label = "".join([c if c.isalnum() or c in "-_" else "_" for c in cfg.label])
    filename = f"{cfg.user.username}_{safe_label}_{cfg.user.interface_name}.conf"
    
    return Response(
        content=conf_content,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.get("/{config_id}/qr")
async def get_config_qr_image(
    config_id: int,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(get_current_admin)
):
    res = await db.execute(
        select(ClientConfigModel).options(selectinload(ClientConfigModel.user)).where(ClientConfigModel.id == config_id)
    )
    cfg = res.scalar_one_or_none()
    if not cfg:
        raise HTTPException(status_code=404, detail="Config not found")

    server_public_ip = await get_server_public_ip()
    conf_content = awg_service.generate_client_config(
        iface_name=cfg.user.interface_name,
        client_private_key=cfg.private_key,
        device_ip=cfg.device_ip,
        server_public_ip=server_public_ip,
        preshared_key=cfg.preshared_key
    )
    png_bytes = generate_qr_png_bytes(conf_content)
    return Response(content=png_bytes, media_type="image/png")

@router.delete("/{config_id}")
async def delete_client_config(
    config_id: int,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(get_current_admin)
):
    res = await db.execute(
        select(ClientConfigModel).options(selectinload(ClientConfigModel.user)).where(ClientConfigModel.id == config_id)
    )
    cfg = res.scalar_one_or_none()
    if not cfg:
        raise HTTPException(status_code=404, detail="Config not found")

    # Remove peer from AWG
    try:
        await awg_service.remove_peer(cfg.user.interface_name, cfg.public_key)
    except Exception as e:
        pass

    await db.delete(cfg)
    await db.commit()
    return {"status": "success", "message": f"Config {cfg.label} deleted"}
