"""AEGIS v2.0 Attack Lab Seeding Script.

Registers isolated vulnerable lab targets (lab-wordpress, lab-dvwa, juice-shop)
with is_lab=True, criticality=3, and environment='lab'.
Safe and idempotent to execute multiple times.
"""

import asyncio
import logging
import socket
from sqlalchemy import select

from app.db.session import AsyncSessionLocal
from app.models.user import User
from app.models.asset import Asset, AssetType, AssetEnvironment, TargetType

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("aegis.seed_lab")


def resolve_docker_host(hostname: str) -> str:
    """Attempt resolving container hostname via Docker internal DNS."""
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return "127.0.0.1"


async def seed_lab_targets():
    """Register lab targets in the asset inventory."""
    async with AsyncSessionLocal() as session:
        logger.info("[LAB SEED] Initializing AEGIS v2.0 Attack Lab assets...")

        # 1. Fetch admin user
        admin_stmt = select(User).where(User.email == "admin@aegis.internal")
        admin_user = (await session.execute(admin_stmt)).scalar_one_or_none()
        admin_id = admin_user.id if admin_user else None

        # 2. Lab Target Definitions
        lab_targets = [
            {
                "name": "lab-wordpress",
                "ip_address": "lab-wordpress",
                "hostname": "lab-wordpress",
                "asset_type": AssetType.web,
                "environment": AssetEnvironment.lab,
                "criticality": 3,
                "owner": "Lab Operations",
                "description": "Vulnerable WordPress 5.4 / PHP 7.2 Apache container target for attack simulation and verification.",
                "is_lab": True,
                "is_seed": True,
                "target_type": TargetType.domain,
            },
            {
                "name": "lab-dvwa",
                "ip_address": "lab-dvwa",
                "hostname": "lab-dvwa",
                "asset_type": AssetType.web,
                "environment": AssetEnvironment.lab,
                "criticality": 3,
                "owner": "Lab Operations",
                "description": "Damn Vulnerable Web Application (DVWA) container for web vulnerability auditing.",
                "is_lab": True,
                "is_seed": True,
                "target_type": TargetType.domain,
            },
        ]

        # 3. Seed / Update container targets
        for target_info in lab_targets:
            stmt = select(Asset).where(
                (Asset.name == target_info["name"]) | (Asset.ip_address == target_info["ip_address"])
            )
            existing = (await session.execute(stmt)).scalar_one_or_none()
            resolved_ip = resolve_docker_host(target_info["hostname"])

            if not existing:
                logger.info("[LAB SEED] Creating new lab asset: %s (resolved: %s)", target_info["name"], resolved_ip)
                asset = Asset(
                    name=target_info["name"],
                    ip_address=target_info["ip_address"],
                    hostname=target_info["hostname"],
                    resolved_ip=resolved_ip,
                    asset_type=target_info["asset_type"],
                    environment=target_info["environment"],
                    criticality=target_info["criticality"],
                    owner=target_info["owner"],
                    owner_id=admin_id,
                    description=target_info["description"],
                    is_lab=True,
                    is_seed=True,
                    target_type=target_info["target_type"],
                )
                session.add(asset)
            else:
                logger.info("[LAB SEED] Updating existing asset to lab target: %s", existing.name)
                existing.is_lab = True
                existing.environment = AssetEnvironment.lab
                existing.criticality = 3
                existing.resolved_ip = resolved_ip

        # 4. Update / Ensure OWASP Juice Shop as Lab Asset
        juice_stmt = select(Asset).where(
            (Asset.name.ilike("%juice%")) | (Asset.ip_address.in_(["172.20.0.5", "172.20.0.2", "aegis-juice-shop", "vulnerable-target"]))
        )
        juice_assets = (await session.execute(juice_stmt)).scalars().all()

        if juice_assets:
            for j in juice_assets:
                logger.info("[LAB SEED] Tagging Juice Shop asset #%s (%s) as lab target", j.id, j.name)
                j.is_lab = True
                j.environment = AssetEnvironment.lab
                j.criticality = 3
        else:
            logger.info("[LAB SEED] Creating default aegis-juice-shop lab asset...")
            juice_asset = Asset(
                name="aegis-juice-shop",
                ip_address="172.20.0.5",
                hostname="aegis-juice-shop",
                resolved_ip="172.20.0.5",
                asset_type=AssetType.web,
                environment=AssetEnvironment.lab,
                criticality=3,
                owner="Lab Operations",
                owner_id=admin_id,
                description="OWASP Juice Shop vulnerable target container for simulated exploit verification.",
                is_lab=True,
                is_seed=True,
                target_type=TargetType.ip,
            )
            session.add(juice_asset)

        await session.commit()
        logger.info("[LAB SEED] Lab asset registration completed successfully.")


def main():
    asyncio.run(seed_lab_targets())


if __name__ == "__main__":
    main()
