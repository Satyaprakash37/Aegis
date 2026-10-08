"""Asset management API routes for inventory tracking and CRUD operations."""

from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import asc, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin, require_analyst_or_admin
from app.db.session import get_db
from app.models.asset import Asset, AssetEnvironment, AssetType, TargetType
from app.models.user import User
from app.services.scanner.target_resolver import resolve_target
from app.schemas.asset import (
    AssetCreate,
    AssetDetailRead,
    AssetListResponse,
    AssetRead,
    AssetUpdate,
    VulnSeverityCounts,
)

router = APIRouter(prefix="/assets", tags=["assets"])


@router.post("", response_model=AssetRead, status_code=status.HTTP_201_CREATED)
async def create_asset(
    asset_in: AssetCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst_or_admin)],
) -> Asset:
    """Create a new network asset. Requires analyst or admin role."""
    # Resolve target format (IPv4, domain name, or URL)
    resolution = resolve_target(asset_in.ip_address)
    if resolution["type"] == "invalid":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=resolution["error"],
        )

    cleaned_target = resolution["target"]
    resolved_ip = resolution["ip"] if resolution["type"] == "domain" else None
    effective_ip = resolution["ip"]
    target_type = TargetType.domain if resolution["type"] == "domain" else TargetType.ip

    # Check for duplicate IP or domain target for current user
    duplicate_conditions = [
        Asset.ip_address == cleaned_target,
        Asset.resolved_ip == cleaned_target,
    ]
    if resolved_ip:
        duplicate_conditions.extend([
            Asset.ip_address == resolved_ip,
            Asset.resolved_ip == resolved_ip,
        ])

    existing_query = await db.execute(
        select(Asset).where(
            Asset.owner_id == current_user.id,
            or_(*duplicate_conditions),
        )
    )
    existing_asset = existing_query.scalar_one_or_none()
    if existing_asset is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"An asset with target '{cleaned_target}' or IP '{effective_ip}' "
                f"already exists (Asset '{existing_asset.name}', ID: {existing_asset.id})."
            ),
        )

    db_asset = Asset(
        name=asset_in.name,
        ip_address=cleaned_target,
        target_type=target_type,
        resolved_ip=resolved_ip,
        hostname=asset_in.hostname or resolution["hostname"],
        asset_type=asset_in.asset_type,
        environment=asset_in.environment,
        criticality=asset_in.criticality,
        owner=asset_in.owner or current_user.full_name or current_user.email,
        owner_id=current_user.id,
        description=asset_in.description,
    )
    db.add(db_asset)
    await db.commit()
    await db.refresh(db_asset)
    return db_asset


@router.get("", response_model=AssetListResponse)
async def list_assets(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, description="Search term for name, IP, or hostname"),
    asset_type: Optional[AssetType] = Query(None, description="Filter by asset type"),
    environment: Optional[AssetEnvironment] = Query(None, description="Filter by environment"),
    criticality: Optional[int] = Query(None, ge=1, le=5, description="Filter by criticality (1-5)"),
    sort_by: Optional[str] = Query("created_at", description="Field to sort by: name, criticality, created_at, ip_address"),
    order: Optional[str] = Query("desc", description="Sort direction: asc or desc"),
) -> AssetListResponse:
    access_filter = or_(Asset.owner_id == current_user.id, Asset.is_seed == True)
    query = select(Asset).where(access_filter)
    count_query = select(func.count(Asset.id)).where(access_filter)

    # Apply search filter
    if search:
        search_filter = or_(
            Asset.name.ilike(f"%{search}%"),
            Asset.ip_address.ilike(f"%{search}%"),
            Asset.hostname.ilike(f"%{search}%"),
            Asset.resolved_ip.ilike(f"%{search}%"),
        )
        query = query.where(search_filter)
        count_query = count_query.where(search_filter)

    # Apply enum and attribute filters
    if asset_type:
        query = query.where(Asset.asset_type == asset_type)
        count_query = count_query.where(Asset.asset_type == asset_type)

    if environment:
        query = query.where(Asset.environment == environment)
        count_query = count_query.where(Asset.environment == environment)

    if criticality:
        query = query.where(Asset.criticality == criticality)
        count_query = count_query.where(Asset.criticality == criticality)

    # Dynamic sort column whitelist validation
    allowed_sort_fields = {
        "name": Asset.name,
        "criticality": Asset.criticality,
        "ip_address": Asset.ip_address,
        "created_at": Asset.created_at,
    }
    if sort_by and sort_by not in allowed_sort_fields:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid sort_by parameter '{sort_by}'. Allowed fields: {', '.join(sorted(allowed_sort_fields.keys()))}",
        )

    if order and order.lower() not in {"asc", "desc"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid order parameter '{order}'. Allowed values: 'asc', 'desc'",
        )

    sort_column = allowed_sort_fields.get(sort_by, Asset.created_at)
    order_fn = desc if order and order.lower() == "desc" else asc
    query = query.order_by(order_fn(sort_column))

    # Pagination
    total = (await db.execute(count_query)).scalar_one()
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    results = (await db.execute(query)).scalars().all()

    return AssetListResponse(
        data=list(results),
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{id}", response_model=AssetDetailRead)
async def get_asset(
    id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> AssetDetailRead:
    """Retrieve detailed information for a specific asset including vulnerability counts."""
    query = await db.execute(
        select(Asset).where(
            Asset.id == id,
            or_(Asset.owner_id == current_user.id, Asset.is_seed == True),
        )
    )
    asset = query.scalar_one_or_none()

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID {id} not found.",
        )

    # In Phase 3, vulnerability scanner is not connected yet, return structured zero counts
    counts = VulnSeverityCounts(
        critical=0,
        high=0,
        medium=0,
        low=0,
        none=0,
    )

    return AssetDetailRead(
        id=asset.id,
        name=asset.name,
        ip_address=asset.ip_address,
        target_type=asset.target_type,
        resolved_ip=asset.resolved_ip,
        hostname=asset.hostname,
        asset_type=asset.asset_type,
        environment=asset.environment,
        criticality=asset.criticality,
        owner=asset.owner,
        owner_id=asset.owner_id,
        description=asset.description,
        auto_created=asset.auto_created,
        is_seed=asset.is_seed,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
        vuln_counts=counts,
    )


@router.put("/{id}", response_model=AssetRead)
async def update_asset(
    id: int,
    asset_update: AssetUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst_or_admin)],
) -> Asset:
    """Update an existing asset. Requires analyst or admin role and asset ownership."""
    query = await db.execute(
        select(Asset).where(
            Asset.id == id,
            Asset.owner_id == current_user.id,
        )
    )
    asset = query.scalar_one_or_none()

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID {id} not found.",
        )

    # Check and resolve target if target/IP is modified
    if asset_update.ip_address is not None and asset_update.ip_address.strip():
        resolution = resolve_target(asset_update.ip_address)
        if resolution["type"] == "invalid":
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=resolution["error"],
            )

        cleaned_target = resolution["target"]
        resolved_ip = resolution["ip"] if resolution["type"] == "domain" else None
        effective_ip = resolution["ip"]
        target_type = TargetType.domain if resolution["type"] == "domain" else TargetType.ip

        if cleaned_target != asset.ip_address:
            duplicate_conditions = [
                Asset.ip_address == cleaned_target,
                Asset.resolved_ip == cleaned_target,
            ]
            if resolved_ip:
                duplicate_conditions.extend([
                    Asset.ip_address == resolved_ip,
                    Asset.resolved_ip == resolved_ip,
                ])

            duplicate_query = await db.execute(
                select(Asset).where(
                    Asset.owner_id == current_user.id,
                    or_(*duplicate_conditions),
                    Asset.id != id,
                )
            )
            existing_asset = duplicate_query.scalar_one_or_none()
            if existing_asset is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"An asset with target '{cleaned_target}' or IP '{effective_ip}' "
                        f"already exists (Asset '{existing_asset.name}', ID: {existing_asset.id})."
                    ),
                )
            asset.ip_address = cleaned_target
            asset.target_type = target_type
            asset.resolved_ip = resolved_ip
            if not asset.hostname and resolution["hostname"]:
                asset.hostname = resolution["hostname"]

    if asset_update.name is not None:
        asset.name = asset_update.name
    if asset_update.hostname is not None:
        asset.hostname = asset_update.hostname
    if asset_update.asset_type is not None:
        asset.asset_type = asset_update.asset_type
    if asset_update.environment is not None:
        asset.environment = asset_update.environment
    if asset_update.criticality is not None:
        asset.criticality = asset_update.criticality
    if asset_update.owner is not None:
        asset.owner = asset_update.owner
    if asset_update.description is not None:
        asset.description = asset_update.description

    await db.commit()
    await db.refresh(asset)
    return asset


@router.delete("/seed", status_code=status.HTTP_200_OK)
async def clear_demo_data(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
) -> dict:
    """Clear all seeded demo infrastructure assets and cascading findings. Admin only."""
    query = await db.execute(select(Asset).where(Asset.is_seed == True))
    seed_assets = query.scalars().all()

    count = len(seed_assets)
    for a in seed_assets:
        await db.delete(a)

    await db.commit()

    return {
        "data": {"deleted_count": count},
        "message": f"Successfully cleared {count} demo seed assets and associated findings.",
        "status": "success",
    }


@router.delete("/{id}")
async def delete_asset(
    id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst_or_admin)],
) -> dict:
    """Delete an asset. Must be owned by current user (or admin)."""
    stmt = select(Asset).where(Asset.id == id)
    if current_user.role == "admin":
        stmt = stmt.where(or_(Asset.owner_id == current_user.id, Asset.is_seed == False))
    else:
        stmt = stmt.where(Asset.owner_id == current_user.id)

    query = await db.execute(stmt)
    asset = query.scalar_one_or_none()

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID {id} not found.",
        )

    await db.delete(asset)
    await db.commit()

    return {
        "data": None,
        "message": f"Asset '{asset.name}' (ID: {id}) deleted successfully.",
        "status": "success",
    }
