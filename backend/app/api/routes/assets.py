"""Asset management API routes for inventory tracking and CRUD operations."""

from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import asc, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin, require_analyst_or_admin
from app.db.session import get_db
from app.models.asset import Asset, AssetEnvironment, AssetType
from app.models.user import User
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
    # Check for duplicate IP address
    existing_ip_query = await db.execute(
        select(Asset).where(Asset.ip_address == asset_in.ip_address)
    )
    if existing_ip_query.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An asset with IP address '{asset_in.ip_address}' already exists.",
        )

    db_asset = Asset(
        name=asset_in.name,
        ip_address=asset_in.ip_address,
        hostname=asset_in.hostname,
        asset_type=asset_in.asset_type,
        environment=asset_in.environment,
        criticality=asset_in.criticality,
        owner=asset_in.owner or "Unassigned",
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
    """List network assets with searching, filtering, sorting, and pagination."""
    query = select(Asset)
    count_query = select(func.count(Asset.id))

    # Apply search filter
    if search:
        search_filter = or_(
            Asset.name.ilike(f"%{search}%"),
            Asset.ip_address.ilike(f"%{search}%"),
            Asset.hostname.ilike(f"%{search}%"),
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

    # Sorting
    sort_column = {
        "name": Asset.name,
        "criticality": Asset.criticality,
        "ip_address": Asset.ip_address,
        "created_at": Asset.created_at,
    }.get(sort_by, Asset.created_at)

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
    query = await db.execute(select(Asset).where(Asset.id == id))
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
        hostname=asset.hostname,
        asset_type=asset.asset_type,
        environment=asset.environment,
        criticality=asset.criticality,
        owner=asset.owner,
        description=asset.description,
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
    """Update an existing asset. Requires analyst or admin role."""
    query = await db.execute(select(Asset).where(Asset.id == id))
    asset = query.scalar_one_or_none()

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID {id} not found.",
        )

    # Check duplicate IP if IP is modified
    if asset_update.ip_address and asset_update.ip_address != asset.ip_address:
        duplicate_query = await db.execute(
            select(Asset).where(
                Asset.ip_address == asset_update.ip_address,
                Asset.id != id,
            )
        )
        if duplicate_query.scalar_one_or_none() is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"An asset with IP address '{asset_update.ip_address}' already exists.",
            )
        asset.ip_address = asset_update.ip_address

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


@router.delete("/{id}")
async def delete_asset(
    id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
) -> dict:
    """Delete an asset. Admin privileges strictly required."""
    query = await db.execute(select(Asset).where(Asset.id == id))
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
