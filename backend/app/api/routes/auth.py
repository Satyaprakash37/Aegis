"""Authentication API endpoints: register, login, and current user profile."""

from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.security import create_access_token, hash_password, verify_password
from app.db.session import get_db
from app.models.user import User, UserRole
from app.schemas.user import Token, UserCreate, UserRead

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register(
    user_in: UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """Register a new user. The first registered user is automatically granted Admin role."""
    # Check if user already exists
    existing_user_query = await db.execute(
        select(User).where(User.email == user_in.email)
    )
    if existing_user_query.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email address already exists",
        )

    # First user becomes admin, subsequent users default to analyst
    count_query = await db.execute(select(func.count(User.id)))
    total_users = count_query.scalar_one()
    assigned_role = UserRole.admin if total_users == 0 else UserRole.analyst

    db_user = User(
        email=user_in.email,
        password_hash=hash_password(user_in.password),
        full_name=user_in.full_name,
        role=assigned_role,
        is_active=True,
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user


@router.post("/login", response_model=Token)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Token:
    """Authenticate credentials and issue JWT bearer access token."""
    user_query = await db.execute(
        select(User).where(User.email == form_data.username)
    )
    user = user_query.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is deactivated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": str(user.id)})
    return Token(access_token=access_token, token_type="bearer")


@router.get("/me", response_model=UserRead)
async def get_me(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Retrieve details for currently authenticated user."""
    return current_user
