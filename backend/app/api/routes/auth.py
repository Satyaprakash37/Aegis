"""Authentication API endpoints: register, login, and current user profile with security hardening."""

from datetime import datetime, timedelta, timezone
from typing import Annotated, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.limiter import limiter
from app.core.security import create_access_token, hash_password, verify_password
from app.db.session import get_db
from app.models.user import User, UserRole
from app.schemas.user import Token, UserCreate, UserRead

router = APIRouter(prefix="/auth", tags=["auth"])

# In-memory account lockout tracker: email -> {"attempts": int, "locked_until": datetime}
FAILED_LOGINS: Dict[str, Dict[str, Any]] = {}
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/hour")
async def register(
    request: Request,
    user_in: UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """Register a new user. The first registered user is automatically granted Admin role."""
    normalized_email = user_in.email.strip().lower()

    # Check if user already exists (anti-enumeration: generic error message)
    existing_user_query = await db.execute(
        select(User).where(User.email == normalized_email)
    )
    if existing_user_query.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to complete registration with the provided credentials. Please verify your information or proceed to sign in.",
        )

    # First user becomes admin, subsequent users default to analyst
    count_query = await db.execute(select(func.count(User.id)))
    total_users = count_query.scalar_one()
    assigned_role = UserRole.admin if total_users == 0 else UserRole.analyst

    db_user = User(
        email=normalized_email,
        password_hash=hash_password(user_in.password),
        full_name=user_in.full_name.strip(),
        role=assigned_role,
        is_active=True,
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user


@router.post("/login", response_model=Token)
@limiter.limit("10/minute")
async def login(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Token:
    """Authenticate credentials and issue JWT bearer access token with brute-force lockout."""
    email = form_data.username.strip().lower()
    now = datetime.now(timezone.utc)

    # 1. Check Account Lockout Status
    lockout_record = FAILED_LOGINS.get(email)
    if lockout_record and lockout_record.get("locked_until"):
        if now < lockout_record["locked_until"]:
            remaining_secs = int((lockout_record["locked_until"] - now).total_seconds())
            remaining_mins = max(1, (remaining_secs + 59) // 60)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is temporarily locked due to 5 consecutive failed login attempts. Try again in {remaining_mins} minutes.",
            )
        else:
            # Lockout period expired: reset tracker
            FAILED_LOGINS.pop(email, None)

    # 2. Query User
    user_query = await db.execute(select(User).where(User.email == email))
    user = user_query.scalar_one_or_none()

    # 3. Verify Password
    if not user or not verify_password(form_data.password, user.password_hash):
        record = FAILED_LOGINS.setdefault(email, {"attempts": 0, "locked_until": None})
        record["attempts"] += 1

        if record["attempts"] >= MAX_FAILED_ATTEMPTS:
            record["locked_until"] = now + LOCKOUT_DURATION
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account locked due to 5 consecutive failed login attempts. Please try again in 15 minutes.",
            )

        attempts_left = MAX_FAILED_ATTEMPTS - record["attempts"]
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Incorrect email or password. {attempts_left} attempt(s) remaining before account lockout.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. Check If Active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is deactivated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 5. Successful Login: Clear any failed attempts
    FAILED_LOGINS.pop(email, None)

    access_token = create_access_token(data={"sub": str(user.id)})
    return Token(access_token=access_token, token_type="bearer")


@router.get("/me", response_model=UserRead)
async def get_me(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Retrieve details for currently authenticated user."""
    return current_user
