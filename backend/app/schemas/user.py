"""Pydantic schemas for User entity and authentication tokens."""

import re
from datetime import datetime
from typing import Optional, Set
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator
from app.models.user import UserRole

# Common disposable email domain blocklist (~20 common services)
DISPOSABLE_EMAIL_DOMAINS: Set[str] = {
    "10minutemail.com",
    "tempmail.com",
    "guerrillamail.com",
    "mailinator.com",
    "throwawaymail.com",
    "sharklasers.com",
    "yopmail.com",
    "dispostable.com",
    "getairmail.com",
    "mohmal.com",
    "trashmail.com",
    "temp-mail.org",
    "fakeinbox.com",
    "maildrop.cc",
    "inboxkitten.com",
    "mytemp.email",
    "burnermail.io",
    "trashmail.net",
    "dropmail.me",
    "nada.ltd",
}

# Common weak password patterns
COMMON_WEAK_PATTERNS = ["password", "qwerty", "admin123", "welcome", "letmein", "123456"]


class UserBase(BaseModel):
    email: EmailStr
    full_name: str = Field(..., min_length=1, max_length=100)
    role: UserRole = UserRole.analyst
    is_active: bool = True

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        if isinstance(v, str):
            v = v.strip().lower()
        return v


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=12, max_length=128, description="Password must be 12-128 characters with upper, lower, digit, and special char")
    full_name: str = Field(..., min_length=1, max_length=100)

    @field_validator("email", mode="before")
    @classmethod
    def validate_and_normalize_email(cls, v: str) -> str:
        if isinstance(v, str):
            v = v.strip().lower()
            if "@" in v:
                domain = v.split("@", 1)[1].strip()
                if domain in DISPOSABLE_EMAIL_DOMAINS:
                    raise ValueError(f"Disposable email domains ({domain}) are not permitted. Please use an enterprise or permanent email.")
        return v

    @field_validator("password")
    @classmethod
    def validate_password_complexity(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Password must contain at least 12 characters.")
        if len(v) > 128:
            raise ValueError("Password length cannot exceed 128 characters.")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter (A-Z).")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter (a-z).")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one numeric digit (0-9).")
        if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]", v):
            raise ValueError("Password must contain at least one special character (!@#$%^&* etc.).")

        lower_pw = v.lower()
        if any(pattern in lower_pw for pattern in COMMON_WEAK_PATTERNS):
            raise ValueError("Password contains a common, easily guessable pattern (e.g., password, qwerty).")

        return v

    @model_validator(mode="after")
    def validate_no_email_in_password(self):
        email_str = str(self.email).lower()
        if "@" in email_str:
            username = email_str.split("@", 1)[0]
            # Strip non-alphanumeric chars from username
            clean_username = re.sub(r"[^a-z0-9]", "", username)
            if len(clean_username) >= 3 and clean_username in self.password.lower():
                raise ValueError("Password must not contain your email username or handle.")
        return self


class UserRead(BaseModel):
    id: int
    email: EmailStr
    full_name: str
    role: UserRole
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    sub: Optional[str] = None
