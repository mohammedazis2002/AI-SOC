from pydantic import BaseModel, EmailStr, Field, field_validator


class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    email: EmailStr
    # bcrypt truncates at 72 bytes; enforce to avoid silent weakening/crashes
    password: str = Field(..., min_length=8, max_length=72)

    @field_validator("password")
    @classmethod
    def _bcrypt_max_72_bytes(cls, v: str) -> str:
        if len(v.encode("utf-8")) > 72:
            raise ValueError("password must be <= 72 bytes (bcrypt limit)")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class RegisterResponse(BaseModel):
    id: str
    email: str
    name: str
    status: str
    message: str
