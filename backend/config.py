import os
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # App
    APP_NAME: str = "k8scan"
    APP_ENV: str = "development"
    FRONTEND_ORIGIN: str = "http://localhost:3000"

    # Database
    DATABASE_URL: str = "sqlite:///./k8scan.db"

    # JWT
    JWT_SECRET_KEY: str  # required – set in .env
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # Stripe
    STRIPE_SECRET_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""
    STRIPE_PRICE_PRO_MONTHLY: str = ""
    STRIPE_PRICE_PRO_ANNUAL: str = ""
    STRIPE_PRICE_ENT_MONTHLY: str = ""
    STRIPE_PRICE_ENT_ANNUAL: str = ""

    # File upload
    UPLOAD_DIR: str = "./uploads"
    MAX_UPLOAD_BYTES: int = 50 * 1024 * 1024   # 50 MB
    ALLOWED_EXTENSIONS: set = {".tgz", ".tar.gz", ".zip", ".yaml", ".yml", ".json"}
    FILE_RETENTION_HOURS: int = 24

    # Plan quotas  {plan: monthly_scans}
    PLAN_QUOTAS: dict = {
        "starter":    3,
        "pro":        10,
        "enterprise": 999_999,
    }

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    return Settings()
