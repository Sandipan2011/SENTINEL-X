from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "SENTINEL-X"
    app_version: str = "0.1.0"
    environment: str = "development"

    redis_url: str = "redis://localhost:6379/0"

    database_url: str = (
        "postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinel"
    )

    stream_name: str = "sentinel:flows"

    model_directory: str = "models"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()