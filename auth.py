from jose import jwt
from datetime import datetime, timedelta, timezone
import os

# Production me SECRET_KEY environment variable me rakhein
SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET_KEY_2026"
)

ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 60


def create_access_token(data: dict):
    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    to_encode.update({
        "exp": expire
    })

    return jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )