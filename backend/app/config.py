import os
from dotenv import load_dotenv

load_dotenv()

APP_NAME = os.getenv("APP_NAME", "DAT250 SecureApp")
APP_ENV = os.getenv("APP_ENV", "lab")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://dat250:dat250@db:5432/dat250_secureapp")
SESSION_SECRET = os.getenv("SESSION_SECRET", "hardcoded-dev-secret")
MAILHOG_HOST = os.getenv("MAILHOG_HOST", "mailhog")
MAILHOG_PORT = int(os.getenv("MAILHOG_PORT", "1025"))
BASE_URL = os.getenv("BASE_URL", "http://localhost:18181")

# Session / authentication hardening
SESSION_MAX_AGE_SECONDS = int(os.getenv("SESSION_MAX_AGE_SECONDS", str(8 * 60 * 60)))
RESET_TOKEN_TTL_SECONDS = int(os.getenv("RESET_TOKEN_TTL_SECONDS", str(30 * 60)))
# Must be true whenever the app is served over HTTPS; false only for the
# local plain-HTTP lab setup on http://localhost.
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() in ("1", "true", "yes")
