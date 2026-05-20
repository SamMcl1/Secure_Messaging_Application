import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# In-memory storage is sufficient for single-process deployment.
# For multi-worker or multi-instance deployments, configure
# RATELIMIT_STORAGE_URI to use a shared backend
# (e.g. "redis://localhost:6379").
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
    default_limits=[],
    headers_enabled=True,   # PT-05: emit Retry-After / X-RateLimit-* on 429
)
