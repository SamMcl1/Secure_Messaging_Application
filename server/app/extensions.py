from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# In-memory storage is sufficient for single-process deployment.
# For multi-worker or multi-instance deployments, replace storage_uri
# with a shared backend (e.g. "redis://localhost:6379").
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=[],
)
