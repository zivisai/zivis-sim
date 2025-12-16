# Vulnerability modules for MAUL
# Each module implements intentionally vulnerable functionality for security training

from .agent_tools import router as agent_router
from .document_upload import router as upload_router
from .streaming import router as streaming_router
from .embeddings import router as embeddings_router
from .auth import router as auth_router
from .output_handling import router as output_router
from .multi_agent import router as multi_agent_router
from .rbac import router as rbac_router

__all__ = [
    'agent_router',
    'upload_router',
    'streaming_router',
    'embeddings_router',
    'auth_router',
    'output_router',
    'multi_agent_router',
    'rbac_router'
]
