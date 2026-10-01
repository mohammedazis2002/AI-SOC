"""
Autonomous Agentic SOAR - Main Package
Intelligent agent orchestration for security incident response
"""

__version__ = "1.0.0"
__author__ = "SOAR Team"

"""
Keep package import side-effects minimal.

Some services import submodules like `backend.services.agentic.config.llm_service`.
Importing the package should not fail if optional orchestration modules move.
"""

__all__: list[str] = []
