"""
LLM Service with Three-Tier Fallback
Llama 3.1 70B → Llama 3.1 8B → Phi-3 Mini
"""

import logging
import os
from typing import Optional, Any, List, Dict
from langchain_community.llms import Ollama
from langchain_community.chat_models import ChatOllama

logger = logging.getLogger(__name__)


def _ollama_base_url() -> str:
    """
    Resolve Ollama HTTP API base URL.

    In Docker, Ollama runs as a separate service (e.g. `ollama:11434`); `localhost`
    inside a container is not the host. Prefer `LLM_API_URL` (used in docker-compose)
    or `LLM_SERVICE_URL` (backend settings), then default to local dev.
    """
    raw = (
        os.getenv("LLM_API_URL")
        or os.getenv("LLM_SERVICE_URL")
        or "http://localhost:11434"
    ).strip()
    # ChatOllama expects base URL only (no /v1/... suffix).
    for suffix in ("/v1/chat/completions", "/v1", "/"):
        if raw.endswith(suffix) and len(raw) > len("http://x"):
            raw = raw[: -len(suffix)].rstrip("/")
            break
    return raw.rstrip("/")


class LLMService:
    """
    Multi-tier LLM service with automatic fallback.
    
    Tier 1 (Primary): Llama 3.1 70B - Complex reasoning, hypothesis, synthesis
    Tier 2 (Secondary): Llama 3.1 8B - Action planning, compliance, faster tasks  
    Tier 3 (Fallback): Phi-3 Mini - Emergency fallback, simple tasks
    """
    
    def __init__(self, base_url: str | None = None):
        """
        Initialize LLM service with three-tier configuration.
        
        Args:
            base_url: Ollama server URL
        """
        self.base_url = base_url if base_url is not None else _ollama_base_url()
        logger.info("LLM Service Ollama base_url=%s", self.base_url)
        
        # Seconds per HTTP call to Ollama. Local CPU inference often exceeds 15s; env overrides below.
        t_primary = int(os.getenv("LLM_TIMEOUT_PRIMARY", "120"))
        t_secondary = int(os.getenv("LLM_TIMEOUT_SECONDARY", "90"))
        t_fallback = int(os.getenv("LLM_TIMEOUT_FALLBACK", "60"))

        self.llm_stack = [
            {
                "name": "llama-3.1-70b",
                "model": "llama3.1:70b",
                "tier": "primary",
                "use_case": "Complex reasoning, synthesis, hypothesis generation",
                "timeout": t_primary,
            },
            {
                "name": "llama-3.1-8b",
                "model": "llama3.1:8b",
                "tier": "secondary",
                "use_case": "Action planning, compliance checking, faster tasks",
                "timeout": t_secondary,
            },
            {
                "name": "phi-3-mini",
                "model": "phi3:mini",
                "tier": "fallback",
                "use_case": "Emergency fallback, simple classification",
                "timeout": t_fallback,
            },
        ]
        
        self.tier_map = {
            "primary": 0,
            "secondary": 1,
            "fallback": 2
        }
        
        logger.info(f"LLM Service initialized with {len(self.llm_stack)} tiers")
    
    async def ainvoke(
        self, 
        prompt: str, 
        tier: str = "primary",
        system_message: Optional[str] = None,
        **kwargs
    ) -> Any:
        """
        Invoke LLM with automatic fallback on failure.
        
        Args:
            prompt: The prompt to send to LLM
            tier: Starting tier ("primary", "secondary", or "fallback")
            system_message: Optional system message
            **kwargs: Additional arguments to pass to LLM
            
        Returns:
            LLM response
            
        Raises:
            Exception: If all LLMs fail
        """
        start_idx = self.tier_map.get(tier, 0)
        
        for i in range(start_idx, len(self.llm_stack)):
            llm_config = self.llm_stack[i]
            
            try:
                logger.info(f"Attempting LLM: {llm_config['name']} ({llm_config['tier']})")
                
                # Create LLM instance
                llm = ChatOllama(
                    model=llm_config["model"],
                    base_url=self.base_url,
                    timeout=llm_config["timeout"],
                    **kwargs
                )
                
                # Build messages
                messages = []
                if system_message:
                    messages.append(("system", system_message))
                messages.append(("human", prompt))
                
                # Invoke LLM
                response = await llm.ainvoke(messages)
                
                logger.info(f"✓ Success with {llm_config['name']}")
                return response
                
            except Exception as e:
                err = str(e).strip() or repr(e)
                logger.warning(
                    "✗ %s failed: %s: %s",
                    llm_config["name"],
                    type(e).__name__,
                    err[:500],
                )
                
                # If this is the last LLM, raise the exception
                if i == len(self.llm_stack) - 1:
                    logger.error("All LLMs failed!")
                    raise Exception(f"All LLMs failed. Last error: {e}")
                
                # Otherwise, continue to next tier
                logger.info(f"Falling back to tier {self.llm_stack[i + 1]['tier']}...")
                continue
    
    def invoke(
        self, 
        prompt: str, 
        tier: str = "primary",
        system_message: Optional[str] = None,
        **kwargs
    ) -> Any:
        """
        Synchronous version of ainvoke.
        
        Args:
            prompt: The prompt to send to LLM
            tier: Starting tier ("primary", "secondary", or "fallback")
            system_message: Optional system message
            **kwargs: Additional arguments to pass to LLM
            
        Returns:
            LLM response
        """
        start_idx = self.tier_map.get(tier, 0)
        
        for i in range(start_idx, len(self.llm_stack)):
            llm_config = self.llm_stack[i]
            
            try:
                logger.info(f"Attempting LLM: {llm_config['name']} ({llm_config['tier']})")
                
                # Create LLM instance
                llm = ChatOllama(
                    model=llm_config["model"],
                    base_url=self.base_url,
                    timeout=llm_config["timeout"],
                    **kwargs
                )
                
                # Build messages
                messages = []
                if system_message:
                    messages.append(("system", system_message))
                messages.append(("human", prompt))
                
                # Invoke LLM
                response = llm.invoke(messages)
                
                logger.info(f"✓ Success with {llm_config['name']}")
                return response
                
            except Exception as e:
                err = str(e).strip() or repr(e)
                logger.warning(
                    "✗ %s failed: %s: %s",
                    llm_config["name"],
                    type(e).__name__,
                    err[:500],
                )
                
                if i == len(self.llm_stack) - 1:
                    logger.error("All LLMs failed!")
                    raise Exception(f"All LLMs failed. Last error: {e}")
                
                logger.info(f"Falling back to tier {self.llm_stack[i + 1]['tier']}...")
                continue
    
    def get_llm_for_tier(self, tier: str = "primary") -> ChatOllama:
        """
        Get a configured LLM instance for a specific tier.
        
        Args:
            tier: Tier name ("primary", "secondary", or "fallback")
            
        Returns:
            ChatOllama instance
        """
        tier_idx = self.tier_map.get(tier, 0)
        llm_config = self.llm_stack[tier_idx]
        
        return ChatOllama(
            model=llm_config["model"],
            base_url=self.base_url,
            timeout=llm_config["timeout"]
        )
    
    def get_llm_info(self) -> List[Dict[str, Any]]:
        """
        Get information about configured LLMs.
        
        Returns:
            List of LLM configuration dictionaries
        """
        return self.llm_stack.copy()


# Global instance (can be imported by agents)
llm_service = LLMService()
