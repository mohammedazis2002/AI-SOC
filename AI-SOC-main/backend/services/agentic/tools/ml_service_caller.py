"""
ML Service Caller - Tool for invoking ML services
Supports parallel execution and error handling
"""

import aiohttp
import asyncio
import logging
from typing import Dict, Any, List, Optional

from ..config.config import config

logger = logging.getLogger(__name__)


class MLServiceCaller:
    """
    ML Service Caller - Invokes ML services with parallel execution.
    
    Features:
    - Parallel async HTTP calls
    - Automatic retries
    - Timeout handling
    - Error aggregation
    """
    
    def __init__(self):
        self.services = config.ML_SERVICES
        self.logger = logging.getLogger("tools.ml_service_caller")
    
    async def call_service(
        self, 
        service_name: str, 
        alert: Dict[str, Any],
        retry_count: int = 1
    ) -> Dict[str, Any]:
        """
        Call a single ML service.
        
        Args:
            service_name: Name of the ML service
            alert: Alert data to send
            retry_count: Number of retries on failure
            
        Returns:
            ML service response
        """
        if service_name not in self.services:
            raise ValueError(f"Unknown ML service: {service_name}")
        
        service_config = self.services[service_name]
        url = f"{service_config['url']}{service_config['endpoint']}"
        timeout = service_config['timeout']
        
        for attempt in range(retry_count + 1):
            try:
                self.logger.info(f"Calling {service_name} (attempt {attempt + 1}/{retry_count + 1})")
                
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url,
                        json={"alert": alert},
                        timeout=aiohttp.ClientTimeout(total=timeout)
                    ) as response:
                        
                        if response.status == 200:
                            result = await response.json()
                            self.logger.info(f"✓ {service_name} success")
                            return {
                                "service": service_name,
                                "status": "success",
                                "result": result,
                                "attempt": attempt + 1
                            }
                        else:
                            error_text = await response.text()
                            self.logger.warning(
                                f"✗ {service_name} returned {response.status}: {error_text[:100]}"
                            )
                            
                            if attempt < retry_count:
                                await asyncio.sleep(1)  # Brief delay before retry
                                continue
                            
                            return {
                                "service": service_name,
                                "status": "error",
                                "error": f"HTTP {response.status}: {error_text}",
                                "attempt": attempt + 1
                            }
            
            except asyncio.TimeoutError:
                self.logger.warning(f"✗ {service_name} timeout after {timeout}s")
                
                if attempt < retry_count:
                    await asyncio.sleep(1)
                    continue
                
                return {
                    "service": service_name,
                    "status": "error",
                    "error": f"Timeout after {timeout}s",
                    "attempt": attempt + 1
                }
            
            except Exception as e:
                self.logger.error(f"✗ {service_name} exception: {e}")
                
                if attempt < retry_count:
                    await asyncio.sleep(1)
                    continue
                
                # All retries failed - try local fallback
                self.logger.warning(f"All retries failed for {service_name}, trying local fallback")
                
                return await self._try_local_fallback(service_name, alert)
        
        # Should never reach here
        return await self._try_local_fallback(service_name, alert)
    
    async def _try_local_fallback(self, service_name: str, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Try local model fallback when remote service fails"""
        try:
            from .local_ml_fallback import local_ml_fallback
            return await local_ml_fallback.predict(service_name, alert)
        except Exception as e:
            self.logger.error(f"Local fallback also failed: {e}")
            return {
                "service": service_name,
                "status": "error",
                "error": f"Remote and local fallback failed: {str(e)}",
                "source": "total_failure"
            }
    
    async def call_multiple_services(
        self,
        service_names: List[str],
        alert: Dict[str, Any],
        retry_count: int = 1
    ) -> Dict[str, Any]:
        """
        Call multiple ML services in parallel.
        
        Args:
            service_names: List of ML service names to call
            alert: Alert data to send
            retry_count: Number of retries per service
            
        Returns:
            Aggregated results from all services
        """
        self.logger.info(f"Calling {len(service_names)} ML services in parallel")
        
        # Create tasks for parallel execution
        tasks = [
            self.call_service(service_name, alert, retry_count)
            for service_name in service_names
        ]
        
        # Execute all in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Aggregate results
        aggregated = {
            "services_called": service_names,
            "results": {},
            "successes": 0,
            "failures": 0,
            "errors": []
        }
        
        for result in results:
            if isinstance(result, Exception):
                # Task raised an exception
                aggregated["failures"] += 1
                aggregated["errors"].append(str(result))
            else:
                service_name = result["service"]
                aggregated["results"][service_name] = result
                
                if result["status"] == "success":
                    aggregated["successes"] += 1
                else:
                    aggregated["failures"] += 1
                    aggregated["errors"].append(
                        f"{service_name}: {result.get('error', 'Unknown')}"
                    )
        
        self.logger.info(
            f"ML services complete: {aggregated['successes']} successes, "
            f"{aggregated['failures']} failures"
        )
        
        return aggregated


# Global instance
ml_service_caller = MLServiceCaller()
