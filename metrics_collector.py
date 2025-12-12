import psutil
import asyncio
import httpx
import os
import logging
from typing import Optional

LOGGER = logging.getLogger(__name__)

class MetricsCollector:
    """
    Collects CPU and memory metrics for the IDS container and pushes them to the core backend.
    Designed to run as a background task.
    """
    
    def __init__(self, container_id: int, container_name: str, core_backend_url: str, push_interval: int = 5):
        """
        Initialize the metrics collector.
        
        Args:
            container_id: The ID of the IDS container
            container_name: The name of the IDS container
            core_backend_url: URL of the core backend (e.g., 'http://core:8000')
            push_interval: How often to push metrics in seconds (default: 5)
        """
        self.container_id = container_id
        self.container_name = container_name
        self.core_backend_url = core_backend_url
        self.push_interval = push_interval
        self.running = False
        self.process = psutil.Process()
        
    async def collect_metrics(self) -> dict:
        """
        Collect current CPU and memory metrics for the entire container.
        
        Returns:
            dict with cpu_usage (in cores) and memory_usage (in MB)
        """
        try:
            # Get all processes in container and sum their resource usage
            total_cpu_percent = 0.0
            total_memory_bytes = 0
            
            # Iterate through all processes
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    # Get CPU and memory for each process
                    proc_cpu = proc.cpu_percent(interval=0.1) / 100.0  # Convert to cores
                    proc_mem = proc.memory_info().rss
                    
                    total_cpu_percent += proc_cpu
                    total_memory_bytes += proc_mem
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            memory_mb = total_memory_bytes / (1024 * 1024)
            
            return {
                "container_id": self.container_id,
                "container_name": self.container_name,
                "cpu_usage": round(total_cpu_percent, 4),
                "memory_usage": round(memory_mb, 2)
            }
        except Exception as e:
            LOGGER.error(f"Error collecting metrics: {e}")
            return None
    
    async def push_metrics(self, metrics: dict) -> bool:
        """
        Push metrics to the core backend.
        
        Args:
            metrics: The metrics dictionary to push
            
        Returns:
            True if successful, False otherwise
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.core_backend_url}/metrics/push",
                    json=metrics,
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    LOGGER.debug(f"Successfully pushed metrics for {self.container_name}")
                    return True
                else:
                    LOGGER.warning(f"Failed to push metrics: {response.status_code}")
                    return False
                    
        except Exception as e:
            LOGGER.error(f"Error pushing metrics: {e}")
            return False
    
    async def start(self):
        """
        Start the metrics collection and pushing loop.
        This should be run as a background task.
        """
        self.running = True
        LOGGER.info(f"Started metrics collector for {self.container_name}")
        
        while self.running:
            metrics = await self.collect_metrics()
            if metrics:
                await self.push_metrics(metrics)
            
            await asyncio.sleep(self.push_interval)
    
    async def stop(self):
        """
        Stop the metrics collection loop.
        """
        LOGGER.info(f"Stopping metrics collector for {self.container_name}")
        self.running = False


async def start_metrics_collector(container_id: int, container_name: str, core_backend_url: Optional[str] = None) -> MetricsCollector:
    """
    Helper function to create and start a metrics collector.
    
    Args:
        container_id: The ID of the IDS container
        container_name: The name of the IDS container
        core_backend_url: URL of the core backend (if None, reads from CORE_URL env var)
        
    Returns:
        MetricsCollector instance
    """
    if core_backend_url is None:
        # Try CORE_URL first (used by IDS containers), then fall back to CORE_BACKEND_URL
        core_backend_url = os.environ.get('CORE_URL') or os.environ.get('CORE_BACKEND_URL')
        if not core_backend_url:
            LOGGER.error("Neither CORE_URL nor CORE_BACKEND_URL environment variable is set")
            # Use a default that won't work but won't crash
            core_backend_url = 'http://localhost:8000'
    
    LOGGER.info(f"Starting metrics collector for {container_name} pushing to {core_backend_url}")
    
    collector = MetricsCollector(container_id, container_name, core_backend_url)
    asyncio.create_task(collector.start())
    
    return collector
