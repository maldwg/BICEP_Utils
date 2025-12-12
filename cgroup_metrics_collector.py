import asyncio
import httpx
import os
import logging
import time
from typing import Optional
from pathlib import Path
from .general_utilities import get_env_variable
from .models.ids_base import IDSBase

LOGGER = logging.getLogger(__name__)


class CgroupMetricsCollector:
    """
    Collects CPU and memory metrics from cgroup filesystem (like Kubernetes does).
    Reads directly from /sys/fs/cgroup for accurate container-level metrics.
    """

    def __init__(
        self,
        container_id: int,
        container_name: str,
        core_backend_url: str,
        push_interval: int = 2,
    ):
        """
        Initialize the cgroup metrics collector.

        Args:
            container_id: The ID of the IDS container
            container_name: The name of the IDS container
            core_backend_url: URL of the core backend (e.g., 'http://172.28.0.1:8000')
            push_interval: How often to push metrics in seconds (default: 5)
        """
        self.container_id = container_id
        self.container_name = container_name
        self.core_backend_url = core_backend_url
        self.push_interval = push_interval
        self.running = False

        # Track previous CPU readings for delta calculation
        self.prev_cpu_usage_usec = None
        self.prev_cpu_timestamp = None

        # Detect cgroup version
        self.cgroup_version = self._detect_cgroup_version()
        LOGGER.info(f"Detected cgroup v{self.cgroup_version}")

    def _detect_cgroup_version(self) -> int:
        """Detect if system uses cgroup v1 or v2"""
        # cgroup v2 has a unified hierarchy at /sys/fs/cgroup/cgroup.controllers
        if Path("/sys/fs/cgroup/cgroup.controllers").exists():
            return 2
        # cgroup v1 has separate hierarchies
        elif (
            Path("/sys/fs/cgroup/cpu").exists()
            or Path("/sys/fs/cgroup/memory").exists()
        ):
            return 1
        else:
            LOGGER.warning("Could not detect cgroup version, defaulting to v2")
            return 2

    def _read_cgroup_file(self, path: str) -> Optional[str]:
        """Safely read a cgroup file"""
        try:
            with open(path, "r") as f:
                return f.read().strip()
        except (FileNotFoundError, PermissionError) as e:
            LOGGER.debug(f"Could not read {path}: {e}")
            return None

    def _get_cpu_usage_v2(self) -> Optional[float]:
        """
        Get CPU usage in cores from cgroup v2.
        Returns the rate of CPU usage (cores) calculated from usage delta.
        """
        # Read total CPU usage in microseconds
        cpu_stat = self._read_cgroup_file("/sys/fs/cgroup/cpu.stat")
        if not cpu_stat:
            return None

        # Parse usage_usec from cpu.stat
        usage_usec = None
        for line in cpu_stat.split("\n"):
            if line.startswith("usage_usec"):
                usage_usec = int(line.split()[1])
                break

        if usage_usec is None:
            return None

        # Calculate CPU usage rate from delta
        current_time = time.time()

        if self.prev_cpu_usage_usec is not None and self.prev_cpu_timestamp is not None:
            # Calculate deltas
            delta_usage_usec = usage_usec - self.prev_cpu_usage_usec
            delta_time_sec = current_time - self.prev_cpu_timestamp

            # CPU cores = (microseconds of CPU used) / (microseconds of wall time)
            # = (delta_usage_usec) / (delta_time_sec * 1_000_000)
            if delta_time_sec > 0:
                cpu_cores = delta_usage_usec / (delta_time_sec * 1_000_000)
            else:
                cpu_cores = 0.0
        else:
            # First reading, can't calculate delta yet
            cpu_cores = 0.0

        # Store current values for next iteration
        self.prev_cpu_usage_usec = usage_usec
        self.prev_cpu_timestamp = current_time

        return cpu_cores

    def _get_cpu_usage_v1(self) -> Optional[float]:
        """
        Get CPU usage in cores from cgroup v1.
        Returns the rate of CPU usage (cores) calculated from usage delta.
        """
        # Read total CPU usage in nanoseconds
        usage_str = self._read_cgroup_file("/sys/fs/cgroup/cpu/cpuacct.usage")
        if not usage_str:
            # Try cpu,cpuacct combined controller
            usage_str = self._read_cgroup_file(
                "/sys/fs/cgroup/cpu,cpuacct/cpuacct.usage"
            )

        if not usage_str:
            return None

        usage_nsec = int(usage_str)
        current_time = time.time()

        if self.prev_cpu_usage_usec is not None and self.prev_cpu_timestamp is not None:
            # Calculate deltas (convert nanoseconds to microseconds)
            delta_usage_usec = (usage_nsec / 1000) - self.prev_cpu_usage_usec
            delta_time_sec = current_time - self.prev_cpu_timestamp

            # CPU cores = (microseconds of CPU used) / (microseconds of wall time)
            if delta_time_sec > 0:
                cpu_cores = delta_usage_usec / (delta_time_sec * 1_000_000)
            else:
                cpu_cores = 0.0
        else:
            cpu_cores = 0.0

        # Store current values for next iteration (in microseconds)
        self.prev_cpu_usage_usec = usage_nsec / 1000
        self.prev_cpu_timestamp = current_time

        return cpu_cores

    def _get_memory_usage_v2(self) -> Optional[float]:
        """Get memory usage in MB from cgroup v2"""
        # Read current memory usage in bytes
        memory_str = self._read_cgroup_file("/sys/fs/cgroup/memory.current")
        if not memory_str:
            return None

        memory_bytes = int(memory_str)
        memory_mb = memory_bytes / (1024 * 1024)

        return memory_mb

    def _get_memory_usage_v1(self) -> Optional[float]:
        """Get memory usage in MB from cgroup v1"""
        # Read current memory usage in bytes
        memory_str = self._read_cgroup_file(
            "/sys/fs/cgroup/memory/memory.usage_in_bytes"
        )
        if not memory_str:
            return None

        memory_bytes = int(memory_str)
        memory_mb = memory_bytes / (1024 * 1024)

        return memory_mb

    async def collect_metrics(self) -> Optional[dict]:
        """
        Collect current CPU and memory metrics from cgroup filesystem.

        Returns:
            dict with cpu_usage (in cores) and memory_usage (in MB)
        """
        try:
            # Collect CPU usage
            if self.cgroup_version == 2:
                cpu_usage = self._get_cpu_usage_v2()
            else:
                cpu_usage = self._get_cpu_usage_v1()

            # Collect memory usage
            if self.cgroup_version == 2:
                memory_usage = self._get_memory_usage_v2()
            else:
                memory_usage = self._get_memory_usage_v1()

            # If we couldn't read metrics, return None
            if cpu_usage is None or memory_usage is None:
                LOGGER.warning("Could not read cgroup metrics")
                return None

            return {
                "container_id": self.container_id,
                "container_name": self.container_name,
                "cpu_usage": round(cpu_usage, 4),
                "memory_usage": round(memory_usage, 2),
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
                    f"{self.core_backend_url}/metrics/push", json=metrics, timeout=5.0
                )

                if response.status_code == 200:
                    LOGGER.debug(
                        f"Successfully pushed metrics for {self.container_name}: CPU={metrics['cpu_usage']:.4f} cores, RAM={metrics['memory_usage']:.2f} MB"
                    )
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
        LOGGER.info(f"Started cgroup metrics collector for {self.container_name}")

        while self.running:
            metrics = await self.collect_metrics()
            if metrics:
                await self.push_metrics(metrics)

            await asyncio.sleep(self.push_interval)

    async def stop(self):
        """Stop the metrics collection loop."""
        LOGGER.info(f"Stopping cgroup metrics collector for {self.container_name}")
        self.running = False


async def start_cgroup_metrics_collector(
    ids: IDSBase, core_backend_url: Optional[str] = None
) -> CgroupMetricsCollector:
    """
    Helper function to create and start a cgroup metrics collector.

    Args:
        ids: IDSBase
        core_backend_url: URL of the core backend (if None, reads from CORE_URL env var)

    Returns:
        CgroupMetricsCollector instance
    """
    if core_backend_url is None:
        # Try CORE_URL first (used by IDS containers), then fall back to CORE_BACKEND_URL
        try:
            core_backend_url = await get_env_variable("CORE_URL")
        except Exception as e:
            LOGGER.error("Could not determine a CORE URL for the metrics collection!")
            raise e

    LOGGER.info(
        f"Starting cgroup metrics collector for {ids.container_name} pushing to {core_backend_url}"
    )

    collector = CgroupMetricsCollector(
        ids.container_id, ids.container_name, core_backend_url
    )
    asyncio.create_task(collector.start())

    return collector
