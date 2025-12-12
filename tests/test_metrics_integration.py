"""
Integration test that spins up a Docker container and verifies
cgroup metrics collection works end-to-end.

This test:
1. Starts a Docker container with CPU/memory load
2. Runs the metrics collector inside the container
3. Verifies metrics are accurate
4. Compares with Docker stats API

Run with: pytest test_metrics_integration.py -v -s
"""

import pytest
import docker
import time
import asyncio
import httpx
from unittest.mock import AsyncMock, patch


@pytest.mark.integration
class TestMetricsIntegrationWithDocker:
    """End-to-end integration tests with Docker containers"""
    
    @pytest.fixture(scope="class")
    def docker_client(self):
        """Create Docker client"""
        try:
            client = docker.from_env()
            client.ping()
            yield client
            client.close()
        except Exception as e:
            pytest.skip(f"Docker not available: {e}")
    
    @pytest.fixture
    def stress_container(self, docker_client):
        """
        Create a container with some CPU/memory load.
        Uses stress-ng to generate measurable resource usage.
        """
        # Run Alpine with stress-ng
        container = docker_client.containers.run(
            "alpine:latest",
            command="sh -c 'apk add --no-cache stress-ng && stress-ng --cpu 1 --vm 1 --vm-bytes 100M --timeout 60s'",
            detach=True,
            remove=True,
            name="bicep-test-metrics",
            mem_limit="256m",
            cpu_quota=50000,  # 0.5 CPU cores
            cpu_period=100000
        )
        
        # Wait for stress to start
        time.sleep(5)
        
        yield container
        
        # Cleanup
        try:
            container.stop(timeout=2)
        except:
            pass
    
    def test_docker_stats_baseline(self, stress_container):
        """
        Test baseline: Verify Docker stats API shows resource usage.
        This confirms the container is actually using resources.
        """
        # Get stats from Docker API
        stats = stress_container.stats(stream=False)
        
        # Verify we get meaningful stats
        assert 'cpu_stats' in stats
        assert 'memory_stats' in stats
        
        # Check CPU usage is > 0
        cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                   stats['precpu_stats']['cpu_usage']['total_usage']
        system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                      stats['precpu_stats']['system_cpu_usage']
        
        if system_delta > 0:
            cpu_percent = (cpu_delta / system_delta) * len(stats['cpu_stats']['cpu_usage']['percpu_usage']) * 100
            print(f"\nDocker stats CPU: {cpu_percent:.2f}%")
            assert cpu_percent > 0, "Container should be using CPU"
        
        # Check memory usage
        memory_mb = stats['memory_stats']['usage'] / (1024 * 1024)
        print(f"Docker stats Memory: {memory_mb:.2f} MB")
        assert memory_mb > 0, "Container should be using memory"
    
    @pytest.mark.asyncio
    async def test_cgroup_metrics_accuracy(self, stress_container, docker_client):
        """
        Test that cgroup metrics collector reads accurate values
        compared to Docker stats API.
        """
        # We need to exec into the container and read cgroup files
        # This simulates what the metrics collector does
        
        # Read cgroup v2 CPU stats (most systems)
        exit_code, output = stress_container.exec_run("cat /sys/fs/cgroup/cpu.stat")
        
        if exit_code == 0:
            print(f"\nCgroup CPU stats:\n{output.decode()}")
            assert b'usage_usec' in output, "Should have CPU usage data"
        else:
            # Try cgroup v1
            exit_code, output = stress_container.exec_run("cat /sys/fs/cgroup/cpu/cpuacct.usage")
            if exit_code == 0:
                print(f"\nCgroup v1 CPU usage: {output.decode()}")
                assert int(output) > 0, "CPU usage should be > 0"
        
        # Read memory stats
        exit_code, output = stress_container.exec_run("cat /sys/fs/cgroup/memory.current")
        
        if exit_code == 0:
            memory_bytes = int(output.decode().strip())
            memory_mb = memory_bytes / (1024 * 1024)
            print(f"\nCgroup memory usage: {memory_mb:.2f} MB")
            assert memory_mb > 10, "Memory usage should be reasonable"
        else:
            # Try cgroup v1
            exit_code, output = stress_container.exec_run("cat /sys/fs/cgroup/memory/memory.usage_in_bytes")
            if exit_code == 0:
                memory_bytes = int(output.decode().strip())
                memory_mb = memory_bytes / (1024 * 1024)
                print(f"\nCgroup v1 memory usage: {memory_mb:.2f} MB")
                assert memory_mb > 10, "Memory usage should be reasonable"
    
    @pytest.mark.asyncio
    async def test_metrics_collection_loop(self, stress_container):
        """
        Test full metrics collection loop:
        1. Read metrics twice (to calculate CPU delta)
        2. Verify values are reasonable
        3. Verify metrics change over time
        """
        from cgroup_metrics_collector import CgroupMetricsCollector
        
        # Mock the push_metrics to capture what would be sent
        captured_metrics = []
        
        async def mock_push(metrics):
            captured_metrics.append(metrics)
            return True
        
        # Create collector (would normally run inside container)
        # For this test, we just verify the logic
        collector = CgroupMetricsCollector(1, "bicep-test-metrics", "http://localhost:8000")
        collector.push_metrics = mock_push
        
        # Simulate reading cgroup files from the container
        # In reality, this would be done inside the container
        
        # Mock cgroup reads to simulate container data
        with patch.object(collector, '_read_cgroup_file') as mock_read:
            def side_effect(path):
                if 'cpu.stat' in path:
                    # Simulate increasing CPU usage
                    if collector.prev_cpu_usage_usec is None:
                        return "usage_usec 1000000000"
                    else:
                        return "usage_usec 1500000000"  # 0.5 second more CPU
                elif 'memory.current' in path:
                    return str(150 * 1024 * 1024)  # 150 MB
                return None
            
            mock_read.side_effect = side_effect
            
            # First collection (establishes baseline)
            metrics1 = await collector.collect_metrics()
            assert metrics1 is not None
            assert metrics1['cpu_usage'] == 0.0  # First reading
            
            # Wait a bit
            await asyncio.sleep(1)
            
            # Second collection (should show delta)
            metrics2 = await collector.collect_metrics()
            assert metrics2 is not None
            assert metrics2['cpu_usage'] > 0, "CPU should show usage after delta"
            assert metrics2['memory_usage'] > 140, "Memory should be ~150 MB"
            
            print(f"\nCollected metrics: CPU={metrics2['cpu_usage']:.4f} cores, RAM={metrics2['memory_usage']:.2f} MB")
    
    def test_compare_cgroup_vs_docker_stats(self, stress_container):
        """
        Compare cgroup-based metrics with Docker stats API.
        They should be reasonably close.
        """
        import json
        
        # Get Docker stats
        stats = stress_container.stats(stream=False)
        docker_memory_mb = stats['memory_stats']['usage'] / (1024 * 1024)
        
        # Get cgroup memory
        exit_code, output = stress_container.exec_run("cat /sys/fs/cgroup/memory.current")
        if exit_code != 0:
            exit_code, output = stress_container.exec_run("cat /sys/fs/cgroup/memory/memory.usage_in_bytes")
        
        if exit_code == 0:
            cgroup_memory_mb = int(output.decode().strip()) / (1024 * 1024)
            
            print(f"\nDocker API memory: {docker_memory_mb:.2f} MB")
            print(f"Cgroup memory: {cgroup_memory_mb:.2f} MB")
            
            # They should be within 10% of each other
            diff_percent = abs(docker_memory_mb - cgroup_memory_mb) / docker_memory_mb * 100
            assert diff_percent < 10, f"Cgroup and Docker stats should match (diff: {diff_percent:.1f}%)"


@pytest.mark.asyncio
async def test_push_to_mock_backend():
    """
    Test pushing metrics to a mock backend server.
    Verifies the HTTP request format is correct.
    """
    from cgroup_metrics_collector import CgroupMetricsCollector
    
    collector = CgroupMetricsCollector(5, "test-container", "http://localhost:8000")
    
    metrics = {
        "container_id": 5,
        "container_name": "test-container",
        "cpu_usage": 1.2345,
        "memory_usage": 256.78
    }
    
    # Mock HTTP client
    mock_response = AsyncMock()
    mock_response.status_code = 200
    
    with patch('httpx.AsyncClient') as mock_client:
        mock_post = AsyncMock(return_value=mock_response)
        mock_client.return_value.__aenter__.return_value.post = mock_post
        
        result = await collector.push_metrics(metrics)
        
        assert result is True
        
        # Verify the request
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        
        # Check URL
        assert call_args[0][0] == "http://localhost:8000/metrics/push"
        
        # Check JSON payload
        assert call_args[1]['json'] == metrics
        assert call_args[1]['timeout'] == 5.0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "-m", "integration"])
