import pytest
import os
import asyncio
import psutil
import subprocess
import time
from unittest.mock import AsyncMock, patch
from BICEP_Utils.general_utilities import (
    save_file,
    get_env_variable,
    stop_process,
    wait_for_process_completion,
    create_and_activate_network_interface,
    mirror_network_traffic_to_interface,
    remove_network_interface,
    execute_command_async,
    exececute_command_sync_in_seperate_thread
)

@pytest.fixture
def temp_file(tmp_path):
    test_file = tmp_path / "test.txt"
    return test_file

@pytest.mark.asyncio
async def test_save_file(temp_file):
    class FakeFile:
        async def read(self):
            return b"test content"
    
    fake_file = FakeFile()
    await save_file(fake_file, temp_file)
    
    with open(temp_file, "rb") as f:
        content = f.read()
    
    assert content == b"test content"

@pytest.mark.asyncio
async def test_get_env_variable(monkeypatch):
    monkeypatch.setenv("TEST_ENV", "test_value")
    result = await get_env_variable("TEST_ENV")
    assert result == "test_value"

@pytest.mark.asyncio
@patch("asyncio.create_subprocess_exec")
async def test_execute_command_async(mock_subprocess):
    mock_process = AsyncMock()
    mock_process.pid = 1234
    mock_subprocess.return_value = mock_process
    
    command = ["echo", "Hello"]
    pid = await execute_command_async(command)
    
    assert pid == 1234
    mock_subprocess.assert_called_once_with(*command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def test_execute_command_returns_valid_pid(tmp_path):
    command = ["sleep", "3"]  
    cwd = tmp_path

    pid = exececute_command_sync_in_seperate_thread(command, cwd=str(cwd))

    # Check that the PID is a positive integer
    assert isinstance(pid, int)
    assert pid > 0

    time.sleep(0.1)  # Give it a moment to start
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        pytest.fail("Process terminated unexpectedly")

    # Clean up the process
    subprocess.run(["kill", str(pid)])


@pytest.mark.asyncio
@patch("psutil.Process")
async def test_stop_process(mock_process_class):
    mock_process = mock_process_class.return_value
    mock_process.is_running.return_value = True
    
    await stop_process(1234)
    
    mock_process.terminate.assert_called_once()

@pytest.mark.asyncio
@patch("psutil.Process")
async def test_wait_for_process_completion(mock_process_class):
    mock_process = mock_process_class.return_value
    mock_process.is_running.side_effect = [True, False]
    mock_process.returncode = 0
    
    result = await wait_for_process_completion(1234)
    
    assert result == 0

@pytest.mark.asyncio
@patch("BICEP_Utils.general_utilities.execute_command_async")
async def test_create_and_activate_network_interface(mock_execute_command):
    mock_execute_command.return_value = None
    
    await create_and_activate_network_interface("test0")
    
    assert mock_execute_command.call_count == 2

@pytest.mark.asyncio
@patch("BICEP_Utils.general_utilities.execute_command_async")
async def test_mirror_network_traffic_to_interface(mock_execute_command):
    mock_execute_command.return_value = 1234
    
    pid = await mirror_network_traffic_to_interface("tap0", "eth0")
    
    assert pid == 1234
    mock_execute_command.assert_called_once()

@pytest.mark.asyncio
@patch("BICEP_Utils.general_utilities.execute_command_async")
async def test_remove_network_interface(mock_execute_command):
    mock_execute_command.return_value = None
    
    await remove_network_interface("tap0")
    
    mock_execute_command.assert_called_once()
