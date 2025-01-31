import pytest
import os
import asyncio
import psutil
import subprocess
import json
from unittest.mock import AsyncMock, patch, MagicMock
from starlette.datastructures import UploadFile

from BICEP_Utils.general_utilities import (
    save_file,
    get_env_variable,
    execute_command,
    stop_process,
    wait_for_process_completion,
    create_and_activate_network_interface,
    mirror_network_traffic_to_interface,
    remove_network_interface
)
from fastapi import status
from BICEP_Utils.fastapi.routes import *
from BICEP_Utils.fastapi.dependencies import get_ids_instance
from BICEP_Utils.models.ids_base import IDSBase

@pytest.fixture
def mock_ids():
    mock = AsyncMock(spec=IDSBase)
    mock.container_id = 1
    mock.ensemble_id = None
    mock.configure = AsyncMock(return_value="Test")
    return mock

@pytest.mark.asyncio
async def test_healthcheck():
    response = await healthcheck()
    response_json = json.loads(response.body.decode())
    assert response.status_code == 200
    assert response_json == {"message": "healthy"}

@patch("BICEP_Utils.fastapi.routes.save_file")
@pytest.mark.asyncio
async def test_configuration(save_file_mock, mock_ids):
    container_id = "1"
    mock_file = MagicMock(spec=UploadFile)
    response = await configure(container_id=container_id,file=mock_file,ids=mock_ids)
    response_json = json.loads(response.body.decode())
    assert response.status_code == 200
    assert response_json == {'message': mock_ids.configure.return_value}
    
@pytest.mark.asyncio
async def test_configuration_file_is_none(mock_ids):
    container_id="1"
    mock_file = None
    response = await configure(container_id=container_id,file=mock_file,ids=mock_ids)
    response_json = json.loads(response.body.decode())
    assert response.status_code == 400
    assert response_json == {"error": "No file provided"}
    

# @pytest.mark.asyncio
# async def test_add_to_ensemble(client, mock_ids):
#     with patch("BICEP_Utils.fastapi.routes.get_ids_instance", return_value=mock_ids):
#         response = client.post("/configure/ensemble/add/123")
#         assert response.status_code == status.HTTP_200_OK
#         assert "Added IDS to ensemble 123" in response.text

# @pytest.mark.asyncio
# async def test_remove_from_ensemble(client, mock_ids):
#     with patch("BICEP_Utils.fastapi.routes.get_ids_instance", return_value=mock_ids):
#         response = client.post("/configure/ensemble/remove")
#         assert response.status_code == status.HTTP_200_OK

# @pytest.mark.asyncio
# async def test_static_analysis(client, mock_ids):
#     with patch("BICEP_Utils.fastapi.routes.get_ids_instance", return_value=mock_ids):
#         response = client.post("/analysis/static", files={"dataset": ("data.pcap", b"packet data")}, data={"dataset_id": "1", "container_id": "1"})
#         assert response.status_code == status.HTTP_200_OK

# @pytest.mark.asyncio
# async def test_network_analysis(client, mock_ids):
#     with patch("BICEP_Utils.fastapi.routes.get_ids_instance", return_value=mock_ids):
#         response = client.post("/analysis/network", json={"ensemble_id": 1})
#         assert response.status_code == status.HTTP_200_OK

# @pytest.mark.asyncio
# async def test_stop_analysis(client, mock_ids):
#     with patch("BICEP_Utils.fastapi.routes.get_ids_instance", return_value=mock_ids):
#         response = client.post("/analysis/stop")
#         assert response.status_code == status.HTTP_200_OK
#         assert "successfully stopped analysis" in response.text

# @pytest.fixture
# async def temp_file(tmp_path):
#     test_file = tmp_path / "test.txt"
#     return test_file

# @pytest.mark.asyncio
# async def test_save_file(temp_file):
#     class FakeFile:
#         async def read(self):
#             return b"test content"
    
#     fake_file = FakeFile()
#     await save_file(fake_file, temp_file)
    
#     with open(temp_file, "rb") as f:
#         content = f.read()
    
#     assert content == b"test content"

# @pytest.mark.asyncio
# async def test_get_env_variable(monkeypatch):
#     monkeypatch.setenv("TEST_ENV", "test_value")
#     result = await get_env_variable("TEST_ENV")
#     assert result == "test_value"

# @pytest.mark.asyncio
# @patch("asyncio.create_subprocess_exec")
# async def test_execute_command(mock_subprocess):
#     mock_process = AsyncMock()
#     mock_process.pid = 1234
#     mock_subprocess.return_value = mock_process
    
#     command = ["echo", "Hello"]
#     pid = await execute_command(command)
    
#     assert pid == 1234
#     mock_subprocess.assert_called_once_with(*command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# @pytest.mark.asyncio
# @patch("psutil.Process")
# async def test_stop_process(mock_process_class):
#     mock_process = mock_process_class.return_value
#     mock_process.is_running.return_value = True
    
#     await stop_process(1234)
    
#     mock_process.terminate.assert_called_once()

# @pytest.mark.asyncio
# @patch("psutil.Process")
# async def test_wait_for_process_completion(mock_process_class):
#     mock_process = mock_process_class.return_value
#     mock_process.is_running.side_effect = [True, False]
#     mock_process.returncode = 0
    
#     result = await wait_for_process_completion(1234)
    
#     assert result == 0

# @pytest.mark.asyncio
# @patch("BICEP_Utils.general_utilities.execute_command")
# async def test_create_and_activate_network_interface(mock_execute_command):
#     mock_execute_command.return_value = None
    
#     await create_and_activate_network_interface("test0")
    
#     assert mock_execute_command.call_count == 2

# @pytest.mark.asyncio
# @patch("BICEP_Utils.general_utilities.execute_command")
# async def test_mirror_network_traffic_to_interface(mock_execute_command):
#     mock_execute_command.return_value = 1234
    
#     pid = await mirror_network_traffic_to_interface("tap0", "eth0")
    
#     assert pid == 1234
#     mock_execute_command.assert_called_once()

# @pytest.mark.asyncio
# @patch("BICEP_Utils.general_utilities.execute_command")
# async def test_remove_network_interface(mock_execute_command):
#     mock_execute_command.return_value = None
    
#     await remove_network_interface("tap0")
    
#     mock_execute_command.assert_called_once()
