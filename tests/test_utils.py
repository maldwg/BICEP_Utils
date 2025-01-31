import pytest
import json
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from httpx import Response
from BICEP_Utils.fastapi.utils import tell_core_analysis_has_finished, send_alerts_to_core, send_alerts_to_core_periodically
from BICEP_Utils.models.ids_base import Alert, IDSParser, IDSBase

@pytest.fixture
def mock_alert_list():
    alert1 = Alert(
                    time= "2025-01-01T12:00:00Z",
                    destination_ip= "192.168.0.1",
                    destination_port= "8080",
                    source_ip= "10.0.0.1",
                    source_port= "1234",
                    severity= 0,
                    type= "test alert",
                    message = "Test alert message"
        )
    alert2 = Alert(
                    time= "2025-01-01T13:00:00Z",
                    destination_ip= "169.168.0.1",
                    destination_port= "3200",
                    source_ip= "10.0.0.1",
                    source_port= "1234",
                    severity= 1,
                    type= "test alert 2",
                    message = "Test alert 2 message"
        )
    alert3 = Alert(
                    time= "2025-01-01T14:00:00Z",
                    destination_ip= "0.0.0.1",
                    destination_port= "10230",
                    source_ip= "10.0.0.1",
                    source_port= "5678",
                    severity= 0,
                    type= "test alert 3",
                    message = "Test alert 3 message"
        )
    return [alert1,alert2,alert3]


@pytest.fixture
def mock_ids(mock_alert_list):
    mock_parser = MagicMock(spec=IDSParser)
    mock_parser.parse_alerts = AsyncMock() 
    mock_parser.parse_alerts.return_value = mock_alert_list

    mock = AsyncMock(spec=IDSBase)
    mock.container_id = 1
    mock.ensemble_id = None
    mock.configure = AsyncMock(return_value="Test")
    mock.startNetworkAnalysis = AsyncMock(return_value="Started Network Analysis")
    mock.parser = mock_parser

    return mock

@pytest.mark.asyncio
@patch("BICEP_Utils.fastapi.utils.get_env_variable", new_callable=AsyncMock)
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_tell_core_analysis_has_finished_for_ensemble(mock_post, mock_get_env_variable, mock_ids):
    mock_get_env_variable.return_value = "http://core-url"
    mock_post.return_value = Response(200, json={"status": "success"})
    mock_ids.ensemble_id = 1
    response = await tell_core_analysis_has_finished(mock_ids)
    
    assert response.status_code == 200
    assert mock_ids.ensemble_id == None

@pytest.mark.asyncio
@patch("BICEP_Utils.fastapi.utils.get_env_variable", new_callable=AsyncMock)
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_tell_core_analysis_has_finished(mock_post, mock_get_env_variable, mock_ids):
    mock_get_env_variable.return_value = "http://core-url"
    mock_post.return_value = Response(200, json={"status": "success"})
    
    response = await tell_core_analysis_has_finished(mock_ids)
    
    assert response.status_code == 200


@pytest.mark.asyncio
@patch("BICEP_Utils.fastapi.utils.get_env_variable", new_callable=AsyncMock)
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_send_alerts_to_core(mock_post, mock_get_env_variable, mock_ids):
    mock_get_env_variable.return_value = "http://core-url"
    mock_post.return_value = Response(200, json={"status": "success"})
    mock_ids.dataset_id = 1
    response = await send_alerts_to_core(mock_ids)
    
    assert response.status_code == 200
    assert mock_ids.dataset_id == None
    mock_post.assert_called_once()

@pytest.mark.asyncio
@patch("BICEP_Utils.fastapi.utils.get_env_variable", new_callable=AsyncMock)
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_send_alerts_to_core_ensemble(mock_post, mock_get_env_variable, mock_ids):
    mock_get_env_variable.return_value = "http://core-url"
    mock_post.return_value = Response(200, json={"status": "success"})
    mock_ids.dataset_id = 1
    mock_ids.ensemble_id = 1
    response = await send_alerts_to_core(mock_ids)
    
    assert response.status_code == 200
    assert mock_ids.dataset_id == None
    mock_post.assert_called_once()


@pytest.mark.asyncio
@patch("BICEP_Utils.fastapi.utils.get_env_variable", new_callable=AsyncMock)
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_send_alerts_to_core_periodically(mock_post, mock_get_env_variable, mock_ids):
    mock_get_env_variable.return_value = "http://core-url"
    mock_post.return_value = Response(200, json={"status": "success"})

    task = asyncio.create_task(send_alerts_to_core_periodically(mock_ids, period=1))
    await asyncio.sleep(2)
    task.cancel()
    
    assert mock_post.call_count >= 1


@pytest.mark.asyncio
@patch("BICEP_Utils.fastapi.utils.get_env_variable", new_callable=AsyncMock)
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_send_alerts_to_core_periodically_ensemble(mock_post, mock_get_env_variable, mock_ids):
    mock_get_env_variable.return_value = "http://core-url"
    mock_post.return_value = Response(200, json={"status": "success"})
    mock_ids.ensemble_id = 1
    task = asyncio.create_task(send_alerts_to_core_periodically(mock_ids, period=1))
    await asyncio.sleep(2)
    task.cancel()
    
    assert mock_post.call_count >= 1


@pytest.mark.asyncio
@patch("BICEP_Utils.fastapi.utils.get_env_variable", new_callable=AsyncMock)
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_send_alerts_to_core_periodically_exception(mock_post, mock_get_env_variable, mock_ids):
    mock_get_env_variable.return_value = "http://core-url"
    # First call raises an exception, second call returns a mock response
    mock_post.side_effect = [Exception("Oh no, something went wrong"), MagicMock(status_code=200)]
    mock_ids.ensemble_id = 1
    task = asyncio.create_task(send_alerts_to_core_periodically(mock_ids, period=1))
    # Ensure at least two iterations run
    await asyncio.sleep(2.5)  
    task.cancel()
    assert mock_post.call_count >= 2  # Ensure it was called at least twice
    # Verify second call was correct
    assert mock_post.call_args_list[1][0][0] == "http://core-url/ensemble/publish/alerts" 
