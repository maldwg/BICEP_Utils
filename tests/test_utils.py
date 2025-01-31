import pytest
import json
import asyncio
from unittest.mock import AsyncMock, patch
from httpx import Response
from BICEP_Utils.fastapi.utils import tell_core_analysis_has_finished, send_alerts_to_core, send_alerts_to_core_periodically
from BICEP_Utils.models.ids_base import Alert

@pytest.mark.asyncio
@patch("BICEP_Utils.fastapi.utils.get_env_variable", new_callable=AsyncMock)
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_tell_core_analysis_has_finished(mock_post, mock_get_env_variable):
    mock_get_env_variable.return_value = "http://core-url"
    mock_post.return_value = Response(200, json={"status": "success"})
    
    class MockIDS:
        def __init__(self):
            self.container_id = "container123"
            self.ensemble_id = None
    
    ids = MockIDS()
    response = await tell_core_analysis_has_finished(ids)
    
    assert response.status_code == 200

@pytest.mark.asyncio
@patch("BICEP_Utils.fastapi.utils.get_env_variable", new_callable=AsyncMock)
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_send_alerts_to_core(mock_post, mock_get_env_variable):
    mock_get_env_variable.return_value = "http://core-url"
    mock_post.return_value = Response(200, json={"status": "success"})
    
    class MockIDS:
        def __init__(self):
            self.container_id = "container123"
            self.ensemble_id = None
            self.dataset_id = "dataset456"
            self.parser = AsyncMock()
            alert = Alert("test-alert")
            self.parser.parse_alerts.return_value = [alert]
    
    ids = MockIDS()
    response = await send_alerts_to_core(ids)
    
    assert response.status_code == 200
    mock_post.assert_called_once()

@pytest.mark.asyncio
@patch("BICEP_Utils.fastapi.utils.get_env_variable", new_callable=AsyncMock)
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_send_alerts_to_core_periodically(mock_post, mock_get_env_variable):
    mock_get_env_variable.return_value = "http://core-url"
    mock_post.return_value = Response(200, json={"status": "success"})
    
    class MockIDS:
        def __init__(self):
            self.container_id = "container123"
            self.ensemble_id = None
            self.parser = AsyncMock()
            alert = Alert("test-alert")
            self.parser.parse_alerts.return_value = [alert]
    
    ids = MockIDS()
    task = asyncio.create_task(send_alerts_to_core_periodically(ids, period=1))
    await asyncio.sleep(2)  # Allow two iterations
    task.cancel()
    
    assert mock_post.call_count >= 1
