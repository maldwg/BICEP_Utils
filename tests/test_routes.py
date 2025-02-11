import pytest
import os
import asyncio
import psutil
import subprocess
import json
from unittest.mock import AsyncMock, patch, MagicMock
from starlette.datastructures import UploadFile
from BICEP_Utils.validation.models import NetworkAnalysisData 
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
    mock.configure = AsyncMock(return_value="Succesfully configured")
    mock.start_network_analysis = AsyncMock(return_value="Started Network Analysis")
    mock.configure_ruleset = AsyncMock(return_value = "Succesfully configured Ruleset")
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
    
@patch("BICEP_Utils.fastapi.routes.save_file")
@pytest.mark.asyncio
async def test_ruleset(save_file_mock, mock_ids):
    mock_file = MagicMock(spec=UploadFile)
    response = await ruleset(file=mock_file,ids=mock_ids)
    response_json = json.loads(response.body.decode())
    assert response.status_code == 200
    assert response_json == {'message': mock_ids.configure_ruleset.return_value}
    
@pytest.mark.asyncio
async def test_ruleset_file_is_none(mock_ids):
    mock_file = None
    response = await ruleset(file=mock_file,ids=mock_ids)
    response_json = json.loads(response.body.decode())
    assert response.status_code == 400
    assert response_json == {"error": "No file provided"}
    

@pytest.mark.asyncio
async def test_add_to_ensemble_with_incorrect_id(mock_ids):
    response = await add_to_ensemble(ensemble_id=mock_ids.ensemble_id, ids=mock_ids)
    response_json = json.loads(response.body.decode())
    assert response.status_code == 500
    assert response_json == {"error": "Ensemble ID was None!"}


@pytest.mark.asyncio
async def test_add_to_ensemble(mock_ids):
    mock_ids.ensemble_id = 1
    response = await add_to_ensemble(ensemble_id=mock_ids.ensemble_id, ids=mock_ids)
    response_json = json.loads(response.body.decode())
    assert response.status_code == 200
    assert response_json == {"message": f"Added IDS to ensemble {mock_ids.ensemble_id}"}

@pytest.mark.asyncio
async def test_remove_from_ensemble(mock_ids):
        mock_ids.ensemble_id = 1
        response = await remove_from_ensemble(mock_ids)
        assert response.status_code == 200
        assert mock_ids.ensemble_id == None

@patch("BICEP_Utils.fastapi.routes.save_file")
@pytest.mark.asyncio
async def test_static_analysis(save_file_mock, mock_ids):
    dataset_id = "1"
    dataset = MagicMock(spec=UploadFile)
    response = await static_analysis(ensemble_id=mock_ids.ensemble_id, dataset_id=dataset_id, container_id=mock_ids.container_id, dataset=dataset,ids=mock_ids)
    response_json = json.loads(response.body.decode())
    assert response.status_code == 200
    assert response_json == {"message": f"Started analysis for container {mock_ids.container_id}"}

@patch("BICEP_Utils.fastapi.routes.save_file")
@pytest.mark.asyncio
async def test_static_analysis_no_file_provided(save_file_mock, mock_ids):
    dataset_id = "1"
    dataset = None
    response = await static_analysis(ensemble_id=mock_ids.ensemble_id, dataset_id=dataset_id, container_id=mock_ids.container_id, dataset=dataset,ids=mock_ids)
    response_json = json.loads(response.body.decode())
    assert response.status_code == 400
    assert response_json == {"error": "No file provided"}

@pytest.mark.asyncio
async def test_network_analysis(mock_ids):
    network_analysis_data= NetworkAnalysisData(
        container_id = 1,
        ensemble_id=None
    )
    response = await network_analysis(network_analysis_data=network_analysis_data,ids=mock_ids)
    print(response)
    response_json = json.loads(response.body.decode())
    print(response_json)
    assert response.status_code == 200
    assert response_json == {"message": mock_ids.start_network_analysis.return_value}


@pytest.mark.asyncio
async def test_network_analysis_for_ensemble(mock_ids):
    network_analysis_data= NetworkAnalysisData(
        container_id = 1,
        ensemble_id=1
    )
    response = await network_analysis(network_analysis_data=network_analysis_data,ids=mock_ids)
    response_json = json.loads(response.body.decode())
    assert response.status_code == 200
    assert response_json == {"message": mock_ids.start_network_analysis.return_value}
    assert mock_ids.ensemble_id == network_analysis_data.ensemble_id

@pytest.mark.asyncio
async def test_stop_analysis(mock_ids):
    mock_ids.dataset_id = 2
    mock_ids.ensemble_id = 3
    response = await stop_analysis(ids=mock_ids)
    resposne_json = json.loads(response.body.decode())
    assert response.status_code == 200
    assert resposne_json == {'message': 'successfully stopped analysis'}
    assert mock_ids.dataset_id == None
    assert mock_ids.ensemble_id == None