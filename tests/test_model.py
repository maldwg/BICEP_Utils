import pytest
import json
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from httpx import Response
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



class MockIDS(IDSBase):
        async def parser(self):
            pass

        async def log_location(self):
            pass

        async def configuration_location(self):
            pass

        async def configure(self, file_path):
            pass

        async def configure_ruleset(self, file_path):
            pass

        async def execute_static_analysis_command(self, file_path: str):
            pid = 789
            return pid

        async def execute_network_analysis_command(self):
            pid = 456
            return pid  
        

@pytest.fixture
def mock_ids(mock_alert_list):
    mock_parser = MagicMock(spec=IDSParser)
    mock_parser.parse_alerts = AsyncMock() 
    mock_parser.parse_alerts.return_value = mock_alert_list

    mock = MockIDS()
    mock.container_id = 1
    mock.ensemble_id = None
    mock.parser = mock_parser

    return mock

@pytest.mark.asyncio
async def test_alerts_from_json_with_double_quotes():
    double_quoted_alerts = [
        "{'time': '2017-07-07T12:17:48', 'source_ip': '192.168.10.15', 'source_port': '49820', 'destination_ip': '23.208.163.130', 'destination_port': '80', 'severity': 0.5, 'type': 'Unknown Traffic', 'message': \"(http_inspect) 'HTTP' in version field not all upper case\"}",
        "{'time': '2017-07-04T12:29:11', 'source_ip': '192.168.10.14', 'source_port': '50205', 'destination_ip': '23.52.150.84', 'destination_port': '80', 'severity': 0.5, 'type': 'Unknown Traffic', 'message': \"(http_inspect) 'HTTP' in version field not all upper case\"}",  
        "{'time': '2017-07-04T18:16:37', 'source_ip': '192.168.10.15', 'source_port': '57005', 'destination_ip': '23.66.190.240', 'destination_port': '80', 'severity': 0.5, 'type': 'Unknown Traffic', 'message': \"(http_inspect) 'HTTP' in version field not all upper case\"}",
        "{'time': '2017-07-04T12:29:11', 'source_ip': '192.168.10.14', 'source_port': '50205', 'destination_ip': '23.52.150.84', 'destination_port': '80', 'severity': 0.5, 'type': 'NA', 'message': \"(http_inspect) 'HTTP' in version field not all upper case\"}",  
        "{'time': '2017-07-05T11:55:25', 'source_ip': '192.168.10.25', 'source_port': '49223', 'destination_ip': '23.15.4.16', 'destination_port': '80', 'severity': 0.5, 'type': 'NA', 'message': \"(http_inspect) 'HTTP' in version field not all upper case\"}"
    ]
    parsed_alerts = []
    for alert_string in double_quoted_alerts:
        try:
            parsed_alerts.append(Alert.from_json(alert_string))
        except Exception as e:
            print(f"Could not parse alert {alert_string}")
            assert False
    assert True

@pytest.mark.asyncio
@patch("BICEP_Utils.models.ids_base.get_env_variable", new_callable=AsyncMock)
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_tell_core_analysis_has_finished_for_ensemble(mock_post, mock_get_env_variable, mock_ids: MockIDS):
    mock_get_env_variable.return_value = "http://core-url"
    mock_post.return_value = Response(200, json={"status": "success"})
    mock_ids.ensemble_id = 1
    response = await mock_ids.tell_core_analysis_has_finished()
    
    assert response.status_code == 200
    assert mock_ids.ensemble_id == None

@pytest.mark.asyncio
@patch("BICEP_Utils.models.ids_base.get_env_variable", new_callable=AsyncMock)
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_tell_core_analysis_has_finished(mock_post, mock_get_env_variable, mock_ids: MockIDS):
    mock_get_env_variable.return_value = "http://core-url"
    mock_post.return_value = Response(200, json={"status": "success"})
    
    response = await mock_ids.tell_core_analysis_has_finished()
    
    assert response.status_code == 200


@pytest.mark.asyncio
@patch("BICEP_Utils.models.ids_base.get_env_variable", new_callable=AsyncMock)
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_send_alerts_to_core(mock_post, mock_get_env_variable, mock_ids: MockIDS):
    mock_get_env_variable.return_value = "http://core-url"
    mock_post.return_value = Response(200, json={"status": "success"})
    mock_ids.dataset_id = 1
    response = await mock_ids.send_alerts_to_core()
    
    assert response.status_code == 200
    assert mock_ids.dataset_id == None
    mock_post.assert_called_once()

@pytest.mark.asyncio
@patch("BICEP_Utils.models.ids_base.get_env_variable", new_callable=AsyncMock)
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_send_alerts_to_core_ensemble(mock_post, mock_get_env_variable, mock_ids: MockIDS):
    mock_get_env_variable.return_value = "http://core-url"
    mock_post.return_value = Response(200, json={"status": "success"})
    mock_ids.dataset_id = 1
    mock_ids.ensemble_id = 1
    response = await mock_ids.send_alerts_to_core()
    
    assert response.status_code == 200
    assert mock_ids.dataset_id == None
    mock_post.assert_called_once()


@pytest.mark.asyncio
@patch("BICEP_Utils.models.ids_base.get_env_variable", new_callable=AsyncMock)
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_send_alerts_to_core_periodically(mock_post, mock_get_env_variable, mock_ids: MockIDS):
    mock_get_env_variable.return_value = "http://core-url"
    mock_post.return_value = Response(200, json={"status": "success"})

    task = asyncio.create_task(mock_ids.send_alerts_to_core_periodically(period=1))
    await asyncio.sleep(2)
    task.cancel()
    
    assert mock_post.call_count >= 1


@pytest.mark.asyncio
@patch("BICEP_Utils.models.ids_base.get_env_variable", new_callable=AsyncMock)
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_send_alerts_to_core_periodically_ensemble(mock_post, mock_get_env_variable, mock_ids: MockIDS):
    mock_get_env_variable.return_value = "http://core-url"
    mock_post.return_value = Response(200, json={"status": "success"})
    mock_ids.ensemble_id = 1
    task = asyncio.create_task(mock_ids.send_alerts_to_core_periodically(period=1))
    await asyncio.sleep(2)
    task.cancel()
    
    assert mock_post.call_count >= 1


@pytest.mark.asyncio
@patch("BICEP_Utils.models.ids_base.get_env_variable", new_callable=AsyncMock)
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_send_alerts_to_core_periodically_exception(mock_post, mock_get_env_variable, mock_ids: MockIDS):
    mock_get_env_variable.return_value = "http://core-url"
    # First call raises an exception, second call returns a mock response
    mock_post.side_effect = [Exception("Oh no, something went wrong"), MagicMock(status_code=200)]
    mock_ids.ensemble_id = 1
    task = asyncio.create_task(mock_ids.send_alerts_to_core_periodically(period=1))
    # Ensure at least two iterations run
    await asyncio.sleep(2.5)  
    task.cancel()
    assert mock_post.call_count >= 2  # Ensure it was called at least twice
    # Verify second call was correct
    assert mock_post.call_args_list[1][0][0] == "http://core-url/ensemble/publish/alerts" 

@patch("BICEP_Utils.models.ids_base.stop_process", new_callable=AsyncMock)
@pytest.mark.asyncio
async def test_stop_all_processes(mock_stop_process, mock_ids: MockIDS):
    mock_ids.pids = [111, 222, 333]
    
    await mock_ids.stop_all_processes()
    
    assert mock_ids.pids == []
    assert mock_stop_process.call_count == 3  



@patch("BICEP_Utils.models.ids_base.stop_process", new_callable=AsyncMock)
@pytest.mark.asyncio
async def test_stop_all_processes_without_process_numbers(mock_stop_process, mock_ids: MockIDS):
    mock_ids.pids = []
    
    await mock_ids.stop_all_processes()
    
    assert mock_ids.pids == [] 
    assert mock_stop_process.call_count == 0  

@patch("BICEP_Utils.models.ids_base.IDSBase.send_alerts_to_core", new_callable=AsyncMock)
@patch("BICEP_Utils.models.ids_base.IDSBase.tell_core_analysis_has_finished", new_callable=AsyncMock)
@pytest.mark.asyncio
async def test_finish_static_analysis_in_background(mock_tell_core, mock_send_alerts, mock_ids: MockIDS):
    mock_send_alerts.return_value = "Alerts Sent"
    mock_tell_core.return_value = "Analysis Finished"
    
    await mock_ids.finish_static_analysis_in_background()
    
    mock_send_alerts.assert_called_once()
    mock_tell_core.assert_called_once()

@patch("BICEP_Utils.models.ids_base.create_and_activate_network_interface", new_callable=AsyncMock)
@patch("BICEP_Utils.models.ids_base.mirror_network_traffic_to_interface", new_callable=AsyncMock)
@pytest.mark.asyncio
async def test_start_network_analysis(mock_mirror, mock_create_interface, mock_ids: MockIDS):
    mock_ids.tap_interface_name = "tap0"
    
    mock_mirror.return_value = 888
    network_analysis_pid = await mock_ids.execute_network_analysis_command()
    response = await mock_ids.start_network_analysis()
    
    mock_create_interface.assert_called_once_with("tap0")
    mock_mirror.assert_called_once()
    
    assert mock_mirror.return_value in mock_ids.pids
    assert network_analysis_pid in mock_ids.pids  
    assert mock_ids.send_alerts_periodically_task is not None
    assert response == f"started network analysis for container with {mock_ids.container_id}"

@patch("BICEP_Utils.models.ids_base.IDSBase.tell_core_analysis_has_finished", new_callable=AsyncMock)
@patch("BICEP_Utils.models.ids_base.wait_for_process_completion", new_callable=AsyncMock)
@pytest.mark.asyncio
async def test_start_static_analysis_if_no_other_analysis_task_running_in_background(mock_wait_for_process,tell_core_has_finished_mock,  mock_ids: MockIDS):
    mock_ids.static_analysis_running = False  
    static_analysis_pid = await mock_ids.execute_static_analysis_command("test.pcap")
    await mock_ids.start_static_analysis("test.pcap")
    
    mock_wait_for_process.assert_called_once_with(static_analysis_pid)
    assert static_analysis_pid not in mock_ids.pids 


@patch("BICEP_Utils.models.ids_base.wait_for_process_completion", new_callable=AsyncMock)
@pytest.mark.asyncio
async def test_start_static_analysis(mock_wait_for_process, mock_ids: MockIDS):
    mock_ids.static_analysis_running = True  
    static_analysis_pid = await mock_ids.execute_static_analysis_command("test.pcap")
    await mock_ids.start_static_analysis("test.pcap")
    
    assert static_analysis_pid not in mock_ids.pids 
    assert mock_ids.static_analysis_running == False

@patch("BICEP_Utils.models.ids_base.IDSBase.stop_all_processes", new_callable=AsyncMock)
@patch("BICEP_Utils.models.ids_base.IDSBase.tell_core_analysis_has_finished", new_callable=AsyncMock)
@pytest.mark.asyncio
async def test_stop_static_analysis(mock_tell_core, mock_stop_all, mock_ids: MockIDS):
  
    mock_ids.send_alerts_periodically_task = None 
    mock_ids.tap_interface_name = None
    
    await mock_ids.stop_analysis()
    
    mock_stop_all.assert_called_once()
    mock_tell_core.assert_called_once()

@patch("BICEP_Utils.models.ids_base.remove_network_interface", new_callable=AsyncMock)
@patch("BICEP_Utils.models.ids_base.IDSBase.stop_all_processes", new_callable=AsyncMock)
@patch("BICEP_Utils.models.ids_base.IDSBase.tell_core_analysis_has_finished", new_callable=AsyncMock)
@pytest.mark.asyncio
async def test_stop_network_analysis(mock_tell_core, mock_stop_all, mock_remove_interface, mock_ids: MockIDS):
  
    mock_ids.send_alerts_periodically_task = asyncio.create_task(asyncio.sleep(5))
    mock_ids.tap_interface_name = "tap0"
    
    await mock_ids.stop_analysis()
    
    mock_stop_all.assert_called_once()
    assert mock_ids.send_alerts_periodically_task is None 
    mock_remove_interface.assert_called_once_with("tap0")
    mock_tell_core.assert_called_once()