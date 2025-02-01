import pytest
import json
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from httpx import Response
from src.utils.models.ids_base import Alert
from src.models.suricata import SuricataParser
import shutil
import json
import tempfile
from pathlib import Path
import os


TEST_FILE_LOCATION = "bicep-suricata/src/tests/testfiles"

@pytest.fixture
def parser():
    parser = MyModel()
    parser.alert_file_location = TEST_FILE_LOCATION
    return parser

@pytest.mark.asyncio
async def test_parse_alerts_empty_file(parser):
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        parser.alert_file_location = temp_file.name
    alerts = await parser.parse_alerts()
    assert alerts == [], "Expected empty list for an empty log file"


@pytest.mark.asyncio
async def test_parse_alerts_valid_and_invalid_data(parser):
    # pat to your file of outputted alerts. 
    # valid and invalid lines are expected as not every single line is to be expected to have all necessary information
    original_alert_file = f"{TEST_FILE_LOCATION}/test_alerts_and_anomalies.json"
    temporary_alert_file = f"{TEST_FILE_LOCATION}/test_alerts_and_anomalies_temporary.json"
    shutil.copy(original_alert_file, temporary_alert_file)
    parser.alert_file_location = temporary_alert_file
    print(parser.alert_file_location)
    alerts = await parser.parse_alerts()
    
    # there are 384 entries that should be regarded as valid
    assert len(alerts) == 384
    assert alerts[0].message == "decoder.ipv6.zero_len_padn"
    assert alerts[0].severity == None
    assert alerts[100].message == "SURICATA TCPv4 invalid checksum"
    assert alerts[383].severity == 0.33 

    os.remove(temporary_alert_file)



@pytest.mark.asyncio
async def test_parse_line_valid(parser: SuricataParser):
    # original data
    line_data = # a valid line of the logs of your system

    
    alert = await parser.parse_line(line_data)
    
    assert isinstance(alert, Alert)
    assert alert.message == # expected message
    assert alert.severity == # expected severity
    # If you have multiple types of alerts that you need to distinguish, add more tests like these

@pytest.mark.asyncio
async def test_parse_line_missing_fields(parser: SuricataParser):
    # Missing dest_ip and dest_port
    line_data = # Data line of the format you would expect it to be for your IDS, with missing information such as missing destination IP info
    
    alert = await parser.parse_line(line_data)
    
    assert alert is None, "Expected None due to missing fields"


@pytest.mark.asyncio
async def test_normalize_threat_levels(parser: SuricataParser):   
    assert await parser.normalize_threat_levels(1) == # your expected value
    assert await parser.normalize_threat_levels(2) == # your expected value
    assert await parser.normalize_threat_levels(3) == # your expected value
    assert await parser.normalize_threat_levels(4) is None
    assert await parser.normalize_threat_levels(None) is None
    # Feel free to test with other values as well