from http.client import HTTPResponse
import json
import asyncio
import httpx
from ..models.ids_base import Alert
from ..general_utilities import get_env_variable, ANALYSIS_MODES



async def tell_core_analysis_has_finished(ids):
    if ids.ensemble_id == None:
        endpoint = f"/ids/analysis/finished"
    else:
        endpoint = f"/ensemble/analysis/finished"

    data = {
        'container_id': ids.container_id,
        'ensemble_id': ids.ensemble_id
    }
    
    # tell the core to stop/set status to idle again
    core_url = await get_env_variable("CORE_URL")
        # reset ensemble id to wait if next analysis is for ensemble or ids solo

    async with httpx.AsyncClient() as client:
            response: HTTPResponse = await client.post(core_url+endpoint, data=json.dumps(data))

    # reset ensemble id after each analysis is completed to keep track if analysis has been triggered for ensemble or not
    if ids.ensemble_id != None:
        ids.ensemble_id = None
    return response


async def send_alerts_to_core(ids):
    if ids.ensemble_id == None:
        endpoint = f"/ids/publish/alerts"
    else:
        endpoint = f"/ensemble/publish/alerts"

    # tell the core to stop/set status to idle again
    core_url = await get_env_variable("CORE_URL")
    alerts: list[Alert] = await ids.parser.parse_alerts(ANALYSIS_MODES.STATIC.value)
    json_alerts = [ a.to_dict() for a in alerts] 
    data = {"container_id": ids.container_id, "ensemble_id": ids.ensemble_id, "alerts": json_alerts, "analysis_type": "static", "dataset_id": ids.dataset_id}
    async with httpx.AsyncClient() as client:
        # set timeout to 90, to be able to send all alerts
        response: HTTPResponse = await client.post(core_url+endpoint, data=json.dumps(data), timeout=90)

    # remove dataset here, becasue removing it in tell_core function removes the id before using it here otehrwise
    if ids.dataset_id != None:
        ids.dataset_id = None

    return response


# TODO 0: adjust to 300 secodns
# TODO 0: cant this be includd in the router itself ? has it to be done in each impleemented image ? --> goal reduce dependency knowledge
async def send_alerts_to_core_periodically(ids, period: float=60):
    try:
        if ids.ensemble_id == None:
            endpoint = f"/ids/publish/alerts"
        else:
            endpoint = f"/ensemble/publish/alerts"
        # tell the core to stop/set status to idle again
        core_url = await get_env_variable("CORE_URL")

        while True:
            alerts: list[Alert] = await ids.parser.parse_alerts(ANALYSIS_MODES.NETWORK.value)

            json_alerts = [ a.to_dict() for a in alerts]
            data = {"container_id": ids.container_id, "ensemble_id": ids.ensemble_id, "alerts": json_alerts, "analysis_type": "network", "dataset_id": None}
            try:
                async with httpx.AsyncClient() as client:
                    # set timeout to 90 seconds to be able to send all alerts
                    response: HTTPResponse = await client.post(core_url+endpoint, data=json.dumps(data), timeout=90)
            except Exception as e:
                print("Something went wrong during alert sending... retrying on next iteration")
            await asyncio.sleep(period)

    except asyncio.CancelledError as e:
        print(f"Canceled the sending of alerts")
        
