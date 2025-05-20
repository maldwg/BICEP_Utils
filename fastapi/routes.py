from http.client import HTTPException
from typing import Optional

from fastapi import APIRouter, Depends, UploadFile, Form, Response
from fastapi.responses import JSONResponse
from ..models.ids_base import IDSBase
from .dependencies import get_ids_instance
from ..general_utilities import save_file, LOGGER
from ..validation.models import NetworkAnalysisData
import asyncio
import shutil
router = APIRouter()

@router.get("/healthcheck")
async def healthcheck():
    LOGGER.info("Helathcheck succsessful")
    return JSONResponse({"message": "healthy"}, status_code = 200)


# TODO 10: send status codeds and response objects every time

@router.post("/configuration")
async def configure(container_id: str = Form(...) , file: UploadFile = Form(...)  ,ids: IDSBase = Depends(get_ids_instance)):
    if file is None:
        return JSONResponse({"error": "No file provided"}, status_code = 400)
    
    # initialize container id variable to keep track which container is associated with the ids instance
    ids.container_id = int(container_id)

    temporary_file_path = "/tmp/temporary.txt"
    await save_file(file, temporary_file_path)
    response = await ids.configure(temporary_file_path)
    LOGGER.debug("Configured system by adding main config file")
    return JSONResponse({"message": response}, status_code = 200)

@router.post("/configure/ensemble/add/{ensemble_id}")
async def add_to_ensemble(ensemble_id: int, ids: IDSBase = Depends(get_ids_instance)):
    ids.ensemble_id = ensemble_id
    if ensemble_id is None:
        LOGGER.error(f"Failed to add container to ensemble with Ensemble ID = None")
        return JSONResponse({"error": "Ensemble ID was None!"}, status_code=500)
    LOGGER.info(f"Sucessfully added container to ensmeble {ensemble_id}")
    return JSONResponse({"message": f"Added IDS to ensemble {ensemble_id}"}, status_code=200)

@router.post("/configure/ensemble/remove")
async def remove_from_ensemble(ids: IDSBase = Depends(get_ids_instance)):
    former_id = ids.ensemble_id
    ids.ensemble_id = None
    LOGGER.info(f"Removed container from ensemble {former_id}")
    return JSONResponse({"message": f"Removed IDS to ensemble {former_id}"}, status_code = 200)


@router.post("/ruleset")
async def ruleset(file: UploadFile = None ,ids: IDSBase = Depends(get_ids_instance)):
    if file is None:
        return JSONResponse({"error": "No file provided"}, status_code = 400)

    temporary_file_path = "/tmp/temporary.txt"
    await save_file(file, temporary_file_path)
    response = await ids.configure_ruleset(temporary_file_path)
    LOGGER.debug(f"configured ruleset sucessfully")
    return JSONResponse({"message": response}, status_code = 200)


@router.post("/analysis/static")
async def static_analysis(ensemble_id: Optional[str] = Form(None), dataset_id: str = Form(...), container_id: str = Form(...), dataset: UploadFile = Form(...), ids: IDSBase = Depends(get_ids_instance)):
    if dataset is None:
        return JSONResponse({"error": "No file provided"}, status_code = 400)
    
    if ensemble_id != None:
        ids.ensemble_id = int(ensemble_id)

    ids.dataset_id = dataset_id
    temporary_file_path = "/tmp/dataset.pcap"
    
    with open(temporary_file_path, "wb") as f_out:
        shutil.copyfileobj(dataset.file, f_out)
    
    asyncio.create_task(ids.start_static_analysis(temporary_file_path))
    LOGGER.info(f"Started static analysis for dataset with ID {dataset_id}")
    ids.static_analysis_running = True
    http_response = JSONResponse({"message": f"Started analysis for container {container_id}"}, status_code=200)

    return http_response

@router.post("/analysis/network")
async def network_analysis(network_analysis_data: NetworkAnalysisData, ids: IDSBase = Depends(get_ids_instance)):
    if network_analysis_data.ensemble_id != None:
        ids.ensemble_id = network_analysis_data.ensemble_id

    response = await ids.start_network_analysis()
    LOGGER.info(f"Started network analysis")
    return JSONResponse({"message": response}, status_code=200)


@router.post("/analysis/stop")
async def stop_analysis(ids: IDSBase = Depends(get_ids_instance)):
    await ids.stop_analysis()  

    # reset ensemble id to wait if next analysis is for ensemble or ids solo
    if ids.ensemble_id != None:
        ids.ensemble_id = None
  
    if ids.dataset_id != None:
        ids.dataset_id = None
    LOGGER.info(f"Stopped analysis succesfully")
    return JSONResponse({"message": "successfully stopped analysis"}, status_code=200)
