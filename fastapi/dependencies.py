from fastapi import Request
from ..models.ids_base import IDSBase


def get_ids_instance(request: Request) -> IDSBase:
    return request.app.state.ids_instance

def get_analysis_start_time(request: Request):
    return request.app.state.ANALYSIS_START_TIME

def get_analysis_stop_time(request: Request):
    return request.app.state.ANALYSIS_STOP_TIME