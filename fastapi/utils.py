
from ..models.ids_base import Alert
from ..general_utilities import save_dataset

async def alert_stream(alerts: Alert):
    for alert in alerts:
        yield alert.to_json()
               
async def save_dataset_and_start_static_analysis(ids, dataset, file_path):
    await save_dataset(dataset, file_path)
    await ids.start_static_analysis(file_path)
