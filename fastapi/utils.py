
from ..models.ids_base import Alert

async def alert_stream(alerts: Alert):
    for alert in alerts:
        yield alert.to_json()
               
               
