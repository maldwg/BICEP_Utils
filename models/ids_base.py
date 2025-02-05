from abc import ABC, abstractmethod
from ..general_utilities import stop_process
import json 
from http.client import HTTPResponse
import asyncio
import httpx
from ..general_utilities import get_env_variable, wait_for_process_completion, create_and_activate_network_interface, mirror_network_traffic_to_interface, remove_network_interface

class Alert():
    """
    Class which contains the most important fields of an alert (one line of anomaly).
    It presents a standardized interface for the different IDS to map their distinct alerts to.
    """
    time: str
    source_ip: str
    source_port: str
    destination_ip: str
    destination_port: str
    severity: float
    type: str
    message: str

    def __init__(self, time=None, source_ip=None, source_port=None, destination_ip=None, destination_port=None, severity=None, type=None, message=None):
        self.time=time
        self.source_ip=source_ip
        self.source_port=source_port
        self.destination_ip=destination_ip
        self.destination_port=destination_port
        self.severity=severity
        self.type=type
        self.message=message

    @classmethod
    def from_json(cls, json_alert: str):
        # replace none with null to be able to load from json
        json_str = json_alert.replace('None', 'null')
        # replace single quotes with double quotes to be able to load it from json
        json_str = json_str.replace("'",'"')
        alert_dict = json.loads(json_str)
        return Alert(
            time=alert_dict["time"],
            source_ip=alert_dict["source_ip"],
            source_port=alert_dict["source_port"],
            destination_ip=alert_dict["destination_ip"],
            destination_port=alert_dict["destination_port"],
            severity=alert_dict["severity"],
            type=alert_dict["type"],
            message=alert_dict["message"]
        )

    def __str__(self):
        return f"{self.time}, From: {self.source_ip}:{self.source_port}, To: {self.destination_ip}:{self.destination_port}, Type: {self.type}, Content: {self.message}, Severity: {self.severity}"

    def to_dict(self):
        return {
            "time": self.time,  
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "severity": self.severity,
            "type": self.type,
            "message": self.message
        }
    def to_json(self):
        return json.dumps(self.to_dict())

class IDSParser(ABC):


    # use the isoformat as printed below to return the timestamps of the parsed lines
    timestamp_format = '%Y-%m-%dT%H:%M:%S.%f%z'
    
    @property
    @abstractmethod
    async def alert_file_location(self):
        pass

    @abstractmethod
    async def parse_alerts(self) -> list[Alert]:
        """
        Method triggered once after the static analysis is complete or periodically for a network analysis. 
        Takes in the whole file, reads it, parses it, deletes it and returns the parsed lines
        """
        pass

    @abstractmethod
    async def parse_line(self, line) -> Alert:
        """
        Method to parse one line at a time into the Alert object
        """
        pass

    @abstractmethod
    async def normalize_threat_levels(self, threat: int) -> float:
        """
       Normalize the threat levels which are individual for each IDS from 0 to 1 (1 being the highest)
       returns decimal values with only 2 decimals
        """
        pass


    
class IDSBase(ABC):
    """
    Abstract base class for all IDS supported by BICEP
    Each IDS involved needs to inherit from this base class and implement the following methods and attributes
    """
    container_id: int = None
    ensemble_id: int = None
    pids: list[int] = []
    # Id of the dataset used to trigger a static analysis
    dataset_id: int = None
    static_analysis_running: bool = False
    send_alerts_periodically_task = None
    tap_interface_name: str = None
    background_tasks = set()
    
    @property
    @abstractmethod
    async def parser(self):
        pass

    @property
    @abstractmethod
    async def log_location(self):
        pass
    
    @property
    @abstractmethod
    async def configuration_location(self):
        pass

    @abstractmethod
    async def configure(self, file_path) -> str:
        """
        Method for setting up the main configuration file in the corresponding location
        gets a file content as input and needs to save it to the location necesary for the IDS system
        """
        return "base implementation"

    @abstractmethod
    async def configure_ruleset(self, file_path) -> str:
        """
        Method for setting up the main configuration file in the corresponding location
        gets a file content as input and needs to save it to the location necesary for the IDS system
        """
        return "base implementation"


    @abstractmethod
    async def execute_static_analysis_command(self, file_path: str) -> int:
        """
        Method that takes all actions necessary to execute the IDS command for a static analysis using a pcap file.
        Returns a pid of the main process spawned.
        """
        pass

        
    @abstractmethod
    async def execute_network_analysis_command(self) -> int:
        """
        Method that takes all actions necessary to execute the IDS command for a network analysis on the self.tap_interface.
        Returns a pid of the main process spawned.        """
        pass

    async def stop_all_processes(self):
        remove_process_ids = []
        if self.pids != []:
            for pid in self.pids:
                await stop_process(pid)
                remove_process_ids.append(pid)
        for removed_pid in remove_process_ids:
            self.pids.remove(removed_pid)      

    async def send_alerts_to_core_periodically(self, period: float=300):
        try:
            if self.ensemble_id == None:
                endpoint = f"/ids/publish/alerts"
            else:
                endpoint = f"/ensemble/publish/alerts"
            # tell the core to stop/set status to idle again
            core_url = await get_env_variable("CORE_URL")

            while True:
                alerts: list[Alert] = await self.parser.parse_alerts()

                json_alerts = [ a.to_dict() for a in alerts]
                data = {"container_id": self.container_id, "ensemble_id": self.ensemble_id, "alerts": json_alerts, "analysis_type": "network", "dataset_id": None}
                try:
                    async with httpx.AsyncClient() as client:
                        # set timeout to 90 seconds to be able to send all alerts
                        response: HTTPResponse = await client.post(core_url+endpoint, data=json.dumps(data), timeout=90)
                except Exception as e:
                    print("Something went wrong during alert sending... retrying on next iteration")
                await asyncio.sleep(period)

        except asyncio.CancelledError as e:
            print(f"Canceled the sending of alerts")


    async def send_alerts_to_core(self):
        if self.ensemble_id == None:
            endpoint = f"/ids/publish/alerts"
        else:
            endpoint = f"/ensemble/publish/alerts"

        # tell the core to stop/set status to idle again
        core_url = await get_env_variable("CORE_URL")
        alerts: list[Alert] = await self.parser.parse_alerts()
        json_alerts = [ a.to_dict() for a in alerts] 

        data = {"container_id": self.container_id, "ensemble_id": self.ensemble_id, "alerts": json_alerts, "analysis_type": "static", "dataset_id": self.dataset_id}
        
        async with httpx.AsyncClient() as client:
            # set timeout to 600, to be able to send all alerts
            response: HTTPResponse = await client.post(core_url+endpoint, data=json.dumps(data)
                ,timeout=300
            )

        # remove dataset here, becasue removing it in tell_core function removes the id before using it here otehrwise
        if self.dataset_id != None:
            self.dataset_id = None

        return response
    
    # TODO 0: make prints to correct log statements
    async def finish_static_analysis_in_background(self):
        response = await self.send_alerts_to_core()
        print(response)
        res = await self.tell_core_analysis_has_finished()
        print(res)


    async def tell_core_analysis_has_finished(self):
        if self.ensemble_id == None:
            endpoint = f"/ids/analysis/finished"
        else:
            endpoint = f"/ensemble/analysis/finished"

        data = {
            'container_id': self.container_id,
            'ensemble_id': self.ensemble_id
        }
        
        # tell the core to stop/set status to idle again
        core_url = await get_env_variable("CORE_URL")
            # reset ensemble id to wait if next analysis is for ensemble or ids solo

        async with httpx.AsyncClient() as client:
                response: HTTPResponse = await client.post(core_url+endpoint, data=json.dumps(data))

        # reset ensemble id after each analysis is completed to keep track if analysis has been triggered for ensemble or not
        if self.ensemble_id != None:
            self.ensemble_id = None
        return response
    

    async def start_network_analysis(self):
        # set tap name if not done already
        if self.tap_interface_name is None:
            self.tap_interface_name = f"tap{self.container_id}"
        await create_and_activate_network_interface(self.tap_interface_name)
        pid = await mirror_network_traffic_to_interface(default_interface="eth0", tap_interface=self.tap_interface_name)
        self.pids.append(pid)
        start_ids = await self.execute_network_analysis_command()
        self.pids.append(start_ids)
        self.send_alerts_periodically_task = asyncio.create_task(self.send_alerts_to_core_periodically())
        return f"started network analysis for container with {self.container_id}"

    
    async def start_static_analysis(self, file_path):
        pid = await self.execute_static_analysis_command(file_path)
        self.pids.append(pid)

        await wait_for_process_completion(pid)
        self.pids.remove(pid)
        if self.static_analysis_running:
            task= asyncio.create_task(self.finish_static_analysis_in_background())
            self.background_tasks.add(task)
            task.add_done_callback(self.background_tasks.discard)
            self.static_analysis_running = False
        else:
            await self.stop_analysis()            


    # overrides the default method
    async def stop_analysis(self):
        self.static_analysis_running = False
        await self.stop_all_processes()
        if self.send_alerts_periodically_task != None:            
            if not self.send_alerts_periodically_task.done():
                self.send_alerts_periodically_task.cancel()
            self.send_alerts_periodically_task = None
        if self.tap_interface_name != None:
            await remove_network_interface(self.tap_interface_name)
        await self.tell_core_analysis_has_finished()


