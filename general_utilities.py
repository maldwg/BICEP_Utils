import os
import psutil 
import subprocess
import asyncio
from enum import Enum
import logging
from dateutil import parser 

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        # Ensure logs are printed to stdout
        logging.StreamHandler()  
    ]
)
LOGGER = logging.getLogger(__name__)
# Ensure logs are propagated to Gunicorn
LOGGER.propagate = True  
LOGGER.setLevel(logging.DEBUG)




class ANALYSIS_MODES(Enum):
    STATIC= "static"
    NETWORK ="network"

async def save_file(file, path):
    with open(path, "wb") as f:
        f.write(await file.read())

async def save_dataset(dataset, path):
    with open(path, "wb") as f:
        f.write(dataset)

async def get_env_variable(name: str):
    return os.getenv(name)

async def execute_command_async(
    command,
    cwd=None,
    suppress_output: bool = True,
    raise_on_error: bool = False,
):
    stdout = asyncio.subprocess.DEVNULL if suppress_output else None
    stderr = asyncio.subprocess.DEVNULL if suppress_output else None
    LOGGER.debug(
        f"Starting async command: {command} (cwd={cwd}, suppress_output={suppress_output})"
    )
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=cwd,
            stdout=stdout,
            stderr=stderr,
            stdin=asyncio.subprocess.DEVNULL,
        )
        LOGGER.debug(f"Started async command with pid {process.pid}: {command}")
        return process.pid
    except Exception as e:
        LOGGER.exception(f"Failed to start async command: {command}")
        if raise_on_error:
            raise
        return None

async def normalize_timestamp_for_alert(timestamp_string: str):
    return parser.parse(timestamp_string).replace(tzinfo=None).replace(microsecond=0).isoformat()


async def stop_process(pid: int):
    try:
        process = psutil.Process(pid)
        if process.is_running():
            process.terminate()
    except psutil.NoSuchProcess:
        LOGGER.error(f"No such process with pid {pid}")
    except Exception as e:
        print(e)




async def wait_for_process_completion(pid):
    try:
        process = psutil.Process(pid)
        # Wait for the process to terminate in a non-blocking way by using asyncio.to_thread
        returncode = await asyncio.to_thread(process.wait)
        return returncode
    except psutil.NoSuchProcess:
        LOGGER.error("No such process")
        return None
    


async def create_and_activate_network_interface(tap_interface_name):
    setup_interface = ["ip", "link", "add", tap_interface_name, "type", "dummy"]
    await execute_command_async(setup_interface)
    # ensure, interface is up
    # TODO 10: make this a correct wait by watching for the interface to be created
    await asyncio.sleep(2)
    activate_interface = ["ip", "link", "set", tap_interface_name, "up"]
    await execute_command_async(activate_interface)
    

async def mirror_network_traffic_to_interface(tap_interface: str, default_interface: str="eth0"):
    activate_interface = ["daemonlogger", "-i", default_interface, "-o", tap_interface]
    return await execute_command_async(activate_interface)       

async def remove_network_interface(tap_interface_name):
    remove_interface = ["ip", "link", "delete", tap_interface_name]
    await execute_command_async(remove_interface)
