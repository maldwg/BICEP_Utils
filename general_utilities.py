import os
import psutil 
import subprocess
import asyncio
from enum import Enum
import logging

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

async def execute_command(command):
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return process.pid
    except Exception as e:
        print(e)
        return None
    

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
        while True:
            process = psutil.Process(pid)
            if process.is_running():
                await asyncio.sleep(1)
            else:
                return process.returncode
    except psutil.NoSuchProcess:
        LOGGER.error("No such process")
        return None 
    


async def create_and_activate_network_interface(tap_interface_name):
    setup_interface = ["ip", "link", "add", tap_interface_name, "type", "dummy"]
    await execute_command(setup_interface)
    # ensure, interface is up
    # TODO 10: make this a correct wait by watching for the interface to be created
    await asyncio.sleep(2)
    activate_interface = ["ip", "link", "set", tap_interface_name, "up"]
    await execute_command(activate_interface)
    

async def mirror_network_traffic_to_interface(tap_interface: str, default_interface: str="eth0"):
    activate_interface = ["daemonlogger", "-i", default_interface, "-o", tap_interface]
    return await execute_command(activate_interface)       

async def remove_network_interface(tap_interface_name):
    remove_interface = ["ip", "link", "delete", tap_interface_name]
    await execute_command(remove_interface)