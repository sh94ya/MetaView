import logging
from datetime import datetime
import os

#Logs Path
current_dir = os.path.dirname(os.path.abspath(__file__))
logs_dir = os.path.join(current_dir, '..\logs')
log_file = os.path.join(logs_dir, f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log")

logging.basicConfig(
    level=logging.DEBUG,
    filename=log_file,
    filemode='w',
    format="*** - %(levelname)s - %(asctime)s - %(module)s - %(funcName)s: %(lineno)d - %(message)s")


def getLogger():
    logger = logging.getLogger('simple_example')
    return logger
