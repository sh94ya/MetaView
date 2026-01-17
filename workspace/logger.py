import logging

logging.basicConfig(
    level=logging.DEBUG,
    filename=".\\logs\Logs.txt",
    filemode='w',
    format="*** - %(levelname)s - %(asctime)s - %(module)s - %(funcName)s: %(lineno)d - %(message)s")

def getLogger():
    logger = logging.getLogger('simple_example')
    return logger
