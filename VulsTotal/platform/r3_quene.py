import logging
import re
import datetime
import queue
mq = queue.Queue()

class R3:
    logger = logging.getLogger("[VulsTotal]")  

    @staticmethod
    def put(item, level="INFO"):
        dtf = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mq.put(f"{dtf}[{level}]: {item}")

    @staticmethod
    def debug(item, log=True):
        R3.put(item, level="DEBUG")
        if log:
            R3.logger.debug(item)   
            
    @staticmethod
    def info(item, log=True):
        R3.put(item, level="INFO")
        if log:
            R3.logger.info(item)    

    @staticmethod
    def warning(item, log=True):
        R3.put(item, level="WARNING")
        if log:
            R3.logger.warning(item)    

    @staticmethod
    def error(item, log=True):
        R3.put(item, level="ERROR")
        if log:
            R3.logger.error(item)   

    @staticmethod
    def critical(item, log=True):
        R3.put(item, level="CRITICAL")
        if log:
            R3.logger.critical(item)  

    @staticmethod
    def get(count):
        data = []
        if mq.empty():
            return data
        pattern = re.compile(r"^.*?\[(INFO|ERROR|WARNING|DEBUG)]:.*$")
        try:
            for _ in range(count):
                item = mq.get_nowait()
                mq.task_done()
                match = re.match(pattern, item)
                message_level = match.group(1) if match else "INFO"
                data.append({"message": item, "level": message_level})
            return data
        except queue.Empty:
            return data  

r3 = R3