# -*- coding: UTF-8 -*-
import logging
# from flask_socketio import SocketIO, emit
from server import socketio

class SocketIOLogger(logging.Logger):
    def __init__(self, name):
        super(SocketIOLogger, self).__init__(name) 
        fh = logging.FileHandler('VulsTotal_pro.log') 
        fh.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        console_fmt = logging.Formatter("%(name)s->%(levelname)s->%(asctime)s->%(message)s",datefmt="%Y-%m-%d %H:%M:%S")
        # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(console_fmt)
        ch.setFormatter(console_fmt)
        self.addHandler(fh)
        self.addHandler(ch)


    def info(self, msg, *args, **kwargs):
        print('socket TEST--------------------')
        super(SocketIOLogger, self).info(msg, *args, **kwargs)  
        socketio.emit("log", {"message": msg})
        

    def warning(self, msg, *args, **kwargs):
        super(SocketIOLogger, self).warning(msg, *args, **kwargs)  
        socketio.emit("log", {"message": msg})

    def critical(self, msg, *args, **kwargs):
        super(SocketIOLogger, self).critical(msg, *args, **kwargs)  
        socketio.emit("log", {"message": msg})

logger = SocketIOLogger("[VulsTotal]")
logger.info("服务器启动成功") # 会自动发送给websocket

# logger = logging.getLogger('[VulsTotal]') 
# logger.setLevel(logging.INFO)
# fh = logging.FileHandler('VulsTotal_pro.log')
# fh.setLevel(logging.DEBUG)
# ch = logging.StreamHandler()
# ch.setLevel(logging.DEBUG)
# console_fmt = logging.Formatter("%(name)s->%(levelname)s->%(asctime)s->%(message)s",datefmt="%Y-%m-%d %H:%M:%S")
# # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# fh.setFormatter(console_fmt)
# ch.setFormatter(console_fmt)
# logger.addHandler(fh)
# logger.addHandler(ch)
