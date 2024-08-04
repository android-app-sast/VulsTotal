# -*- coding: UTF-8 -*-
from flask import Flask, request, render_template, flash, send_from_directory, jsonify, current_app
# from flask_socketio import SocketIO
import logging
import Queue as queue
# from flask_cors import CORS


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
# app.config.from_object(__name__)



class SocketIOLogger(logging.Logger):
    
    def __init__(self, name):
        super(SocketIOLogger, self).__init__(name) 
        self.msg_queue = queue.Queue()

    def on_emit_response(self, response):
        print('Emit response:', response)
        if response.get('error'):
            print('Error:', response['error'])


    def info(self, msg, *args, **kwargs):
        super(SocketIOLogger, self).info(msg, *args, **kwargs)  
        self.msg_queue.put(msg)
        # socketio.emit("loginfo", {"message": msg}, callback=self.on_emit_response)


    def warning(self, msg, *args, **kwargs):
        self.msg_queue.put(msg)
        super(SocketIOLogger, self).warning(msg, *args, **kwargs)  
        # socketio.emit("loginfo", {"message": msg})

    def critical(self, msg, *args, **kwargs):
        self.msg_queue.put(msg)
        super(SocketIOLogger, self).critical(msg, *args, **kwargs)  
        # socketio.emit("loginfo", {"message": msg})
        

fh = logging.FileHandler('VulsTotal_pro.log') 
fh.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
console_fmt = logging.Formatter("%(name)s->%(levelname)s->%(asctime)s->%(message)s",datefmt="%Y-%m-%d %H:%M:%S")
# formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(console_fmt)
ch.setFormatter(console_fmt)

logger = SocketIOLogger("[VulsTotal]")
logger.addHandler(fh)
logger.addHandler(ch)


# logger.info('TEST___________________________')
msg_queue = logger.msg_queue