# -*- coding: UTF-8 -*-
from threading import Thread
import time
from flask import Flask, redirect, url_for, request, render_template, flash, send_from_directory, jsonify, current_app
from werkzeug.utils import secure_filename
import os
import json
import subprocess
from datetime import datetime
from VulsTotal import run
import logging
import zipfile
# from common_logger import logger
from flask_socketio import SocketIO, emit, send, join_room, close_room, rooms
from util import app,msg_queue
import Queue as queue

# app = Flask(__name__)
# app.config['SECRET_KEY'] = 'secret!'
# socketio = SocketIO(app)
# socketio.init_app(app, cors_allowed_origins='*') 

now_path = os.path.dirname(os.path.abspath(__file__))
upload_apps_path = os.path.join(now_path,'upload_apps')
if not (os.path.exists(upload_apps_path)):
   os.mkdir(upload_apps_path)
app.config['UPLOAD_FOLDER'] = upload_apps_path
app.config['MAX_CONTENT_LENGTH'] = 2*1024*1024*1024

upload_app = os.path.join(now_path,'upload')
if not (os.path.exists(upload_app)):
   os.mkdir(upload_app)

reports_folder = os.path.join(now_path,'VulsTotal_Report')
if not(os.path.exists(reports_folder)):
    os.mkdir(reports_folder)

download_folder = os.path.join(now_path,'Download_res')
if not(os.path.exists(download_folder)):
    os.mkdir(download_folder)

csv_folder = os.path.join(now_path,'CSV_Result')
if not(os.path.exists(csv_folder)):
    os.mkdir(csv_folder)

ALLOWED_EXTENSIONS = {'zip'}

def unzip_file(zip_path,extract_path):
    unzip_cmd = 'unzip ' + zip_path + ' -d '+ extract_path
    p1 = subprocess.Popen(unzip_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    shell=True)
    p1.communicate()
    unzip_file_path = os.path.join(extract_path,os.path.splitext(os.path.basename(zip_path))[0])
    return unzip_file_path

def get_latest(folder):
    files = [os.path.join(folder, f) for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]
    files_with_date = [(f, datetime.fromtimestamp(os.path.getctime(f))) for f in files]
    latest_file = sorted(files_with_date, key=lambda x: x[1])[-1][0]
    return latest_file

def vul_des(true_apk_list):
    rules_path = os.path.join(now_path,'frameworkrule.json')
    rules_file = open(rules_path,'r')
    rules_list = json.load(rules_file)
    rules_file.close()
    for i in range(len(true_apk_list)):
        for j in range(len(true_apk_list[i]['true_vuln_list'])):
            true_apk_list[i]['true_vuln_list'][j] = rules_list[true_apk_list[i]['true_vuln_list'][j]]['title']
            print(true_apk_list[i]['true_vuln_list'][j])
    return true_apk_list
        


@app.route('/')
def index():
    return app.send_static_file('index.html')


@app.route('/upload',methods=['POST','GET'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = secure_filename(f.filename)
        types = ['zip']
        if file_name.split('.')[-1] in types:
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], file_name))
        outinfo = file_name + ' Upload successfully'
        return outinfo
    else:
        return 'error'

@app.route("/analyze",methods = ['POST'])
def analyze():
    msg_queue.queue.clear()
    data = request.get_json(silent=True) 
    stra_option = int(data['stra_option'])
    confiden_option = int(data['confiden_option'])
    filename = str(data['filename'])
    print(stra_option)
    print(confiden_option)
    print(filename)
    analyze_zip_path = os.path.join(upload_apps_path,filename)
    print('analyze_zip_path===='+analyze_zip_path)
    unzip_file_path= unzip_file(analyze_zip_path,upload_app)
    print(unzip_file_path)

    apptree = os.listdir(unzip_file_path)
    for i in reversed(range(len(apptree))):
        if not ('.apk' in apptree[i]):
            del apptree[i]
    vul_length,min_apk_set,all_apk_vul = run(unzip_file_path, stra_option, confiden_option)
    all_apk_vul = vul_des(all_apk_vul)
    appnum = len(apptree)
    minnum = len(min_apk_set)
    filename = os.path.splitext(filename)[0]
    result_json = {
            'filename' : filename,
            'appnum' : appnum,
            'minnum': minnum,
            'minvulnum': vul_length,
            'namedownload': filename,
            'analyload':filename,
            'all_apk_vul':all_apk_vul
        }  
    print(result_json)
    print(msg_queue.qsize())
    return json.dumps(result_json)

@app.route("/logreport",methods = ['GET'])
def flush_queue():
    msg = ''    
    if msg_queue.empty() == False:
        msg = msg_queue.get()
        print(msg)
    # if msg == '':
    #     return None
    # else:
    return msg

is_connect = False

@app.route("/download/<filename>",methods = ['GET'])
def files(filename):
    print('--------------filename'+filename)
    foldername = os.path.join(upload_app,filename)
    folderlist = os.listdir(foldername)
    download = os.path.join(download_folder,filename+'_download.zip')
    with zipfile.ZipFile(download, 'w', zipfile.ZIP_DEFLATED) as zf:
        for i in range(len(folderlist)):
            if(os.path.splitext(folderlist[i])[-1]=='.apk'):
                apkname = os.path.splitext(folderlist[i])[0]
                print(apkname)
                resultfolder = os.path.join(reports_folder,apkname)
                result_tree = os.listdir(resultfolder)
                for i in range(len(result_tree)):
                    if(apkname in result_tree[i] and '_download' not in result_tree[i]):
                        src_file = os.path.join(resultfolder,result_tree[i])
                        zf.write(src_file,os.path.basename(src_file))
    zf.close()
    print(os.path.dirname(download))
    print(os.path.basename(download))
    return send_from_directory(os.path.dirname(download),os.path.basename(download),as_attachment = True)

@app.route("/resultodownload/<filename>",methods = ['GET'])
def resultfiles(filename):
    print('--------------filename-----'+filename)
    download = os.path.join(download_folder,filename+'_minAppSetResult.txt')
    print(os.path.dirname(download))
    print(os.path.basename(download))
    return send_from_directory(os.path.dirname(download),os.path.basename(download),as_attachment = True)

@app.route("/csvdownload/<filename>",methods = ['GET'])
def csvfiles(filename):
    print('--------------filename-----'+filename)
    download = os.path.join(csv_folder,filename+'_final.csv')
    print(os.path.dirname(download))
    print(os.path.basename(download))
    return send_from_directory(os.path.dirname(download),os.path.basename(download),as_attachment = True)

@app.route("/detaileddownload/<filename>",methods = ['GET'])
def detailedfiles(filename):
    reportfolder = os.path.join(reports_folder,filename)
    result_tree = os.listdir(reportfolder)
    download = os.path.join(download_folder,filename+'_single_detailed.zip')
    print('download==='+download)
    with zipfile.ZipFile(download, 'w', zipfile.ZIP_DEFLATED) as zf:
        for i in range(len(result_tree)):
            # print(result_tree[i])
            if(filename in result_tree[i] and '_download' not in result_tree[i]):
                src_file = os.path.join(reportfolder,result_tree[i])
                print(src_file)
                zf.write(src_file,os.path.basename(src_file))
    zf.close()
    print(os.path.dirname(download))
    print(os.path.basename(download))
    return send_from_directory(os.path.dirname(download),os.path.basename(download),as_attachment = True)


@app.route('/<path:fallback>')
def fallback(fallback):      
    if fallback.startswith('css/') or fallback.startswith('js/') or fallback.startswith('img/') or fallback == 'favicon.ico':
        return app.send_static_file(fallback)
    else:
        return app.send_static_file('index.html')


if __name__ == '__main__':
   app.run(debug = True,host='127.0.0.1',threaded=True)
#    socketio.run(app,debug = True,host='127.0.0.1',threaded=True)

