# -*- coding: UTF-8 -*-
import os
import subprocess
import time
from util import logger
import re
import json

def trueseeing_run(folder_path,report_folder):
    apk_list = os.listdir(folder_path)
    des_path = ''
    logger.info(' [TrueSeeing] Now begin to scan apks using [TrueSeeing]')
    for i in reversed(range(len(apk_list))):
        if not ('.apk' in apk_list[i]):
            del apk_list[i]
        else:
            apk_name = os.path.splitext(apk_list[i])[0]
            trueseeing = apk_name+'_trueseeing.json'
            report_file = os.path.join(report_folder,apk_name)
            if not (os.path.exists(report_file)):
                os.mkdir(report_file)
            tree = os.listdir(report_file)
            if trueseeing in tree:
                del apk_list[i]
    for i in range(len(apk_list)):
        if(apk_list[i].endswith('.apk')):
            try:
                apk_name = os.path.splitext(apk_list[i])[0]
                report_path = os.path.join(apk_name+'_trueseeing.json')
                # apk_path = os.path.join(folder_path,apk_list[i])
                trueseeing_cmd = 'docker run --rm -v '+folder_path+':/out -v ts2:/cache trueseeing  --no-cache --max-graph-size=1048576 --format=json -o '+ report_path +' '+ apk_list[i]
                logger.info(' [TrueSeeing] Scanning process: '+ str(apk_list[i])+ ' '+ str(i+1)+'/'+str(len(apk_list)))
                start_time = time.time()
                p = subprocess.Popen(trueseeing_cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE,
                                shell=True)
                content, err = p.communicate()
                end_time = time.time()
                timedifferece = end_time - start_time
                current_path = os.path.abspath(__file__)
                report_folder_path = os.path.dirname(current_path)
                report_folder_path = os.path.dirname(report_folder_path)
                time_report_folder = os.path.join(report_folder_path,'TimeReport')
                Trueseeing_time_report = os.path.join(time_report_folder,'Trueseeing_time_record.txt')
                with open(Trueseeing_time_report,'a+') as file:
                    file.write(apk_list[i]+': '+ str(timedifferece) + '\n')
                trueseeing_report_add = os.path.join(report_folder,apk_name,apk_name+'_trueseeing.txt')
                apk_report_folder = os.path.join(report_folder,apk_name)
                src_path = os.path.join(folder_path,report_path)
                des_path = os.path.join(report_folder,apk_name,report_path)
                # print(src_path)
                # print(des_path)
                os.rename(src_path,des_path)
                # if not (os.path.exists(apk_report_folder)):
                #     os.mkdir(apk_report_folder)
                #     with open(trueseeing_report_add,'w+') as file:
                #         file.write(content)
                trueseeing_report_pro(des_path)
            except Exception as e:
                logger.critical('\033[1;31m [Trueseeing] Trueseeing scans fiaure: '+apk_list[i]+'\033[0m')
    logger.info(' [TrueSeeing] TrueSeeing scanning is finished !')


def trueseeing_report_pro(report_file):
    apk_report_folder = os.path.dirname(report_file)
    with open (report_file,'r') as json_file:
        json_data = json.load(json_file)['issues']
    
    trueseeing_single_vuln = []
    trueseeing_single_desc = []

    for i in range(len(json_data)):
        json_data[i]['info'] = []
        for key,value in json_data[i].items():
            if(key == u"no" or key == u"solution" or key == u"seealso" or key == u"description" or key == u"cvss3_score" or
               key == u"cvss3_score" or key == u"cvss3_vector" or key == u"severity" or key == u"detector" or key == u"synopsis" ):
                del json_data[i][key]
            if(key == u"instances"):
                for j in range(len(value)):
                    json_data[i]['info'].append(value[j]['info'])
                del json_data[i][key]
        trueseeing_single_vuln.append(json_data[i]['summary'])
        trueseeing_single_desc.append(json_data[i]['info'])

    Trueseeing_vlun_file = os.path.join(apk_report_folder,'Trueseeing_single_vlun_file.txt')
    Trueseeing_desc_file = os.path.join(apk_report_folder,'Trueseeing_single_desc_file.txt')
    with open (Trueseeing_vlun_file,'w+') as f:
        f.write(str(trueseeing_single_vuln))
    with open (Trueseeing_desc_file,'w+') as f:
        f.write(str(trueseeing_single_desc))
