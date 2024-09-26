# -*- coding: UTF-8 -*-
import os
import time
import subprocess
import re
import logging
import ast
import traceback
from util import logger


def marvine_pro(marvine_apks_path,marvin_report_folder,i,j):
    #marvine_apks_path = ../apk/apk.apk
    try:
        logger.info(' [Marvin] Scanning process: '+str(i+1)+'/'+str(j)+' : '+os.path.basename(marvine_apks_path))
        marvin_folder = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        marvin_folder = os.path.join(marvin_folder,'Marvin-static-Analyzer-master')
        os.chdir(marvin_folder)
        marvin_file = os.path.join(marvin_folder,'MarvinStaticAnalyzer.py')
        marvine_cmd = 'python ' + marvin_file + ' ' + marvine_apks_path
        print(marvine_cmd)
        t_begintime = time.time()
        p = subprocess.Popen(marvine_cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            stdin=subprocess.PIPE,
                            shell=True)
        (output, err) = p.communicate()
        app_name = os.path.basename(marvine_apks_path)
        app_name = os.path.splitext(app_name)[0]
        t_end = time.time()
        timedifferece = t_end - t_begintime
        current_path = os.path.abspath(__file__)
        report_folder_path = os.path.dirname(current_path)
        report_folder_path = os.path.dirname(report_folder_path)
        time_report_folder = os.path.join(report_folder_path,'TimeReport')
        Marvine_time_report = os.path.join(time_report_folder,'Marvine_time_record.txt')
        with open(Marvine_time_report,'a+') as file:
            file.write(app_name+': '+ str(timedifferece) + '\n')


        marvin_report_file = os.path.join(marvin_report_folder,app_name, app_name + '_marvin.txt')
        f = open(marvin_report_file, 'w+')
        f.write(output)
        f.write('----------------------')
        f.close()

        # logger.info('Marvin scanning is finished ! '+str(marvine_apks_path))
        # output_apk_scan = output.split('cd')
        pattern = re.compile('\{.*\}')
        single_output  = pattern.findall(output)
        single_output = single_output[0]
        marvn_results_dict = ast.literal_eval(single_output)
        marvin_key_name = []
        marvin_value_name = []
        
        for keys,values in marvn_results_dict.items():
            marvin_key_name.append(keys)
            marvin_value_name.append(values)

        apk_name = os.path.basename(marvine_apks_path)
        marvin_report_path = os.path.join(marvin_report_folder,os.path.splitext(apk_name)[0])
        if not (os.path.exists(marvin_report_path)):
            os.mkdir(marvin_report_path)
        ausera_vlun_file = os.path.join(marvin_report_path,'Marvin_single_vlun_file.txt')
        ausera_desc_file = os.path.join(marvin_report_path,'Marvin_single_desc_file.txt')
        with open (ausera_vlun_file,'w+') as f:
            f.write(str(marvin_key_name))
        with open (ausera_desc_file,'w+') as f:
            f.write(str(marvin_value_name))
    except Exception as e :
        logger.critical('\033[1;31m [Marvin] something wrong happened!____' + str(marvine_apks_path)+'____'+repr(e)+'\033[0m')
        # traceback.print_exc()
    

def marvine_file_gener(marvine_apks_path, marvin_total_vuln,marvin_vuln_desc,
                       marvin_report_folder):
    apk_name = os.listdir(marvine_apks_path)
    for i in reversed(range(len(apk_name))):
        if ('.apk' not in str(apk_name[i])):
            del apk_name[i]
    for i in range(len(apk_name)):
        app_name = os.path.splitext(apk_name[i])[0]
        marvin_report_folders = os.path.join(marvin_report_folder,app_name)
        if not (os.path.exists(marvin_report_folders)):
            os.mkdir(marvin_report_folders)

        marvin_report_file = os.path.join(marvin_report_folders, app_name + '_marvin.txt')
        f = open(marvin_report_file, 'w+')
        for vlun in marvin_total_vuln[i]:
            f.write(vlun)
            f.write('\n')
        for j in range(len(marvin_vuln_desc[i])):
            f.write(str(marvin_vuln_desc[i][j]))
            f.write('\n')           
        f.close()

