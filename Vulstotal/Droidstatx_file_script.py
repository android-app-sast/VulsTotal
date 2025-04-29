# -*- coding: UTF-8 -*-
import os
import platform
import subprocess
import time
from util import logger
import re
import shutil

def droidstatx_run(folder_path,report_folder):
    current_path = os.path.abspath(__file__)
    platform_folder_path = os.path.dirname(current_path)
    vulstotal_folder_path = os.path.dirname(platform_folder_path)
    droidstatx_file = os.path.join(vulstotal_folder_path,'droidstatx-master/droidstatx.py')
    apk_list = os.listdir(folder_path)
    logger.info(' [DroidStatx] Now begin to scan apks using [DroidStatx]')
    for i in reversed(range(len(apk_list))):
        if not ('.apk' in apk_list[i]):
            del apk_list[i]
        else:
            apk_name = os.path.splitext(apk_list[i])[0]
            apkhunt = apk_name+'_droidstatx.txt'
            report_file = os.path.join(report_folder,apk_name)
            if not (os.path.exists(report_file)):
                os.mkdir(report_file)
            tree = os.listdir(report_file)
            if apkhunt in tree:
                del apk_list[i]

    for i in range(len(apk_list)):
        if(apk_list[i].endswith('.apk')):
            apk_name = os.path.splitext(apk_list[i])[0]
            apk_abs_path = os.path.join(folder_path,apk_list[i])
            logger.info('[DroidStatx] Scanning process: ' + str(apk_list[i])+ ' '+ str(i+1)+'/'+str(len(apk_list)))
            droidstatx_cmd = 'python3 ' + droidstatx_file + ' --apk '+ apk_abs_path
            start_time = time.time()
            p = subprocess.Popen(droidstatx_cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE,
                            shell=True)
            p.communicate()
            end_time = time.time()
            timedifferece = end_time - start_time
            current_path = os.path.abspath(__file__)
            report_folder_path = os.path.dirname(current_path)
            report_folder_path = os.path.dirname(report_folder_path)
            time_report_folder = os.path.join(report_folder_path,'TimeReport')
            DroidStatx_time_report = os.path.join(time_report_folder,'DroidStatx_time_record.txt')
            with open(DroidStatx_time_report,'a+') as file:
                file.write(apk_list[i]+': '+ str(timedifferece) + '\n')
            apk_report_folder = os.path.join(report_folder,apk_name)
            if not (os.path.exists(apk_report_folder)):
                os.mkdir(apk_report_folder)
            out_report_folder = os.path.join(vulstotal_folder_path,'droidstatx-master/output_txt')
            src_file = os.path.join(out_report_folder,apk_name+'_droidstatx.txt')
            des_file = os.path.join(apk_report_folder,apk_name+'_droidstatx.txt')
            droidstatx_xmind = os.path.join(os.path.dirname(out_report_folder),'output_xmind')
            droidstatx_apktoolfolder = os.path.join(os.path.dirname(out_report_folder),'output_apktool')
            xmind_tree = os.listdir(droidstatx_xmind)
            for folder in xmind_tree:
                abs_folder = os.path.join(droidstatx_xmind,folder)
                os.remove(abs_folder)
            apktool_tree = os.listdir(droidstatx_apktoolfolder)
            for folder in apktool_tree:
                abs_folder = os.path.join(droidstatx_apktoolfolder,folder)
                shutil.rmtree(abs_folder)

            try:
                os.rename(src_file,des_file)
            except Exception:
                logger.critical('\033[1;31m [DroidStatx] Move file failed! \033[0m')
            try:
                droidstatx_report_pro(des_file)
            except Exception:
                logger.critical('\033[1;31m [DroidStatx] Report Process filed \033[0m')            
    logger.info(' [DroidStatx] DroidStatx scanning is finished !')

def droidstatx_report_pro(report_file):
    apk_report_folder = os.path.dirname(report_file)
    vulns = {}
    with open(report_file,'r') as file:
        contents = file.readlines()
    for line in contents:
        key, value = line.strip().split(':',1)
        vulns[key] = value
    droid_vulns = []
    droid_desc = []
    for keys, values in vulns.items():
        if not (values == ' []' ):
            if (keys == 'networkSecurityConfigDomains'):
                dict = eval(values)[0]
                for smallkeys, smallvalues in dict.items():
                    if(smallkeys == 'allowClearText' and smallvalues == True):
                        droid_vulns.append(smallkeys)
                        droid_desc.append(smallvalues)
                    elif(smallkeys == 'allowUserCA' and smallvalues == True):
                        droid_vulns.append(smallkeys)
                        droid_desc.append(smallvalues)
                    elif(smallkeys == 'pinning' and smallvalues == True):
                        droid_vulns.append(smallkeys)
                        droid_desc.append(smallvalues)
            else:
                droid_vulns.append(keys)
                droid_desc.append(values)

    APKHunt_vlun_file = os.path.join(apk_report_folder,'Droidstatx_single_vlun_file.txt')
    APKHunt_desc_file = os.path.join(apk_report_folder,'Droidstatx_single_desc_file.txt')
    with open (APKHunt_vlun_file,'w+') as f:
        f.write(str(droid_vulns))
    with open (APKHunt_desc_file,'w+') as f:
        f.write(str(droid_desc))

   