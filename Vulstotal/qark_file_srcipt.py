# -*- coding: UTF-8 -*-
import operator
import os
import logging
import traceback
# from common_logger import logger
from util import logger

def qark_data_pro(qark_report_path):
    f = open(qark_report_path, 'r')
    qark_report = f.readlines()
    qark_report_1 = []
    #pattern = re.compile('WARNING .*?')
    #result = pattern.findall(qark_report)
    for i in range(len(qark_report)):
        if ('WARNING' in qark_report[i]):
            qark_vlun = qark_report[i].rstrip('\n').replace('WARNING -', '')
            qark_report_1.append(qark_vlun)
        if ('POTENTIAL VULNERABILITY' in qark_report[i]):
            qark_vlun_1 = qark_report[i].rstrip('\n').replace(
                'POTENTIAL VULNERABILITY -', '')
            qark_report_1.append(qark_vlun_1)
        if ('INFO' in qark_report[i]):
            qark_vlun_1 = qark_report[i].rstrip('\n').replace(
                'INFO -', '')
            qark_report_1.append(qark_vlun_1)

    f.close()
    for i in reversed(range(len(qark_report_1))):
        if(operator.contains(qark_report_1[i] ,'Unpacking') or operator.contains(qark_report_1[i], 'Zipfile') or operator.contains(qark_report_1[i], 'Extracted APK')  or operator.contains( qark_report_1[i],'Finding AndroidManifest.xml') 
                 or operator.contains(qark_report_1[i],'<?xml version="')  or operator.contains(qark_report_1[i],'AndroidManifest.xml found') or operator.contains(qark_report_1[i],'Determined minimum SDK version to be') 
                 or operator.contains(qark_report_1[i],'Checking ')   or operator.contains(qark_report_1[i],'Please wait while QARK tries to decompile')   or operator.contains(qark_report_1[i],'Trying to improve accuracy of')  
                 or operator.contains(qark_report_1[i],'Restored')   or operator.contains(qark_report_1[i],'Decompiled code found at')   or operator.contains(qark_report_1[i],'Finding all java files')   or operator.contains(qark_report_1[i],'Running Static Code Analysis')  
                 or operator.contains(qark_report_1[i],'Looking for private key files in project') or operator.contains(qark_report_1[i],'No issues to report') or operator.contains(qark_report_1[i],'FOUND ') or operator.contains(qark_report_1[i],'Support for other component')) :
                 del qark_report_1[i]

    return qark_report_1

def qark_file_change(apk_folder, apk_report_folder):
    logger.info(' [QARK] QARK reports process. ')
    apk_name = os.listdir(apk_folder)
    for i in reversed(range(len(apk_name))):
        if not (apk_name[i].split('.')[-1] == 'apk'):
            del apk_name[i]
    apk_name.sort()
    for i in range(len(apk_name)):
        try:
            apkname = os.path.splitext(apk_name[i])[0]
            qark_report_file = os.path.join(apk_report_folder, apkname,apkname + "_qark.log")
            qark_vlun_single = qark_data_pro(qark_report_file)
            apk_single_report_folder = os.path.dirname(qark_report_file)
            qark_vlun_file = os.path.join(apk_single_report_folder,'Qark_single_vlun_file.txt')
            with open (qark_vlun_file,'w+') as f:
                f.write(str(qark_vlun_single))
        except Exception as e:
            logger.critical('\033[1;31m [QARK] something wrong happend !'+str(apk_name[i])+"\033[0m")
            # traceback.print_exc()

