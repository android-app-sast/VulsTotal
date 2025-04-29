# -*- coding: UTF-8 -*-
import os
import re
import subprocess
import logging
import shutil
import traceback
from util import logger

def AUSERA_file_del(ausera_main_apks):
    logger.info( ' [AUSERA] Del the apks in [AUSERA] folder.')
    apks = os.listdir(ausera_main_apks)
    for i in reversed(range(len(apks))):
        if ('.apk' in apks[i]):
            the_apk_path = os.path.join(ausera_main_apks,apks[i])
            os.remove(the_apk_path)

def AUSERA_file_change(ausera_engine_report, apks_file, ausera_main_apks):
    apks = os.listdir(ausera_main_apks)
    for i in reversed(range(len(apks))):
        if not ('.apk' in apks[i]):
            del apks[i]
    apks.sort()

    target_apk_report_file = []
    orginal_apk_report_file = []

    for apk in apks:
        try:
            logger.info(' [AUSERA] Now state a new target path for apk: ' + apk)
            apk_path = os.path.join(ausera_main_apks, apk)
            apk_name = os.path.splitext(apk)[0]
            target_folder = os.path.join(apks_file, apk_name)
            if not (os.path.exists(target_folder)):
                os.mkdir(target_folder)
            target_report_url = os.path.join(target_folder,apk_name + '_AUSERA.txt')

            sha256sum_cmd = 'sha256sum ' + apk_path
            p1 = subprocess.Popen(sha256sum_cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE,
                                shell=True)
            (output, err) = p1.communicate()
            apk_sha256 = output.split(' ')[0]
            if (apk_sha256[0] == '0'):
                apk_sha256 = apk_sha256.lstrip('0')
            apk_sha256_txt = apk_sha256 + '.txt'
            orginal_report_url = os.path.join(ausera_engine_report, apk_sha256_txt)

            target_apk_report_file.append(target_report_url)
            orginal_apk_report_file.append(orginal_report_url)
        except Exception as e:
            logger.critical(' \033[1;31m [AUSERA] [AUSERA_file_change] wrong in '+str(apk)+'\033[0m')
    
    current_folder = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ausera_apk_engine = os.path.join(current_folder,'ausera-main/apk-engine.py') 
    ausera_main = os.path.join(current_folder,'ausera-main/')
    ausera_android_platforms = os.path.join(current_folder,'ausera-main/engine-configuration/libs/android-platforms/') 

    logger.info(' [AUSERA] Now begin to scan apks using [AUSERA] ')
    AUSERA_cmd = 'python2.7 '+ ausera_apk_engine +' ' + ausera_main + ' /usr/local/java/jdk1.8.0_333/ ' + ausera_android_platforms 
    logger.debug(' [AUSERA] AUSERA_cmd ==> '+ AUSERA_cmd)
    
    p = subprocess.Popen(AUSERA_cmd,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         stdin=subprocess.PIPE,
                         shell=True)
    p.communicate()
    logger.info(' [AUSERA] AUSERA scanning is finished ! ')
    
    for i in range(len(target_apk_report_file)):
        try:
            shutil.copyfile(orginal_apk_report_file[i], target_apk_report_file[i])
        except Exception as e:
            logger.critical(' \033[1;31m [AUSERA] file process wrong in '+str(target_apk_report_file[i]) + '\033[0m')

    # Del the remaining apks in ausera folder
    AUSERA_file_del(ausera_main_apks)
    return target_apk_report_file
    
def AUSERA_file(apk_report_file):
    AUERA_total_vuln = []
    AUERA_total_desc = []
    for i in range(len(apk_report_file)):
        try:
            f = open(apk_report_file[i], 'r')
            context_result = f.read()
            pattern = re.compile('\[.*?\]\:\[.*?\]')
            result_re = pattern.findall(context_result)
            f.close()
            AUERA_vul = []
            AUSERA_Level = []
            AUSERA_desc_fin = []
            for j in range(len(result_re)):
                AUERA_vul.append(result_re[j].split("]:[")[0].split("[")[1])
                AUSERA_Level.append(result_re[j].split("]:[")[1].split("]")[0])
            AUERA_total_vuln.append(AUERA_vul) 

            ausera_desc = context_result.splitlines()
            index = []
            for a in range(len(ausera_desc)):
                if ('===================' in ausera_desc[a]):
                    index.append(a)
            for a in range(len(index)-1):
                AUSERA_desc_fin.append(ausera_desc[index[a]:index[a+1]])
            AUSERA_desc_fin.append(ausera_desc[index[-1]:])
            AUERA_total_desc.append(AUSERA_desc_fin)
            apk_report_folder = os.path.dirname(apk_report_file[i])
            ausera_vlun_file = os.path.join(apk_report_folder,'Ausera_single_vlun_file.txt')
            ausera_desc_file = os.path.join(apk_report_folder,'Ausera_single_desc_file.txt')
            with open (ausera_vlun_file,'w+') as f:
                f.write(str(AUERA_vul))
            with open (ausera_desc_file,'w+') as f:
                f.write(str(AUSERA_desc_fin))
        except Exception as e:
            logger.critical(" \033[1;31m [AUSERA] something happened in scanning AUSERA in "+str(apk_report_file[i])+"\033[0m]")


