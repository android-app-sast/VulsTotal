# -*- coding: UTF-8 -*-
import os
import re
import logging
import subprocess
import copy
import traceback
from util import logger

def AndroBugs_file_change(androbugs_apks_folder,androbugs_report_folder):
    logger.info(' [AndroBugs] Now begin to scan apks using [AndroBugs] !')
    current_folder = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    androbugs_massive = os.path.join(current_folder,'AndroBugs_Framework/AndroBugs_MassiveAnalysis.py')
    androbugs_cmd = 'python ' + androbugs_massive + ' -b 20221105  -e 2 -t 01 -d '+ androbugs_apks_folder + ' -o '+androbugs_report_folder
    logger.debug(' [AndroBugs] AndroBugs_cmd ==> ' + androbugs_cmd)
    p = subprocess.Popen(androbugs_cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE,shell=True)
    (output,err) = p.communicate()
    
    logger.info(' [AndroBugs] AndroBugs scanning is finished ! ')
    
    androbugs_apks = os.listdir(androbugs_apks_folder)
    androbugs_apks.sort()
    for apkname in androbugs_apks:
        try:
            if apkname.endswith('.apk'):
                apk_name = os.path.splitext(apkname)[0]
                androbugs_report_file = os.path.join(androbugs_report_folder,apk_name,apk_name+'_androbugs.txt')
                androbugs_vuln ,androbugs_singe_desc_= AndroBugs_data_Pro(androbugs_report_file)
                apk_report_folder = os.path.dirname(androbugs_report_file)
                ausera_vlun_file = os.path.join(apk_report_folder,'Androbugs_single_vlun_file.txt')
                ausera_desc_file = os.path.join(apk_report_folder,'Androbugs_single_desc_file.txt')
                with open (ausera_vlun_file,'w+') as f:
                    f.write(str(androbugs_vuln))
                with open (ausera_desc_file,'w+') as f:
                    f.write(str(androbugs_singe_desc_))
        except Exception as e:
            logger.critical("\033[1;31m [AndroBugs] something happened in "+apkname+'\033[0m')
            # traceback.print_exc()

def AndroBugs_data_Pro(androbugs_file_path):
    pattern = re.compile('\[.*?\].*?\(Vector ID:.*?\)')
    f = open(androbugs_file_path,'r')
    t = f.read()
    result = pattern.findall(t)
    f.close() 
    line = t.splitlines()
    index = []
    androbugs_singe_desc = []
    for i in range(len(line)):
        if('Vector ID' in line[i]):
            index.append(i)
    for i in range(len(index)-1):
        androbugs_singe_desc.append(line[index[i]:index[i+1]])
    androbugs_singe_desc.append(line[index[-1]:])
    for i in reversed(range(len(androbugs_singe_desc))):
        for j in reversed(range(len(androbugs_singe_desc[i]))):
            if('[Info]' in androbugs_singe_desc[i][j]):
                del(androbugs_singe_desc[i])
    for i in range(len(result))[::-1]:
        if "[Info]" in result[i]:
            del result[i]
    result_androbugs_2 = copy.deepcopy(result)
    result_2 = copy.deepcopy(result)
    pattern_1 = re.compile('\[.*?\]') #[Critical]
    pattern_2 = re.compile('\(Vector ID: .*?\)') #(Vector ID:)
    
    for i in range(len(result)):
        result_androbugs_2[i] = pattern_2.findall(result_2[i])
        result_androbugs_2[i]=" ".join(result_androbugs_2[i])
        result_androbugs_2[i] = result_androbugs_2[i].replace('(','').replace(')','').replace('Vector ID:','')   
    return result_androbugs_2,androbugs_singe_desc
    





