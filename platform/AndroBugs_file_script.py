# -*- coding: UTF-8 -*-
import os
import re
import logging
import subprocess
import copy
import traceback

def AndroBugs_file_change(androbugs_apks_folder,androbugs_report_folder):
    logging.info('Now begin to scan apks using [Androbugs] !')
    androbugs_cmd = 'python /home/dell/zjy/02Androbugs/AndroBugs_Framework/AndroBugs_MassiveAnalysis.py -b 20221105  -e 2 -t zjy01 -d '+ androbugs_apks_folder + ' -o '+androbugs_report_folder
    p = subprocess.Popen(androbugs_cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE,shell=True)
    (output,err) = p.communicate()
    logging.info('Androbugs scanning is finished ! ')
    
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
            logging.critical("[Androbugs]something happened __"+apkname+'_'+repr(e))
            traceback.print_exc()

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
    #result_androbugs_1 = copy.deepcopy(result)
    result_androbugs_2 = copy.deepcopy(result)
    result_2 = copy.deepcopy(result)
    #result_androbugs_final = copy.deepcopy(result)
    pattern_1 = re.compile('\[.*?\]') #[Critical]
    pattern_2 = re.compile('\(Vector ID: .*?\)') #(Vector ID:)
    
    for i in range(len(result)):
        result_androbugs_2[i] = pattern_2.findall(result_2[i])
        result_androbugs_2[i]=" ".join(result_androbugs_2[i])
        result_androbugs_2[i] = result_androbugs_2[i].replace('(','').replace(')','').replace('Vector ID:','')   
    return result_androbugs_2,androbugs_singe_desc
    





