# -*- coding: UTF-8 -*-
import os
import subprocess
import time
from util import logger
import re
import shutil

def APKHunt_run(folder_path,report_folder):
    current_path = os.path.abspath(__file__)
    report_folder_path = os.path.dirname(current_path)
    report_folder_path = os.path.dirname(report_folder_path)
    apkhunt_filer = os.path.join(report_folder_path,'APKHunt/apkhunt.go')
    apk_list = os.listdir(folder_path)
    logger.info(' [APKhunt] Now begin to scan apks using [APKhunt]')
    for i in reversed(range(len(apk_list))):
        if not ('.apk' in apk_list[i]):
            del apk_list[i]
        else:
            apk_name = os.path.splitext(apk_list[i])[0]
            apkhunt = apk_name+'_APKHunt.txt'
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
            logger.info(' [APKhunt] Scanning process: ' + str(apk_list[i])+ ' '+ str(i+1)+'/'+str(len(apk_list)))
            apkhunt_cmd = 'go run ' + apkhunt_filer +' -p '+ apk_abs_path + ' -l '
            print(apkhunt_cmd)
            start_time = time.time()
            p = subprocess.Popen(apkhunt_cmd,
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
            APKHunt_time_report = os.path.join(time_report_folder,'APKHunt_time_record.txt')
            with open(APKHunt_time_report,'a+') as file:
                file.write(apk_list[i]+': '+ str(timedifferece) + '\n')
            apk_report_folder = os.path.join(report_folder,apk_name)
            if not (os.path.exists(apk_report_folder)):
                os.mkdir(apk_report_folder)
            apkhunt_report = os.path.join(apk_report_folder,apk_name+'_APKHunt.txt')

            APKHunt_report_pro(apkhunt_report,apk_report_folder)
            apkhunt_dir = os.path.dirname(apk_abs_path)
            apkhunt_jar = os.path.join(apkhunt_dir,apk_name+'.jar')
            apkhunt_folder = os.path.join(apkhunt_dir,apk_name+'_SAST')
            if((os.path.exists(apkhunt_jar))):
                os.remove(apkhunt_jar)
            if(os.path.exists(apkhunt_folder)):
                shutil.rmtree(apkhunt_folder)
            logger.info(' [APKhunt] Delete the files')
    logger.info(' [APKhunt] APKhunt scanning is finished ! ')

def APKHunt_report_pro(report_path,apk_report_folder):
    pattern = re.compile(r'==>> .*?',re.DOTALL)
    with open(report_path,'r') as report :
        content = report.read()
    subsection = pattern.split(content)
    del subsection[0:2] 

    for i in reversed(range(len(subsection))):
        # print('======= '+ str(i+1) + ' ==========')
        subsection[i] = subsection[i].split('\n')

        for j in reversed(range(len(subsection[i]))):
            if(subsection[i][j]== '' ):
                del subsection[i][j]
            elif( '[+] Hunting begins' in subsection[i][j]):
                del subsection[i][j]
            elif( '[+] ------------------' in subsection[i][j]):
                del subsection[i][j]

        if(len(subsection[i]) == 1):
            # print(subsection[i])
            del subsection[i]
        else:
            # print(i)
            # print(subsection[i][1])
            if('The Activities...' in  subsection[i][0]):
                for j in range(len(subsection[i])):
                    if('No exported ' in subsection[i][j]):
                        del subsection[i] 
                        break
            elif('The Content Providers...' in subsection[i][0]):
                for j in range(len(subsection[i])):
                    if('No exported ' in subsection[i][j]):
                        del subsection[i] 
                        break
            elif('The Brodcast Receivers...' in subsection[i][0]):
                for j in range(len(subsection[i])):
                    if('No exported ' in subsection[i][j]):
                        del subsection[i] 
                        break
            elif('The Services...' in subsection[i][0]):
                for j in range(len(subsection[i])):
                    if('No exported ' in subsection[i][j]):
                        del subsection[i] 
                        break
            elif('APK Component Summary' in subsection[i][0]):
                del subsection[i] 
            #     break
            elif('QuickNote' in subsection[i][1]):
                del subsection[i] 
            #     break
            elif('[~] NOTE:' in subsection[i][1]):
                del subsection[i] 
            #     break

    APKHunt_single_vuln = []
    APKHunt_single_desc = []
   
    for i, section in enumerate(subsection):
        APKHunt_single_vuln.append(section[0])
        APKHunt_single_desc.append(section)

    APKHunt_vlun_file = os.path.join(apk_report_folder,'APKHunt_single_vlun_file.txt')
    APKHunt_desc_file = os.path.join(apk_report_folder,'APKHunt_single_desc_file.txt')
    with open (APKHunt_vlun_file,'w+') as f:
        f.write(str(APKHunt_single_vuln))
    with open (APKHunt_desc_file,'w+') as f:
        f.write(str(APKHunt_single_desc))



            