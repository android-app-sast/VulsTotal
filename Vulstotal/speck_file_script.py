# -*- coding: UTF-8 -*-
from imp import reload
import os
import re
import time
import sys
import subprocess
import logging
import traceback
from util import logger

reload(sys)
sys.setdefaultencoding('utf-8')

def speck_scan(speck_apk_path, speck_final_path):
    try:
        current_folder = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        speck_file = os.path.join(current_folder,'SPECK/server/Scan.py')
        speck_cmd = 'python3 '+ speck_file + ' -s ' + speck_apk_path
        print(speck_cmd)
        apk_name  = os.path.basename(speck_apk_path)
        speck_apk_name = os.path.splitext(apk_name)[0]
        speck_report_path = os.path.join(speck_final_path, speck_apk_name)
        if not (os.path.exists(speck_report_path)):
            os.mkdir(speck_report_path)
        strat_time = time.time()
        p = subprocess.Popen(speck_cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE,
                            shell=True)
        (output, err) = p.communicate()
        end_time = time.time()
        timedifferece = end_time - strat_time
        current_path = os.path.abspath(__file__)
        report_folder_path = os.path.dirname(current_path)
        report_folder_path = os.path.dirname(report_folder_path)
        time_report_folder = os.path.join(report_folder_path,'TimeReport')
        SPECK_time_report = os.path.join(time_report_folder,'SPECK_time_record.txt')
        with open(SPECK_time_report,'a+') as file:
            file.write(speck_apk_name+': '+ str(timedifferece) + '\n')

        linenew = []
        matchPattern = re.compile(r'analysed')
        matchPattern_1 = re.compile(r'RULE')
        speck_report_txt_file = os.path.join(speck_report_path,
                                            speck_apk_name + "_speak.txt")
        speck_file = open(speck_report_txt_file, 'w+')
        if('INFO  - loading ...' in output):
            for line in output.splitlines():
                line2 = line.replace('[0m', '').replace('[37m', '').replace(
                    '[01m', '').replace('[44m', '').replace('[32m', '').replace(
                        '[96m', '').replace('[=>]', '').replace('[1m', '').replace(
                            '[91m', '').replace('[92m',
                                                '').replace('[33m', '').replace(
                                                    '[35m', '').replace('[93m', '')
                if matchPattern.search(line2):
                    pass
                else:
                    linenew.append(line2)
            for i in range(len(linenew)):
                speck_file.write(linenew[i])
                speck_file.write('\n')
            speck_file.close()
        else:
            speck_file.write(output)
            speck_file.close()
    except :
        print(speck_apk_path)
    return speck_report_txt_file




def speck_file_pro(speck_report_txt_file):
    file = open(speck_report_txt_file, 'r')
    context = file.read()
    file.close()
    rule_index = []
    speck_context = context.splitlines()
    speck_rule_context = []
    speck_rule_context_fin = []
    speck_rule29_desc = []
    flag = 0
    if ('INFO  - loading' in context):
        for i in range(len(speck_context)):
            if ("RULE: " in speck_context[i]):
                rule_index.append(i)


        for i in range(len(rule_index) - 1):
            speck_rule_context.append(speck_context[rule_index[i]:rule_index[i +
                                                                            1]])

        speck_rule_context.append(speck_context[rule_index[-1]:])
        for i in reversed(range(len(speck_rule_context))):
            for j in range(len(speck_rule_context[i])):
                if ('Choose a recommended algorithm' in speck_rule_context[i][j] ):
                    speck_rule29_desc.append(speck_rule_context[i])
                elif('Use HTML message channels' in speck_rule_context[i][j]):
                    speck_rule29_desc.append(speck_rule_context[i])

            if ('[+] No violation has been found.' in (speck_rule_context[i])):
                #print('true')
                del speck_rule_context[i]


        for i in range(len(speck_rule_context)):
            for j in range(len(speck_rule_context[i])):
                if ('have CRITICAL ' in speck_rule_context[i][j]):
                    speck_rule_context_fin.append(speck_rule_context[i][1])
                elif ('have WARNING(S)' in speck_rule_context[i][j]):
                    speck_rule_context_fin.append(speck_rule_context[i][1])
                elif ('DO NOT RESPECT THE RULE' in speck_rule_context[i][j]):
                    speck_rule_context_fin.append(speck_rule_context[i][1])
                # elif ('Choose a recommended algorithm' in speck_rule_context[i][j] ):
                #     speck_rule29_desc.append(speck_rule_context[i])
                # elif('Use HTML message channels' in speck_rule_context[i][j]):
                #     speck_rule29_desc.append(speck_rule_context[i])
                #speck_rule_context_fin.append(speck_rule_context[i])
                #del speck_rule_context[i]
        #print(speck_rule_context_fin)
    else:
        logger.critical('\033[1;31m [SPECK] SPECK scans fiaure: '+speck_report_txt_file+'\033[0m')
    return speck_rule_context_fin,speck_rule29_desc



def speck_batch(speck_apks_path, speck_final_path):
    logger.info(' [SPECK] Now begin to scan apks using [SPECK] !')
    
    speck_apks_list = os.listdir(speck_apks_path)
    report_path = []
    for i in reversed(range(len(speck_apks_list))):
        if not ('.apk' in speck_apks_list[i]):
            del speck_apks_list[i]
    spepck_scan =[]
    for i in reversed(range(len(speck_apks_list))):
        apk_name = os.path.splitext(speck_apks_list[i])[0]
        speck = apk_name+'_speak.txt'
        report_file = os.path.join(speck_final_path,apk_name)
        if not (os.path.exists(report_file)):
            os.mkdir(report_file)
        tree = os.listdir(report_file)
        if speck in tree:
            del speck_apks_list[i]

    for i in range(len(speck_apks_list)):
        try:
            speck_apks_list[i] = os.path.join(speck_apks_path, speck_apks_list[i])
            logger.info(' [SPECK] Scanning process: '+str(i+1)+'/'+str(len(speck_apks_list))+' : ' + os.path.basename(speck_apks_list[i]))
            speck_report_txt_file = speck_scan(speck_apks_list[i],speck_final_path)

            speck_rule_context_fin,speck_rule29_desc = speck_file_pro(speck_report_txt_file)
            for j in range(len(speck_rule_context_fin)):
                speck_rule_context_fin[j] = speck_rule_context_fin[j].encode('ascii')

            apk_report_folder = os.path.dirname(speck_report_txt_file)
            ausera_vlun_file = os.path.join(apk_report_folder,'Speck_single_vlun_file.txt')
            ausera_desc_file = os.path.join(apk_report_folder,'Speck_single_desc_file_1.txt')
            with open (ausera_vlun_file,'w+') as f:
                f.write(str(speck_rule_context_fin))
            with open (ausera_desc_file,'w+') as f:
                f.write(str(speck_rule29_desc))
        except Exception as e:
            logger.critical("\033[1;31m [Speck] Something happened in Speck!___"+speck_apks_list[i]+'\033[0m')
            # traceback.print_exc()
    logger.info(' [SPECK] SPECK scanning is finished ! ')

    
    
