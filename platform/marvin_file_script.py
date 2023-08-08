# -*- coding: UTF-8 -*-
import os
import time
import subprocess
import re
import logging
import ast
import traceback



def marvine_pro(marvine_apks_path,marvin_report_folder,i,j):
    #修改源文件，改变文件检测的顺序
    #marvine_apks_path = ../apk/apk.apk
    try:
        logging.info('Now begin to scan apks using Marvin!'+'('+str(i+1)+'/'+str(j)+')')
        os.chdir('/home/dell/zjy/07Marvinstaticanalyzer/Marvin02FINAL/Marvin-static-Analyzer-master/')
        marvine_cmd = 'python /home/dell/zjy/07Marvinstaticanalyzer/Marvin02FINAL/Marvin-static-Analyzer-master/MarvinStaticAnalyzer.py ' + marvine_apks_path
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
        f_time = open('/home/dell/zjy/tool_overlap_0311/Time_Record_0721/Marvin_time_record.txt', 'a+')
        print(timedifferece)
        f_time.write(marvine_apks_path+' : ')
        f_time.write(str(timedifferece))
        f_time.write('\n')
        f_time.close()

        marvin_report_file = os.path.join(marvin_report_folder,app_name, app_name + '_marvin.txt')
        f = open(marvin_report_file, 'w+')
        f.write(output)
        f.write('----------------------')
        # f.write(err)
        f.close()

        # logging.info('Marvin scanning is finished ! '+str(marvine_apks_path))
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
        logging.critical('something wrong happened!____' + str(marvine_apks_path)+'____'+repr(e))
        traceback.print_exc()
    

def marvine_file_gener(marvine_apks_path, marvin_total_vuln,marvin_vuln_desc,
                       marvin_report_folder):
    apk_name = os.listdir(marvine_apks_path)
    for i in reversed(range(len(apk_name))):
        if ('.apk' not in str(apk_name[i])):
            del apk_name[i]
    # print(apk_name)
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
    '''
    marvine_apks_name = os.listdir(marvine_apks_path)
    marvine_apks_abso_path = []
    for i in range(len(marvine_apks_name)):
        marvine_apks_abso_path.append(os.path.join(marvine_apks_path,marvine_apks_name[i]))
    print(marvine_apks_abso_path)
    for i in range(len(marvine_apks_abso_path)):
        marvine_cmd = 'python MarvinStaticAnalyzer.py ' + marvine_apks_abso_path[i]
        p = subprocess.Popen(marvine_cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        output_lines = output.decode().splitlines()
        flag = 0
        print('************')
        print(output_lines)
        for i in range(len(output_lines)):
            if '{' in output_lines[i]:
                flag = i
        marvin_result = output_lines[i:]
        print(marvin_result)
    '''


# reports_folder = '/home/dell/zjy/tool_overlap_0311/froid_report'
# marvine_apks_path = '/media/dell/WD_BLACK/fdroid/apks_3/internet/com.thirtydegreesray.openhub_34.apk'
# # marvin_report_folder = '/home/dell/zjy/APK_total_Report/'
# marvine_pro(marvine_apks_path,reports_folder,1,1)
# marvine_file_gener(marvine_apks_path,marvin_total_vuln, marvin_vuln_desc, marvin_report_folder)
