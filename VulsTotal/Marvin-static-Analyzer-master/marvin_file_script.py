import os 
import sys
import subprocess
import re
import json 
import ast

def marvine_pro(marvine_apks_path):
    #marvine_apks_path = ../apk/
    marvine_cmd = 'python MarvinStaticAnalyzer.py ' + marvine_apks_path
    p = subprocess.Popen(marvine_cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE,shell=True)
    (output, err) = p.communicate()
    output_apk_scan = output.split('cd')
    
    pattern = re.compile('\{.*\}')
    print(type(output_apk_scan))
    del output_apk_scan[0]
    marvin_results_list = []
    marvin_vuln_list = []
    for i in range(len(output_apk_scan)):
        marvin_results_list.append(pattern.findall(output_apk_scan[i]))
        print("*******apk scan results ********")
        marvn_results_dict = ast.literal_eval(marvin_results_list[i][0])
  	marvin_key_name = []
        print(type(marvn_results_dict))
        for keys in marvn_results_dict.keys():
            marvin_key_name.append(keys)
    marvin_vuln_list.append(marvin_key_name)
    print(marvin_vuln_list)
    
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
marvine_apks_path = '/home/dell/zjy/07Marvinstaticanalyzer/Marvin02FINAL/Marvin-static-Analyzer-master/APK/'
marvine_pro(marvine_apks_path)
