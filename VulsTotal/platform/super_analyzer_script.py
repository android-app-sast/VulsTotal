# -*- coding: utf-8 -*-
from imp import reload
import operator
import re
import subprocess
import os
import json
import logging
import sys
import traceback
import unicodedata
import shutil
import time

reload(sys)
sys.setdefaultencoding('utf8')

class ApkInfo:
    # This class is not used
    def __init__(self, apk_path):
        self.apkPath = apk_path

    def get_apk_base_info(self):
        p = subprocess.Popen('aapt' + " dump badging %s" % self.apkPath,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             stdin=subprocess.PIPE,
                             shell=True)
        (output, err) = p.communicate()
        match = re.compile("package: name='(\S+)'").match(output.decode())
        if not match:
            raise Exception("can't get packageinfo")
        package_name = match.group(1)
        return package_name

def apk_file_change(apk_scan_file, super_report_folder, apk_target_folder):
    
    apk_name_list = os.listdir(apk_scan_file)
    for i in reversed(range(len(apk_name_list))):
        if not (apk_name_list[i].split('.')[-1] == 'apk'):
            del apk_name_list[i]
    apk_name_list.sort()
    
    apk_abs_path = []
    report_path = []
    for i in range(len(apk_name_list)):
        apk_abs_path.append(os.path.join(apk_scan_file, apk_name_list[i]))
        apk_name = os.path.splitext(apk_name_list[i])[0]
        report_super = os.path.join(apk_target_folder,apk_name)
        if not (os.path.exists(report_super)):
            os.mkdir(report_super)
        report_path.append(report_super)
    
    for i in reversed(range(len(report_path))):
        tree = os.listdir(report_path[i])
        apk_name = os.path.splitext(apk_name_list[i])[0]
        super = apk_name+'_super.json'
        if (super in tree):
            del apk_abs_path[i]
            del apk_name_list[i]
    
    pattern1 = re.compile('manifest package: (\S+)*')
    pattern = re.compile('manifest package: \S')
    super_report_path_total = []
    
    for i in range(len(apk_abs_path)):
        try:
            logging.info('SUPER scanning :' + str(i + 1) +'/'+ str(len(apk_abs_path)))
            super_cmd = 'super-analyzer   --json ' + apk_abs_path[i]
            startTime = time.time()
            p = subprocess.Popen(super_cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE,
                                shell=True)
            (output, err) = p.communicate()
            endTime = time.time()
            different_time = endTime-startTime

            time.sleep(2)
            if (operator.contains(err,'application analysis failed')):
                logging.warning('application analysis failed')
                continue
            if ('there was an error in the configuration' in err):
                logging.warning('application analysis failed')
                continue
            if not (pattern.findall(err)):
                time.sleep(2)
                logging.warning('[super]dont have package name,need to find results.json directly.')
                apk_name = os.path.splitext(apk_name_list[i])[0]
                report_json_path_old = os.path.join(super_report_folder,'results.json')
                report_json_folder = os.path.join(apk_target_folder,apk_name)
                if not (os.path.exists(report_json_folder)):
                    os.mkdir(report_json_folder)
                report_json_path_new = os.path.join(
                    report_json_folder,
                    apk_name + '_super.json')
                # print(report_json_path_old)
                # print(report_json_path_new)
                # shutil.copyfile(report_json_path_old,report_json_path_new)
                os.rename(report_json_path_old, report_json_path_new)
                super_report_path_total.append(report_json_path_new)
                time.sleep(1)
            else:
                time.sleep(2)
                packagename = pattern1.findall(err)[0]
                apk_name = os.path.splitext(apk_name_list[i])[0]    
                # print(apk_name_list[i])
                report_json_path_old = os.path.join(super_report_folder,packagename, 'results.json')
                report_json_folder = os.path.join(apk_target_folder,apk_name)
                if not (os.path.exists(report_json_folder)):
                    os.mkdir(report_json_folder)
                report_json_path_new = os.path.join(report_json_folder,apk_name+ '_super.json')
                print(report_json_path_old)
                print(report_json_path_new)

                os.rename(report_json_path_old, report_json_path_new)
                super_report_path_total.append(report_json_path_new)
                #it is not sure that all apks dont have warn tips
            super_data_pro(report_json_path_new)
    
        except Exception as e:
            logging.critical('[super]the app has something wrong---'+str(apk_abs_path[i]) +'_' +str(e))
            traceback.print_exc()
    
    return super_report_path_total


def super_data_pro(super_jsonreport_path):
    #对文件格式进行调整
    # for i in range(len(super_jsonreport_path)):
    try:
        logging.info('Process file format for apk: ' +str(super_jsonreport_path.split('/')[-1]))
        super_report_file = open(super_jsonreport_path, 'r')
        super_json_context = super_report_file.read()
        super_json_dict = json.loads(super_json_context)
        super_report_file.close()

        super_vuln_criticals = super_json_dict['criticals']
        super_vuln_highs = super_json_dict['highs']
        super_vuln_mediums = super_json_dict['mediums']
        super_vuln_lows = super_json_dict['lows']
        super_vuln_warnings = super_json_dict['warnings']

        super_single_vuln = []
        super_single_desc = []

        for j in range(len(super_vuln_criticals)):
            super_single_vuln.append(super_vuln_criticals[j]['name'])
            super_single_desc.append(super_vuln_criticals[j]['code'])            
        for j in range(len(super_vuln_highs)):
            super_single_vuln.append(super_vuln_highs[j]['name'])
            super_single_desc.append(super_vuln_highs[j]['code'])  
        for j in range(len(super_vuln_mediums)):
            super_single_vuln.append(super_vuln_mediums[j]['name'])
            super_single_desc.append(super_vuln_mediums[j]['code'])  
        for j in range(len(super_vuln_lows)):
            super_single_vuln.append(super_vuln_lows[j]['name'])
            super_single_desc.append(super_vuln_lows[j]['code'])  
        for j in range(len(super_vuln_warnings)):
            super_single_vuln.append(super_vuln_warnings[j]['name'])
            super_single_desc.append(super_vuln_warnings[j]['code'])  
        
        
        #super_single_vuln is the super's result
        super_spec_code = []   
        super_spec_code_1 = []
        super_spec_code_2 = []
        super_spec_code_3 = []
        
        for j in range(len(super_single_vuln)):
            super_single_desc[j] = unicodedata.normalize('NFKD',super_single_desc[j]).encode('ascii','ignore')
            if(super_single_vuln[j] == "Weak Algorithms"):
                super_spec_code_1.append(super_single_desc[j])
            if(super_single_vuln[j] == "Accepting all SSL certificates"):
                super_spec_code_2.append(super_single_desc[j])
            if(super_single_vuln[j] == "WebView XSS"):
                super_spec_code_3.append(super_single_desc[j])
                
        super_spec_code.append(super_spec_code_1)
        super_spec_code.append(super_spec_code_2)
        super_spec_code.append(super_spec_code_3)
        
        super_single_vuln = list(set(super_single_vuln))
        
        for j in range(len(super_single_vuln)):
            super_single_vuln[j] = super_single_vuln[j].encode('ascii')
        apk_report_folder = os.path.dirname(super_jsonreport_path)
        ausera_vlun_file = os.path.join(apk_report_folder,'Super_single_vlun_file.txt')
        ausera_desc_file = os.path.join(apk_report_folder,'Super_single_desc_file.txt')
        with open (ausera_vlun_file,'w+') as f:
            f.write(str(super_single_vuln))
        with open (ausera_desc_file,'w+') as f:
            f.write(str(super_spec_code))
    except Exception as e:
        logging.critical("[Super]something happened!!"+str(super_jsonreport_path)+'___' + repr(e))



