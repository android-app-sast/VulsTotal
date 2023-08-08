# -*- coding: UTF-8 -*-
import os 
import json
import logging
import time
import subprocess
import unicodedata
import traceback
import shutil
import operator


def MobSF_data_pro(MobSF_report_file_path):
    MobSF_report_file = open(MobSF_report_file_path,'r')
    MobSF_report = MobSF_report_file.read()
    MobSF_dict = json.loads(MobSF_report)
    MobSF_report_file.close()
    MobSF_vul = []
    MobSF_Level = []
    MobSF_desc = []
    for key in MobSF_dict:
        if (key == 'high'):
            for i in range(len(MobSF_dict[key])):
                MobSF_vul.append(MobSF_dict[key][i]['title'])
                MobSF_desc.append(MobSF_dict[key][i]['description'])
                MobSF_Level.append('high')
        if (key == 'warning'):
            for i in range(len(MobSF_dict[key])):
                MobSF_vul.append(MobSF_dict[key][i]['title'])
                MobSF_desc.append(MobSF_dict[key][i]['description'])
                MobSF_Level.append('warning')
        if (key == 'info'):
            for i in range(len(MobSF_dict[key])):
                MobSF_vul.append(MobSF_dict[key][i]['title'])
                MobSF_desc.append(MobSF_dict[key][i]['description'])
                MobSF_Level.append('info')
        if (key == 'secure'):
            for i in range(len(MobSF_dict[key])):
                MobSF_vul.append(MobSF_dict[key][i]['title'])
                MobSF_desc.append(MobSF_dict[key][i]['description'])
                MobSF_Level.append('info')
        if (key == 'hotspot'):
            for i in range(len(MobSF_dict[key])):
                # if (MobSF_dict[key][i]['section'] == 'permissions'):
                MobSF_vul.append(MobSF_dict[key][i]['title'])
                MobSF_desc.append(MobSF_dict[key][i]['description'])
    return MobSF_vul,MobSF_desc



def MobSF_scan(apks_folder,reports_folder):

    list = os.listdir(apks_folder)
    for i in reversed(range(len(list))):
        if not ('.apk' in list[i]):
            del list[i]
    for i in range(len(list)):
        list[i] = os.path.splitext(list[i])[0]
        list[i] = os.path.join(reports_folder,list[i])
    
    for i in reversed(range(len(list))):
        mobsf = list[i].split('/')[-1]+"_MobSF.txt"
        if not (os.path.exists(list[i])):
            os.mkdir(list[i])
        dir = os.listdir(list[i])
        for j in range(len(dir)):
            if (mobsf in dir[j]):
                del list[i]
                break
    
    for i in range(len(list)):
        try:
            list[i] = os.path.join(apks_folder,list[i].split('/')[-1]+'.apk') 
            startTime = time.time()
            MobSF_upload_cmd = 'curl -F \'file=@'+list[i]+'\' http://localhost:8000/api/v1/upload -H \"Authorization:88578734c16f06cd0d343fd62f994b8a84a5fcbaf59ebeca3d46b5078bd61111\"'
            p = subprocess.Popen(MobSF_upload_cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE,
                                shell=True)
            (output, err) = p.communicate()
            print(output)
            upload_resp=json.loads(output)
            hash = upload_resp['hash']
            file_name = upload_resp['file_name']
            MobSF_sacn_cmd = 'curl -X POST --url http://localhost:8000/api/v1/scan --data \"scan_type=apk&file_name='+ file_name +'&hash='+ hash +'\" -H \"Authorization:88578734c16f06cd0d343fd62f994b8a84a5fcbaf59ebeca3d46b5078bd61111\"'
            p = subprocess.Popen(MobSF_sacn_cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE,
                                shell=True)
            (output, err) = p.communicate()
            
            endTime = time.time()
            different_time = endTime-startTime

            logging.info('[MobSF] the num is '+str(i)+'/'+str(len(list))) 

            app_name = os.path.basename(list[i])
            app_name = os.path.splitext(app_name)[0]
            MobSF_report_file_path = os.path.join(reports_folder,app_name,app_name + '_MobSF.txt')
            MobSF_vul,MobSF_desc = MobSF_data_pro(MobSF_report_file_path)

            
            for i in range(len(MobSF_vul)):
                MobSF_vul[i] = MobSF_vul[i].encode('ascii')
                MobSF_desc[i] = unicodedata.normalize('NFKD', MobSF_desc[i]).encode('ascii', 'ignore')

            apk_report_folder = os.path.dirname(MobSF_report_file_path)
            if not os.path.exists(apk_report_folder):
                os.mkdir(apk_report_folder)
            ausera_vlun_file = os.path.join(apk_report_folder,'MobSF_single_vlun_file.txt')
            ausera_desc_file = os.path.join(apk_report_folder,'MobSF_single_desc_file.txt')
            with open (ausera_vlun_file,'w+') as f:
                f.write(str(MobSF_vul))
            with open (ausera_desc_file,'w+') as f:
                f.write(str(MobSF_desc))
                        
        except Exception as e:
            logging.critical('[MobSF] something wrong in _'+str(list[i])+'__'+repr(e))
            traceback.print_exc()
            
        