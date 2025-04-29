
from imp import reload
import os
import sys
import csv
import subprocess
import unicodedata
import time
import numpy as np
import pandas as pd
import shutil
import traceback
import pexpect
import logging
import ast
import copy
import argparse
import json
from util import logger
from threading import Thread, Lock 
from AUSERA_file_script import (AUSERA_file_change, AUSERA_file, AUSERA_file_del)
from AndroBugs_file_script import (AndroBugs_file_change, AndroBugs_data_Pro)
from MobSF_file_script import (MobSF_scan)
from qark_file_srcipt import (qark_data_pro, qark_file_change)
from super_analyzer_script import (apk_file_change, super_data_pro)
from jaadas_file_script import (jaadas_scan, jaadas_pro,
                                jaadas_file_scan_batch)
from marvin_file_script import (marvine_pro, marvine_file_gener)
from speck_file_script import (speck_scan, speck_file_pro, speck_batch)
from APkHunt_file_script import APKHunt_run
from trueseeing_file_script import trueseeing_run
from Droidstatx_file_script import droidstatx_run
from corresponding_overlap import vlun_valid,corresponding

reload(sys)
sys.setdefaultencoding('utf8')

def apk_name_handle(apks_folder):
    apk_name = os.listdir(apks_folder)
    for i in reversed(range(len(apk_name))):
        if not ('.apk' in apk_name[i]):
            del apk_name[i]
    apk_name.sort()
    return apk_name

def copy_to_AUSERA(ausera_main_apks,apks_folder):
    apk_list = apk_name_handle(apks_folder)
    logger.info(' [AUSERA] Copy the apks to the AUSERA file')
    for i in range(len(apk_list)):
        apk_abs_path = os.path.join(apks_folder,apk_list[i])
        des_apk_path = os.path.join(ausera_main_apks,apk_list[i])
        shutil.copyfile(apk_abs_path,des_apk_path)
        logger.info(' [AUSERA] Copy ('+str(i+1)+'/'+str(len(apk_list))+') '+ apk_list[i])

def AUSERA_show(apks_folder,reports_folder):
    current_folder = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ausera_engine_report = os.path.join(current_folder,'ausera-main/engine-result/engine-report') 
    ausera_main_apks = os.path.join(current_folder,'ausera-main/apks/')  
    AUSERA_file_del(ausera_main_apks)
    copy_to_AUSERA(ausera_main_apks,apks_folder)
    ausera_target_report_url = AUSERA_file_change(ausera_engine_report,reports_folder,ausera_main_apks)
    AUSERA_file(ausera_target_report_url)

def get_ausera(single_apk_folder):
    ausera_vulns_store = os.path.join(single_apk_folder, 'Ausera_single_vlun_file.txt')
    ausera_desc_store = os.path.join(single_apk_folder, 'Ausera_single_desc_file.txt')
    f_vlun = open(ausera_vulns_store, 'r')
    f_desc = open(ausera_desc_store, 'r')
    AUSERA_single_vlun = f_vlun.read()
    AUSERA_single_vlun = ast.literal_eval(AUSERA_single_vlun)
    AUERA_single_desc = f_desc.read()
    AUERA_single_desc = ast.literal_eval(AUERA_single_desc)
    f_vlun.close()
    f_desc.close()
    return AUSERA_single_vlun, AUERA_single_desc

def Androbugs_show(apks_folder, reports_folder):
    AndroBugs_file_change(apks_folder, reports_folder)

def get_Androbugs(single_apk_folder):
    Androbugs_vulns_store = os.path.join(single_apk_folder, 'Androbugs_single_vlun_file.txt')
    Androbugs_desc_store = os.path.join(single_apk_folder, 'Androbugs_single_desc_file.txt')
    f_vlun = open(Androbugs_vulns_store, 'r')
    f_desc = open(Androbugs_desc_store, 'r')
    Androbugs_single_vlun = f_vlun.read()
    Androbugs_single_vlun = ast.literal_eval(Androbugs_single_vlun)
    androbugs_single_desc = f_desc.read()
    androbugs_single_desc = ast.literal_eval(androbugs_single_desc)
    f_vlun.close()
    f_desc.close()
    return Androbugs_single_vlun, androbugs_single_desc

def MobSF_show(apks_folder, reports_folder):
    MobSF_scan(apks_folder,reports_folder)

def get_MobSF(single_apk_folder):
    MobSF_vulns_store = os.path.join(single_apk_folder, 'MobSF_single_vlun_file.txt')
    MobSF_desc_store = os.path.join(single_apk_folder, 'MobSF_single_desc_file.txt')
    f_vlun = open(MobSF_vulns_store, 'r')
    f_desc = open(MobSF_desc_store, 'r')
    MobSF_single_vuln = f_vlun.read()
    MobSF_single_vuln = ast.literal_eval(MobSF_single_vuln)
    MobSF_single_desc = f_desc.read()
    MobSF_single_desc = ast.literal_eval(MobSF_single_desc)
    f_vlun.close()
    f_desc.close()
    return MobSF_single_vuln, MobSF_single_desc

def QARK_show(apks_folder, reports_folder):
    logger.info(' [QARK] Now begin to scan apks using [QARK] !')

    list = apk_name_handle(apks_folder)
    apk_name = []
    for i in range(len(list)):
        list[i] = os.path.splitext(list[i])[0]
        apk_name.append(list[i])
        list[i] = os.path.join(reports_folder,list[i])
        
    for i in reversed(range(len(list))):
        qark = list[i].split('/')[-1]+"_qark.log"
        if not (os.path.exists(list[i])):
            os.mkdir(list[i])
        dir = os.listdir(list[i])
        for j in range(len(dir)):
            if (qark in dir[j]):
                del list[i]
                del apk_name[i]

    for i in range(len(apk_name)):
        apk_name[i] = apk_name[i]+'.apk'

    for i in range(len(apk_name)):
        try:
            apk_path = os.path.join(apks_folder, apk_name[i])
            logger.info(' [QARK] Now scan the app named: ' + str(apk_name[i]) + '('+str(i+1)+'/'+str(len(apk_name))+')' + '')
            current_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            qark_path = os.path.join(current_path,'QARK','qark.py')
            qark_cmd = 'python ' + qark_path
            startTime = time.time()
            print(apk_path)
            qark_exec = pexpect.spawn(qark_cmd)
            qark_exec.expect('Path:', timeout=10)
            qark_exec.sendline(apk_path)
            qark_exec.buffer = ""
            index_1 = qark_exec.expect(['At any time',pexpect.TIMEOUT,pexpect.EOF],timeout=360)
            if index_1 == 2 or index_1 ==0:
                index_2 = qark_exec.expect(['Finding all java file',pexpect.TIMEOUT,pexpect.EOF],timeout=600)
                if index_2 == 1 :
                    qark_exec.send('c')
                    qark_exec.interact()
                elif index_2 == 0  :
                    qark_exec.interact()
                elif index_2 == 2:
                    logger.critical('\033[1;31m [QARK] '+apk_path+' have classes.jar wrong! \033[0m')
                    qark_exec.interact()
            elif index_1 == 1:
                qark_exec.sendeof()
                logger.critical('\033[31m [QARK] Timeout for decomplie. \033[0m')

            endTime = time.time()
            different_time = endTime-startTime
            current_path = os.path.abspath(__file__)
            report_folder_path = os.path.dirname(current_path)
            report_folder_path = os.path.dirname(report_folder_path)
            time_report_folder = os.path.join(report_folder_path,'TimeReport')
            QARK_time_report = os.path.join(time_report_folder,'QARK_time_record.txt')
            with open(QARK_time_report,'a+') as file:
                file.write(apk_name[i]+': '+ str(different_time) + '\n')

        except Exception as e: 
            logger.critical('\033[1;31m [QARK] Exists the error for apk:' + str(apk_name[i]) +'\033[0m')

    qark_file_change(apks_folder, reports_folder)
    logger.info(' [QARK] QARK scanning is finished ! ')

def get_qark(single_apk_folder):
    Qark_vulns_store = os.path.join(single_apk_folder, 'Qark_single_vlun_file.txt')
    f_vlun = open(Qark_vulns_store, 'r')
    qark_single_vuln = f_vlun.read()
    qark_single_vuln = ast.literal_eval(qark_single_vuln)
    f_vlun.close()
    return qark_single_vuln

def super_show(apks_folder, reports_folder):
    try:
        self_path = os.path.dirname(os.path.abspath(__file__))
        super_report_folder = os.path.join(self_path, 'results')
        apk_file_change(apks_folder, super_report_folder,reports_folder)
    except:
        logger.critical('\033[1;31m [SUPER] Exists the error in SUPER. \033[0m')
        # traceback.print_exc()
    
def get_super(single_apk_folder):
    Super_vulns_store = os.path.join(single_apk_folder, 'Super_single_vlun_file.txt')
    Super_desc_store = os.path.join(single_apk_folder, 'Super_single_desc_file.txt')
    f_vlun = open(Super_vulns_store, 'r')
    f_desc = open(Super_desc_store, 'r')
    super_single_vuln = f_vlun.read()
    super_single_vuln = ast.literal_eval(super_single_vuln)
    super_single_desc = f_desc.read()
    super_single_desc = ast.literal_eval(super_single_desc)
    f_vlun.close()
    f_desc.close()
    return super_single_vuln, super_single_desc

def jaadas_show(apks_folder, reports_folder):
    jaadas_file_scan_batch(apks_folder, reports_folder)

def get_jaadas(single_apk_folder):
    jaadas_vulns_store = os.path.join(single_apk_folder, 'Jaadas_single_vlun_file.txt')
    f_vlun = open(jaadas_vulns_store, 'r')
    jaadas_single_vuln = f_vlun.read()
    jaadas_single_vuln = ast.literal_eval(jaadas_single_vuln)
    f_vlun.close()
    return jaadas_single_vuln

def Marvin_show(apks_folder, reports_folder):
    logger.info(' [Marvin] Now begin to scan apks using [Marvin] !')
    apk_name = apk_name_handle(apks_folder)
    for i in reversed(range(len(apk_name))):
        app_name = os.path.splitext(apk_name[i])[0]
        report_path = os.path.join(reports_folder,app_name)
        if not (os.path.exists(report_path)):
            os.mkdir(report_path)
        tree = os.listdir(report_path)
        marvin = 'Marvin_single_vlun_file.txt'
        # marvin = '_marvin.txt'
        if (marvin in tree):
            del apk_name[i]
    for i in range(len(apk_name)):
        apks_file = os.path.join(apks_folder,apk_name[i])
        j = len(apk_name)
        marvine_pro(apks_file,reports_folder,i,j)
    logger.info(' [Marvin] Marvin scanning is finished ! ')
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

def get_marvin(single_apk_folder):
    Marvin_vulns_store = os.path.join(single_apk_folder, 'Marvin_single_vlun_file.txt')
    Marvin_desc_store = os.path.join(single_apk_folder, 'Marvin_single_desc_file.txt')
    f_vlun = open(Marvin_vulns_store, 'r')
    f_desc = open(Marvin_desc_store, 'r')
    marvin_single_vuln = f_vlun.read()
    marvin_single_vuln = ast.literal_eval(marvin_single_vuln)
    marvin_vuln_single_desc = f_desc.read()
    marvin_vuln_single_desc = ast.literal_eval(marvin_vuln_single_desc)
    f_vlun.close()
    f_desc.close()
    return marvin_single_vuln, marvin_vuln_single_desc

def Speck_show(apks_folder, reports_folder):
    speck_batch(apks_folder,reports_folder)

def get_speck(single_apk_folder):
    Spexk_vulns_store = os.path.join(single_apk_folder, 'Speck_single_vlun_file.txt')
    Spexk_desc_store = os.path.join(single_apk_folder, 'Speck_single_desc_file_1.txt')
    f_vlun = open(Spexk_vulns_store, 'r')
    f_desc = open(Spexk_desc_store, 'r')
    speck_single_vuln = f_vlun.read()
    speck_single_vuln = ast.literal_eval(speck_single_vuln)
    speck_rule29_single_descs = f_desc.read()
    speck_rule29_single_descs = ast.literal_eval(speck_rule29_single_descs)
    f_vlun.close()
    f_desc.close()
    return speck_single_vuln, speck_rule29_single_descs

def APKHunt_show(apks_folder, reports_folder):
    APKHunt_run(apks_folder, reports_folder)

def get_APKHunt(single_apk_folder):
    APKHunt_vulns_store = os.path.join(single_apk_folder, 'APKHunt_single_vlun_file.txt')
    APKHunt_desc_store = os.path.join(single_apk_folder, 'APKHunt_single_desc_file.txt')
    f_vlun = open(APKHunt_vulns_store, 'r')
    f_desc = open(APKHunt_desc_store, 'r')
    APKHunt_single_vuln = f_vlun.read()
    APKHunt_single_vuln = ast.literal_eval(APKHunt_single_vuln)
    APKHunt_single_descs = f_desc.read()
    APKHunt_single_descs = ast.literal_eval(APKHunt_single_descs)
    f_vlun.close()
    f_desc.close()
    return APKHunt_single_vuln,APKHunt_single_descs

def Trueseeing_show(apks_folder, reports_folder):
    trueseeing_run(apks_folder,reports_folder)

def get_trueseeing(single_apk_folder):
    Truseeing_vulns_store = os.path.join(single_apk_folder, 'Trueseeing_single_vlun_file.txt')
    Truseeing_desc_store = os.path.join(single_apk_folder, 'Trueseeing_single_desc_file.txt')
    f_vlun = open(Truseeing_vulns_store, 'r')
    f_desc = open(Truseeing_desc_store, 'r')
    trueseeing_single_vuln = f_vlun.read()
    trueseeing_single_vuln = ast.literal_eval(trueseeing_single_vuln)
    trueseeing_single_descs = f_desc.read()
    trueseeing_single_descs = ast.literal_eval(trueseeing_single_descs)
    f_vlun.close()
    f_desc.close()
    return trueseeing_single_vuln, trueseeing_single_descs

def DroidStatx_show(apks_folder, reports_folder):
    droidstatx_run(apks_folder,reports_folder)

def get_droidstatx(single_apk_folder):
    DroidStatx_vulns_store = os.path.join(single_apk_folder, 'Droidstatx_single_vlun_file.txt')
    f_vlun = open(DroidStatx_vulns_store, 'r')
    DroidStatx_single_vuln = f_vlun.read()
    DroidStatx_single_vuln = ast.literal_eval(DroidStatx_single_vuln)
    f_vlun.close()
    return DroidStatx_single_vuln,

def scan(reports_folder, apks_folder):
    logger.info(' [VulsTotal] Now scan apps! ')
    # AUSERA_show(apks_folder,reports_folder)
    # Androbugs_show(apks_folder, reports_folder)
    # MobSF_show(apks_folder, reports_folder)
    # QARK_show(apks_folder, reports_folder)
    # super_show(apks_folder, reports_folder)
    jaadas_show(apks_folder, reports_folder)
    # Marvin_show(apks_folder,reports_folder)
    # Speck_show(apks_folder,reports_folder)
    # APKHunt_show(apks_folder,reports_folder)
    # Trueseeing_show(apks_folder,reports_folder)
    # DroidStatx_show(apks_folder,reports_folder)
    logger.info(' [VulsTotal] All apps are scanned finally! ')
    current_path = os.path.dirname(os.path.abspath(__file__))
    sootOutput = os.path.join(current_path,'sootOutput')
    if (os.path.exists(sootOutput)):
        shutil.rmtree(sootOutput)
    logger.debug(' [VulsTotal] Del the sootOutput folder.')

def report_name(value):
    switcher = {
        0:"Ausera_single_vlun_file.txt",
        1:"Ausera_single_desc_file.txt",
        2:"Androbugs_single_vlun_file.txt",
        3:"Androbugs_single_desc_file.txt",
        4:"MobSF_single_vlun_file.txt",
        5:"MobSF_single_desc_file.txt",
        6:"Qark_single_vlun_file.txt",
        7:"Super_single_vlun_file.txt",
        8:"Super_single_desc_file.txt",
        9:"Jaadas_single_vlun_file.txt",
        10:"Marvin_single_vlun_file.txt",
        11:"Marvin_single_desc_file.txt",
        12:"Speck_single_desc_file_1.txt",
        13:"Speck_single_vlun_file.txt",
        14:"APKHunt_single_vlun_file.txt",
        15:"Trueseeing_single_vlun_file.txt",
        16:"Trueseeing_single_desc_file.txt",
        17:"Droidstatx_single_vlun_file.txt"
    }
    return switcher.get(value,'wrong value')

def screen_demo_Androbugs(Androbugs_single_vlun,androbugs_single_desc):
    if("HACKER_PREVENT_SCREENSHOT_CHECK" not in Androbugs_single_vlun):
        Androbugs_single_vlun.append("HACKER_PREVENT_SCREENSHOT_CHECK")
        androbugs_single_desc.append('screenshot issue')
    return Androbugs_single_vlun,androbugs_single_desc

def screen_demo_MobSF(MobSF_single_vuln,MobSF_single_desc):
    if("This App has capabilities to prevent against Screenshots from Recent Task History/ Now On Tap etc." not in MobSF_single_vuln):
        MobSF_single_vuln.append("This App has capabilities to prevent against Screenshots from Recent Task History/ Now On Tap etc.")
        MobSF_single_desc.append('screenshot issue')
    return MobSF_single_vuln,MobSF_single_desc

def deltetNull(vuln_list):
    for i in reversed(range(len(vuln_list))):
        if("NULL" == vuln_list[i]):
            del vuln_list[i]
    return vuln_list

def corresponding_overlap(apk_name, AUSERA_single_vlun, Androbugs_single_vlun,
                  MobSF_single_vuln, qark_single_vuln, super_single_vuln,
                  jaadas_single_vuln, marvin_single_vuln, speck_single_vuln, AUERA_single_desc, androbugs_single_desc,
                  MobSF_single_desc, super_single_desc, marvin_vuln_single_desc,
                  speck_rule29_single_descs,
                  APKHunt_single_vuln, APKHunt_single_descs,
                  Trueseeing_single_vuln, Trueseeing_single_descs,
                  DroidStatx_single_vuln,rules):
    AUSERA_unique_item = []
    Androbugs_unique_item = []
    MobSF_unique_item = []
    qark_unique_item = []
    super_unique_item = []
    jaadas_unique_item = []
    marvin_unique_item = []
    speck_unique_item = []
    APKHunt_unique_item = []
    Trueseeing_unique_item = []
    DroidStatx_unique_item = []
    
    AUSERA_vlun = []
    Androbugs_vlun = []
    MobSF_vlun = []
    QARK_vlun = []
    Super_vlun = []
    Jaadas_vlun = []
    Marvin_vlun = []
    Speck_vlun = []
    APKHunt_vuln = []
    Trueseeing_vuln = []
    DroidStatx_vuln = []

    # print("-----------------apkname: "+ apk_name+"------------------------------")
    if not (AUSERA_single_vlun==[0]):
        # print("----------------------------tool name---------AUSERA---------------------------------------------------")
        for j in reversed(range(len(AUSERA_single_vlun))):
            AUSERA_single_vlun[j] = AUSERA_single_vlun[j].strip(' ') 

            vuln_list,tool_uniqe = corresponding(tool_name="AUSERA",tool_vuln=AUSERA_single_vlun[j],tool_uniqe=AUSERA_unique_item, rules=rules, tool_desc=AUERA_single_desc[j])
            for a in range(len(vuln_list)):
                if not (vuln_list == 'NULL'):
                    AUSERA_vlun.append(vuln_list[a])
            AUSERA_unique_item.append(tool_uniqe)
    if not (Androbugs_single_vlun==[0]):
        # print("----------------------------tool name---------Androbug--------------------------------------------------")
        for j in reversed(range(len(Androbugs_single_vlun))):
            Androbugs_single_vlun[j] = Androbugs_single_vlun[j].strip(' ') 
            vuln_list,tool_uniqe = corresponding("Androbugs",Androbugs_single_vlun[j],Androbugs_unique_item, rules, androbugs_single_desc[j])
            for a in range(len(vuln_list)):
                if not (vuln_list == 'NULL'):
                    Androbugs_vlun.append(vuln_list[a])
            Androbugs_unique_item.append(tool_uniqe)
    if not (MobSF_single_vuln==[0]):
        # print("----------------------------tool name---------MobSF---------------------------------------------------")            
        for j in reversed(range(len(MobSF_single_vuln))):
            MobSF_single_vuln[j] = MobSF_single_vuln[j].strip(' ') 
            vuln_list,tool_uniqe = corresponding("MobSF",MobSF_single_vuln[j],MobSF_unique_item, rules, MobSF_single_desc[j])
            for a in range(len(vuln_list)):
                if not (vuln_list == 'NULL'):
                    MobSF_vlun.append(vuln_list[a])
            MobSF_unique_item.append(tool_uniqe)
    if not (qark_single_vuln==[0]):
        # print("----------------------------tool name---------QARK---------------------------------------------------")
        for j in reversed(range(len(qark_single_vuln))):
            qark_single_vuln[j] = qark_single_vuln[j].strip(' ') 
            vuln_list,tool_uniqe = corresponding("QARK",qark_single_vuln[j],qark_unique_item,rules)
            for a in range(len(vuln_list)):
                if not (vuln_list == 'NULL'):
                    QARK_vlun.append(vuln_list[a])
            qark_unique_item.append(tool_uniqe)
    if not (super_single_vuln==[0]):
        # print("----------------------------tool name---------Super---------------------------------------------------")
        for j in reversed(range(len(super_single_vuln))):
            super_single_vuln[j] = super_single_vuln[j].strip(' ') 
            # after corresponding get the new name list or unique
            vuln_list,tool_uniqe = corresponding("Super",super_single_vuln[j],super_unique_item,rules,super_single_desc)
            for a in range(len(vuln_list)):
                if not (vuln_list == ''):
                    Super_vlun.append(vuln_list[a])
            super_unique_item.append(tool_uniqe)
    if not (jaadas_single_vuln==[0]):
        # print("----------------------------tool name---------Jaadas---------------------------------------------------")
        for j in reversed(range(len(jaadas_single_vuln))):
            jaadas_single_vuln[j] = jaadas_single_vuln[j].strip(' ') 
            vuln_list,tool_uniqe = corresponding("Jaadas",jaadas_single_vuln[j],jaadas_unique_item,rules)
            for a in range(len(vuln_list)):
                if not (vuln_list == 'NULL'):
                    Jaadas_vlun.append(vuln_list[a])
            jaadas_unique_item.append(tool_uniqe)
    if not (marvin_single_vuln==[0]):
        # print("----------------------------tool name---------Marvin---------------------------------------------------")
        for j in reversed(range(len(marvin_single_vuln))):
            marvin_single_vuln[j] = marvin_single_vuln[j].strip(' ') 
            vuln_list,tool_uniqe = corresponding("Marvin",marvin_single_vuln[j],marvin_unique_item, rules ,marvin_vuln_single_desc[j])
            for a in range(len(vuln_list)):
                if not (vuln_list == 'NULL'):
                    Marvin_vlun.append(vuln_list[a])
            marvin_unique_item.append(tool_uniqe)
    if not (speck_single_vuln==[0]):
        # print("----------------------------tool name---------Speck---------------------------------------------------")
        for j in reversed(range(len(speck_single_vuln))):
            speck_single_vuln[j] = speck_single_vuln[j].strip(' ') 
            vuln_list,tool_uniqe = corresponding("Speck",speck_single_vuln[j],speck_unique_item, rules ,speck_rule29_single_descs)

            for a in range(len(vuln_list)):
                if not (vuln_list == "NULL"):
                    Speck_vlun.append(vuln_list[a])
            speck_unique_item.append(tool_uniqe)
    if not (APKHunt_single_vuln==[0]):
        # print("----------------------------tool name---------APKHunt---------------------------------------------------")
        for j in reversed(range(len(APKHunt_single_vuln))):
            APKHunt_single_vuln[j] = APKHunt_single_vuln[j].strip(' ').replace('...','')
            if(APKHunt_single_vuln[j] == '' or APKHunt_single_vuln[j] == 'T'):
                del APKHunt_single_vuln[j]
            # print('\033[1;31m Old name : \033[0m'+APKHunt_single_vuln[j])

            vuln_list,tool_uniqe = corresponding("APKHunt",APKHunt_single_vuln[j],APKHunt_unique_item, rules, APKHunt_single_descs[j])

            for a in range(len(vuln_list)):
                if not (vuln_list == "NULL"):
                    APKHunt_vuln.append(vuln_list[a])
            APKHunt_unique_item.append(tool_uniqe)
    if not (Trueseeing_single_vuln==[0]):
        # print("----------------------------tool name---------Trueseeing---------------------------------------------------")
        for j in reversed(range(len(Trueseeing_single_vuln))):
            Trueseeing_single_vuln[j] = Trueseeing_single_vuln[j].strip(' ') 
            vuln_list,tool_uniqe = corresponding("Trueseeing",Trueseeing_single_vuln[j],Trueseeing_unique_item, rules ,Trueseeing_single_descs[j])

            for a in range(len(vuln_list)):
                if not (vuln_list == "NULL"):
                    Trueseeing_vuln.append(vuln_list[a])
            Trueseeing_unique_item.append(tool_uniqe)
    if not (DroidStatx_single_vuln==[0]):
        # print("----------------------------tool name---------DroidStatx---------------------------------------------------")
        for j in reversed(range(len(DroidStatx_single_vuln))):
            DroidStatx_single_vuln[j] = DroidStatx_single_vuln[j].strip(' ') 
            vuln_list,tool_uniqe = corresponding("Droidstatx",DroidStatx_single_vuln[j],DroidStatx_unique_item, rules)

            for a in range(len(vuln_list)):
                if not (vuln_list == "NULL"):
                    DroidStatx_vuln.append(vuln_list[a])
            DroidStatx_unique_item.append(tool_uniqe)
    
    
    if(len(speck_unique_item)>0):
        for i in reversed(range(len(speck_unique_item))):
            if("Choose a recommended algorithm" == speck_unique_item[i]):
                del speck_unique_item[i]
            elif("Use HTML message channels" == speck_unique_item[i]):
                del speck_unique_item[i]
            elif("NULL" == speck_unique_item[i]):
                del speck_unique_item[i]
    if(len(super_unique_item)>0):
        for i in reversed(range(len(super_unique_item))):
            if("WebView XSS" == super_unique_item[i]):
                del super_unique_item[i]
            elif("Weak Algorithms" == super_unique_item[i]):
                del super_unique_item[i]
            elif("NULL" == super_unique_item[i]):
                del super_unique_item[i]
    if(len(marvin_unique_item)>0):
        for i in reversed(range(len(marvin_unique_item))):
            if("CRYPTOGRAPHY" == marvin_unique_item[i]):
                del marvin_unique_item[i]
            elif("NULL" == marvin_unique_item[i]):
                del marvin_unique_item[i]
    if(len(AUSERA_unique_item)>0):
        for i in reversed(range(len(AUSERA_unique_item))):
            if("Invalid certificates" == AUSERA_unique_item[i]):
                del AUSERA_unique_item[i]
            elif("ICC data leakage" == AUSERA_unique_item[i]):
                del AUSERA_unique_item[i]
            elif("MITM attacks" == AUSERA_unique_item[i]):
                del AUSERA_unique_item[i]
            elif("NULL" == AUSERA_unique_item[i]):
                del AUSERA_unique_item[i]
       
    AUSERA_vlun = deltetNull(AUSERA_vlun)
    Androbugs_vlun = deltetNull(Androbugs_vlun)
    MobSF_vlun = deltetNull(MobSF_vlun)
    QARK_vlun = deltetNull(QARK_vlun)
    Super_vlun = deltetNull(Super_vlun)
    Jaadas_vlun = deltetNull(Jaadas_vlun)
    Marvin_vlun = deltetNull(Marvin_vlun)
    Speck_vlun = deltetNull(Speck_vlun)
    APKHunt_vuln = deltetNull(APKHunt_vuln)
    Trueseeing_vuln = deltetNull(Trueseeing_vuln)
    DroidStatx_vuln = deltetNull(DroidStatx_vuln)

    AUSERA_vlun = list(set(AUSERA_vlun))
    Androbugs_vlun = list(set(Androbugs_vlun))
    QARK_vlun = list(set(QARK_vlun))
    MobSF_vlun = list(set(MobSF_vlun))
    Super_vlun = list(set(Super_vlun))
    Jaadas_vlun = list(set(Jaadas_vlun))
    Marvin_vlun = list(set(Marvin_vlun))
    Speck_vlun = list(set(Speck_vlun))
    APKHunt_vuln = list(set(APKHunt_vuln))
    Trueseeing_vuln = list(set(Trueseeing_vuln))
    DroidStatx_vuln = list(set(DroidStatx_vuln))

    AUSERA_unique_item = deltetNull(AUSERA_unique_item)
    Androbugs_unique_item = deltetNull(Androbugs_unique_item)
    MobSF_unique_item = deltetNull(MobSF_unique_item)
    qark_unique_item = deltetNull(qark_unique_item)
    super_unique_item = deltetNull(super_unique_item)
    jaadas_unique_item = deltetNull(jaadas_unique_item)
    marvin_unique_item = deltetNull(marvin_unique_item)
    speck_unique_item = deltetNull(speck_unique_item)
    APKHunt_unique_item = deltetNull(APKHunt_unique_item)
    Trueseeing_unique_item = deltetNull(Trueseeing_unique_item)
    DroidStatx_unique_item = deltetNull(DroidStatx_unique_item)

    AUSERA_unique_item = list(set(AUSERA_unique_item))
    Androbugs_unique_item = list(set(Androbugs_unique_item))
    MobSF_unique_item = list(set(MobSF_unique_item))
    qark_unique_item = list(set(qark_unique_item))
    super_unique_item = list(set(super_unique_item))
    jaadas_unique_item = list(set(jaadas_unique_item))
    marvin_unique_item = list(set(marvin_unique_item))
    speck_unique_item = list(set(speck_unique_item))
    APKHunt_unique_item = list(set(APKHunt_unique_item))
    Trueseeing_unique_item = list(set(Trueseeing_unique_item))
    DroidStatx_unique_item = list(set(DroidStatx_unique_item))

    return AUSERA_vlun, Androbugs_vlun, MobSF_vlun, QARK_vlun, Super_vlun, Jaadas_vlun, Marvin_vlun, Speck_vlun, APKHunt_vuln, Trueseeing_vuln, DroidStatx_vuln,AUSERA_unique_item,Androbugs_unique_item,MobSF_unique_item,qark_unique_item,super_unique_item,jaadas_unique_item,marvin_unique_item,speck_unique_item,APKHunt_unique_item, Trueseeing_unique_item, DroidStatx_unique_item
    
def judge_max(list_num,fact_list):
    truth = 0
    max_list = []
    max_value = max(list_num)
    truth_8_list = ['-','-','-','-','-','-','-','-']
    for i in range(len(list_num)):
        if(list_num[i] == max_value):
            max_list.append(i)
        if(list_num != 0):
            truth_8_list[i] = 0
        if(fact_list[i] ==1 and list_num[i]>0):
            truth_8_list[i] = 1
    for i in range(len(max_list)):
        if fact_list[max_list[i]] == 1:
            truth = 1
            break
    return truth

def overlap(apk_name, AUSERA_single_vlun, Androbugs_single_vlun,
            MobSF_single_vuln, qark_single_vuln, super_single_vuln,jaadas_single_vuln, 
            marvin_single_vuln, speck_single_vuln, 
            APKHunt_single_vuln,
            Trueseeing_single_vuln, DroidStatx_single_vuln,
            scan_failure_list,rules_list,stra_option,confiden_option,CSV_folder):  
    
    overlap_num_1,overlap_num_2,overlap_num_3,overlap_num_4,overlap_num_5,overlap_num_6,overlap_num_7,overlap_num_8,overlap_num_9,overlap_num_10,overlap_num_11 = [],[],[],[],[],[],[],[],[],[],[]
    for i in range(len(rules_list)):
        overlap_num_1.append(rules_list[i]['Gra'][0])
        overlap_num_2.append(rules_list[i]['Gra'][1])
        overlap_num_3.append(rules_list[i]['Gra'][2])
        overlap_num_4.append(rules_list[i]['Gra'][3])
        overlap_num_5.append(rules_list[i]['Gra'][4])
        overlap_num_6.append(rules_list[i]['Gra'][5])
        overlap_num_7.append(rules_list[i]['Gra'][6])
        overlap_num_8.append(rules_list[i]['Gra'][7])
        overlap_num_9.append(rules_list[i]['Gra'][8])
        overlap_num_10.append(rules_list[i]['Gra'][9])
        overlap_num_11.append(rules_list[i]['Gra'][10])

    AUSERA_row,Androbugs_row,MobSF_row,QARK_row,SUPER_row,JAADAS_row,Marvin_row,SPECK_row,APKHunt_row,Truseeing_row,DroidStatx_row,true_flag,theo_overlap,sum_truth_overlap = [0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0]
    vuln_number = len(rules_list)

    for j in range(vuln_number-1):
        AUSERA_row.append(0)
        Androbugs_row.append(0)
        MobSF_row.append(0)
        QARK_row.append(0)
        SUPER_row.append(0)
        JAADAS_row.append(0)
        Marvin_row.append(0)
        SPECK_row.append(0)
        APKHunt_row.append(0)
        Truseeing_row.append(0)
        DroidStatx_row.append(0)
        true_flag.append(0)
        theo_overlap.append(0)
        sum_truth_overlap.append(0)

    overlap_throy = {
        0:overlap_num_1,
        1:overlap_num_2,
        2:overlap_num_3,
        3:overlap_num_4,
        4:overlap_num_5,
        5:overlap_num_6,
        6:overlap_num_7,
        7:overlap_num_8,
        8:overlap_num_9,
        9:overlap_num_10,
        10:overlap_num_11
    }
    tool_select = {
        0:AUSERA_row,
        1:Androbugs_row,
        2:MobSF_row,
        3:QARK_row,
        4:SUPER_row,
        5:JAADAS_row,
        6:Marvin_row,
        7:SPECK_row,
        8:APKHunt_row,
        9:Truseeing_row,
        10:DroidStatx_row
    }

    for i in range(len(theo_overlap)):
        for j in range(len(overlap_throy)):
            if(overlap_throy.get(j,'wrongvalue')[i]>0): # type: ignore
                theo_overlap[i] = theo_overlap[i] + 1

    if(scan_failure_list[0]==1):
        for j in range(len(AUSERA_single_vlun)):
            for a in range(len(rules_list)):
                if AUSERA_single_vlun[j] == rules_list[a]["title"]:
                    AUSERA_row[a] = 1
    else:
        for a in range(len(rules_list)):
            AUSERA_row[a] = '-' # type: ignore

    if(scan_failure_list[1]==1):     
        for j in range(len(Androbugs_single_vlun)):
            for a in range(len(rules_list)):
                if Androbugs_single_vlun[j] == rules_list[a]["title"]:
                    Androbugs_row[a] = 1
    else:
        for a in range(len(rules_list)):
            Androbugs_row[a] = '-' # type: ignore

    if(scan_failure_list[2]==1):
        for j in range(len(MobSF_single_vuln)):
            for a in range(len(rules_list)):
                if MobSF_single_vuln[j] == rules_list[a]["title"]:
                    MobSF_row[a] = 1
    else:
        for a in range(len(rules_list)):
            MobSF_row[a] = '-' # type: ignore

    if(scan_failure_list[3]==1):
        for j in range(len(qark_single_vuln)):
            for a in range(len(rules_list)):
                if qark_single_vuln[j] == rules_list[a]["title"]:
                    QARK_row[a] = 1
    else:
        for a in range(len(rules_list)):
            QARK_row[a] = '-' # type: ignore

    if(scan_failure_list[4]==1):
        for j in range(len(super_single_vuln)):
            for a in range(len(rules_list)):
                if super_single_vuln[j] == rules_list[a]["title"]:
                    SUPER_row[a] = 1
    else:
        for a in range(len(rules_list)):
            SUPER_row[a] = '-' # type: ignore

    if(scan_failure_list[5]==1):
        for j in range(len(jaadas_single_vuln)):
            for a in range(len(rules_list)):
                if jaadas_single_vuln[j] == rules_list[a]["title"]:
                    JAADAS_row[a] = 1
    else:
        for a in range(len(rules_list)):
            JAADAS_row[a] = '-' # type: ignore

    if(scan_failure_list[6]==1):
        for j in range(len(marvin_single_vuln)):
            for a in range(len(rules_list)):
                if marvin_single_vuln[j] == rules_list[a]["title"]:
                    Marvin_row[a] = 1
    else:
        for a in range(len(rules_list)):
            Marvin_row[a] = '-' # type: ignore

    if(scan_failure_list[7]==1):
        for j in range(len(speck_single_vuln)):
            for a in range(len(rules_list)):
                if speck_single_vuln[j] == rules_list[a]["title"]:
                    SPECK_row[a] = 1
    else:
        for a in range(len(rules_list)):
            SPECK_row[a] = '-' # type: ignore

    if(scan_failure_list[8]==1):
        for j in range(len(APKHunt_single_vuln)):
            for a in range(len(rules_list)):
                if APKHunt_single_vuln[j] == rules_list[a]["title"]:
                    APKHunt_row[a] = 1
    else:
        for a in range(len(rules_list)):
            APKHunt_row[a] = '-' # type: ignore

    if(scan_failure_list[9]==1):
        for j in range(len(Trueseeing_single_vuln)):
            for a in range(len(rules_list)):
                if Trueseeing_single_vuln[j] == rules_list[a]["title"]:
                    Truseeing_row[a] = 1
    else:
        for a in range(len(rules_list)):
            Truseeing_row[a] = '-' # type: ignore

    if(scan_failure_list[10]==1):
        for j in range(len(DroidStatx_single_vuln)):
            for a in range(len(rules_list)):
                if DroidStatx_single_vuln[j] == rules_list[a]["title"]:
                    DroidStatx_row[a] = 1
    else:
        for a in range(len(rules_list)):
            DroidStatx_row[a] = '-' # type: ignore


    if (scan_failure_list == [1,1,1,1,1,1,1,1,1,1,1]):
    # normal apk
        for b in range(len(rules_list)):
            sum_truth_overlap[b] = AUSERA_row[b] + Androbugs_row[b] + MobSF_row[b] + QARK_row[b] + SUPER_row[b] + JAADAS_row[b] + Marvin_row[b] + SPECK_row[b] + APKHunt_row[b] + Truseeing_row[b] + DroidStatx_row[b]
    else:
    # the apk lack all the reports,need to confirm the nessary report for each vul
        for a in range(len(scan_failure_list)):
            if(scan_failure_list[a] == 0):
                overlap_throy_num = overlap_throy.get(a,'wrong value')
                for b in range(len(rules_list)):
                    if(overlap_throy_num[b] > 0): # type: ignore
                        sum_truth_overlap[b] ='-' # type: ignore
        for b in range(len(rules_list)):
            if not (sum_truth_overlap[b] == '-'):
                for a in range(len(scan_failure_list)):
                    if(scan_failure_list[a] == 1):
                        tool_row = tool_select.get(a,'wrong value')
                        if(tool_row[b] != 0):
                            sum_truth_overlap[b] = sum_truth_overlap[b]+ tool_row[b] # type: ignore
    
    
    if stra_option == 0:
        # customize_stra
        if confiden_option == 100:
            true_vuln_list = []
            for j in range(len(sum_truth_overlap)):
                if(type(sum_truth_overlap[j]) == int):
                    if (theo_overlap[j] == sum_truth_overlap[j]):
                        true_flag[j] = 1
                        true_vuln_list.append(j)
                else:
                    true_flag[j] =  '-' # type: ignore
        elif 50 <= confiden_option < 100:
            true_vuln_list = []
            for j in range(len(sum_truth_overlap)):
                if(type(sum_truth_overlap[j]) == int):
                    if(theo_overlap[j] == 2 and sum_truth_overlap[j]>=2):
                        true_flag[j] = 1
                        true_vuln_list.append(j)
                    elif(theo_overlap[j] != 2 and sum_truth_overlap[j] >= theo_overlap[j]*0.01*int(confiden_option)):
                        true_flag[j] = 1
                        true_vuln_list.append(j)
                else:
                    true_flag[j] =  '-' # type: ignore
        else:
            logger.critical('\033[1;31m [VulsTotal] Please input the confidence >= 50 \033[0m')
    elif stra_option == 1:
        # gran_stra
        if confiden_option == 100:
            true_vuln_list = []
            for j in range(len(sum_truth_overlap)):
                if(type(sum_truth_overlap[j]) == int):
                    if (theo_overlap[j] == sum_truth_overlap[j]):
                        true_flag[j] = 1
                        true_vuln_list.append(j)
                else:
                    true_flag[j] =  '-' # type: ignore
        elif 50 <= confiden_option < 100:
            true_vuln_list = []
            for j in range(len(rules_list)):
                if(type(sum_truth_overlap[j]) == int):
                    if (7 in rules_list[j]['Gra']):
                        list_num = [] # theory list
                        fact_list = [] 
                        theo_num = 0
                        for a in range(len(scan_failure_list)):
                            num = overlap_throy.get(a,'wrong value')[j]
                            list_num.append(num)
                            num_1 = tool_select.get(a,'wrong value')[j]
                            fact_list.append(num_1)
                        for a in range(len(list_num)):
                            if(list_num[a]>0):
                                theo_num = theo_num +1
                        truth = judge_max(list_num,fact_list)
                        if(truth == 1):
                            if(theo_overlap[j] == 2 and sum_truth_overlap[j]>=2):
                                true_flag[j] = 1
                                true_vuln_list.append(j)
                            elif(theo_overlap[j] != 2 and sum_truth_overlap[j] >= theo_overlap[j]*0.01*int(confiden_option)):
                                true_flag[j] = 1
                                true_vuln_list.append(j)
                        elif(truth == 0):
                            true_flag[j] = 0
                    else:
                        if(theo_overlap[j] == 2 and sum_truth_overlap[j]>=2):
                            true_flag[j] = 1
                            true_vuln_list.append(j)
                        elif(theo_overlap[j] != 2 and sum_truth_overlap[j] >= theo_overlap[j]*0.01*int(confiden_option)):
                            true_flag[j] = 1
                            true_vuln_list.append(j)
                else:
                    true_flag[j] =  '-'   # type: ignore
        else:
            logger.critical('\033[1;31m [VulsTotal] Please input the confidence >= 50 \033[0m')      
        
    else:
        logger.critical('\033[1;31m [VulsTotal] Please input 0(which means customized majority voting) or 1(which means granularity-aware majority voting) \033[0m')
    
    for s in range(len(rules_list)):
        AUSERA_row[s] = str(AUSERA_row[s])+'/'+str(1 if(overlap_num_1[s]>0) else 0) # type: ignore
        Androbugs_row[s] = str(Androbugs_row[s])+'/'+str(1 if(overlap_num_2[s]>0) else 0) # type: ignore
        MobSF_row[s] = str(MobSF_row[s])+'/'+str(1 if(overlap_num_3[s]>0) else 0) # type: ignore
        QARK_row[s] = str(QARK_row[s])+'/'+str(1 if(overlap_num_4[s]>0) else 0) # type: ignore
        SUPER_row[s] = str(SUPER_row[s])+'/'+str(1 if(overlap_num_5[s]>0) else 0) # type: ignore
        JAADAS_row[s] = str(JAADAS_row[s])+'/'+str(1 if(overlap_num_6[s]>0) else 0) # type: ignore
        Marvin_row[s] = str(Marvin_row[s])+'/'+str(1 if(overlap_num_7[s]>0) else 0) # type: ignore
        SPECK_row[s] = str(SPECK_row[s])+'/'+str(1 if(overlap_num_8[s]>0) else 0) # type: ignore
        APKHunt_row[s] = str(APKHunt_row[s])+'/'+str(1 if(overlap_num_9[s]>0) else 0) # type: ignore
        Truseeing_row[s] = str(Truseeing_row[s])+'/'+str(1 if(overlap_num_10[s]>0) else 0) # type: ignore
        DroidStatx_row[s] = str(DroidStatx_row[s])+'/'+str(1 if(overlap_num_11[s]>0) else 0) # type: ignore

    AUSERA_single_vlun_array = np.array(AUSERA_row).reshape(-1, 1)
    Androbugs_single_vlun_array = np.array(Androbugs_row).reshape(-1, 1)
    MobSF_single_vuln_array = np.array(MobSF_row).reshape(-1, 1)
    qark_single_vuln_array = np.array(QARK_row).reshape(-1, 1)
    super_single_vuln_array = np.array(SUPER_row).reshape(-1, 1)
    jaadas_single_vuln_array = np.array(JAADAS_row).reshape(-1, 1)
    marvin_single_vuln_array = np.array(Marvin_row).reshape(-1, 1)
    speck_single_vuln_array = np.array(SPECK_row).reshape(-1, 1)
    APKHuntsingle_vuln_array = np.array(APKHunt_row).reshape(-1, 1)
    Trueseeing_single_vuln_array = np.array(Truseeing_row).reshape(-1, 1)
    DroidStatx_single_vuln_array = np.array(DroidStatx_row).reshape(-1, 1)
    theo_overlap_array = np.array(theo_overlap).reshape(-1, 1)
    sum_truth_overlap_array = np.array(sum_truth_overlap).reshape(-1, 1)
    true_flag_array = np.array(true_flag).reshape(-1,1)

    all_tools_single = np.concatenate((qark_single_vuln_array,Androbugs_single_vlun_array,
                                       jaadas_single_vuln_array,marvin_single_vuln_array,
                                       super_single_vuln_array,MobSF_single_vuln_array,
                                       speck_single_vuln_array,AUSERA_single_vlun_array,
                                       APKHuntsingle_vuln_array,Trueseeing_single_vuln_array,DroidStatx_single_vuln_array,
                                       sum_truth_overlap_array, theo_overlap_array,true_flag_array),axis=1)
    
    csv_columns = ['QARK','AndroBugs', 'JAADAS','Marvin','SUPER','MobSF','SPECK', 'AUSERA','APKHunt','Trueseeing','DroidStatx','Sum_truth_overlap', 'theory_overlap','true_flag']

    csv_index = []
    for j in range(len(rules_list)):
        csv_index.append(rules_list[j]["title"])
    single_apk_vlun = pd.DataFrame(all_tools_single,columns=csv_columns,index=csv_index)
    outputpath = os.path.join(CSV_folder,apk_name + '.csv')
    header_list  = ['Overlap for all tools !']
    with open(outputpath, mode="w") as f:
        writer = csv.writer(f)
        writer.writerow(header_list)
    single_apk_vlun.to_csv(outputpath, sep=',', index=True, header=True,mode='a')
    
    singe_name_vul = {'apk_name':apk_name,'true_vuln_list':true_vuln_list}

    # general only the final result(CSV)
    # final_csv = np.concatenate((true_flag_array))
    # final_columns = ['true_flag']
    # final_apk_vlun = pd.DataFrame(final_csv,columns=final_columns,index=csv_index)
    # outputpath = os.path.join(CSV_folder,apk_name + '_final.csv')
    # with open(outputpath, mode="w") as f:
    #     writer = csv.writer(f)
    # final_apk_vlun.to_csv(outputpath, sep=',', index=True, header=True,mode='a')

    return singe_name_vul

def uniqe_item(apk_name,AUSERA_unique_item ,Androbugs_unique_item ,MobSF_unique_item ,qark_unique_item ,super_unique_item ,
               jaadas_unique_item ,marvin_unique_item ,speck_unique_item,
               APKHunt_unique_item, Trueseeing_unique_item, DroidStatx_unique_item,CSV_folder):
    max_n = max(len(AUSERA_unique_item),len(Androbugs_unique_item),len(MobSF_unique_item),len(qark_unique_item),len(super_unique_item),len(jaadas_unique_item),len(marvin_unique_item),len(speck_unique_item),len(APKHunt_unique_item),len(Trueseeing_unique_item),len(DroidStatx_unique_item))
    for i in range(max_n-len(AUSERA_unique_item)):
        AUSERA_unique_item.append(None)
    for i in range(max_n-len(Androbugs_unique_item)):
        Androbugs_unique_item.append(None)
    for i in range(max_n-len(MobSF_unique_item)):
        MobSF_unique_item.append(None)
    for i in range(max_n-len(qark_unique_item)):
        qark_unique_item.append(None)
    for i in range(max_n-len(super_unique_item)):
        super_unique_item.append(None)
    for i in range(max_n-len(jaadas_unique_item)):
        jaadas_unique_item.append(None)
    for i in range(max_n-len(marvin_unique_item)):
        marvin_unique_item.append(None)
    for i in range(max_n-len(speck_unique_item)):
        speck_unique_item.append(None)
    for i in range(max_n-len(APKHunt_unique_item)):
        APKHunt_unique_item.append(None)
    for i in range(max_n-len(Trueseeing_unique_item)):
        Trueseeing_unique_item.append(None)
    for i in range(max_n-len(DroidStatx_unique_item)):
        DroidStatx_unique_item.append(None)

    AUSERA_single_vlun_array = np.array(AUSERA_unique_item).reshape(-1, 1)
    Androbugs_single_vlun_array = np.array(Androbugs_unique_item).reshape(-1, 1)
    MobSF_single_vuln_array = np.array(MobSF_unique_item).reshape(-1, 1)
    qark_single_vuln_array = np.array(qark_unique_item).reshape(-1, 1)
    super_single_vuln_array = np.array(super_unique_item).reshape(-1, 1)
    jaadas_single_vuln_array = np.array(jaadas_unique_item).reshape(-1, 1)
    marvin_single_vuln_array = np.array(marvin_unique_item).reshape(-1, 1)
    speck_single_vuln_array = np.array(speck_unique_item).reshape(-1, 1)
    APKHunt_single_vuln_array = np.array(APKHunt_unique_item).reshape(-1, 1)
    Trueseeing_single_vuln_array = np.array(Trueseeing_unique_item).reshape(-1, 1)
    DroidStatx_single_vuln_array = np.array(DroidStatx_unique_item).reshape(-1, 1)

    all_tools_single = np.concatenate((qark_single_vuln_array,Androbugs_single_vlun_array,jaadas_single_vuln_array,marvin_single_vuln_array,super_single_vuln_array,
                                       MobSF_single_vuln_array,speck_single_vuln_array,AUSERA_single_vlun_array,
                                       APKHunt_single_vuln_array,Trueseeing_single_vuln_array,DroidStatx_single_vuln_array),axis=1)
    csv_columns = ['QARK','AndroBugs','JAADAS','Marvin','SUPER','MobSF','SPECK', 'AUSERA','APKHunt','Trueseeing','DroidStatx']    
    single_apk_vlun = pd.DataFrame(all_tools_single,index=range(max_n),columns=csv_columns)
    outputpath = os.path.join(CSV_folder, apk_name + '.csv')
    header_list  = ['Uniqe items for all tools !']
    with open(outputpath, mode="a") as f:
        writer = csv.writer(f)
        writer.writerow(header_list)
    single_apk_vlun.to_csv(outputpath, sep=',', index=True, header=True,mode='a')

def data_single_merge(apk_name,reports_folder,CSV_folder,stra_option,confiden_option):
    logger.info(' [VulsTotal Metadata Process] Now Process the matadata.')
    single_vul_list = []
    current_path = os.path.dirname(os.path.abspath(__file__))
    rules_path = os.path.join(current_path,'frameworkrule.json')
    rules_file = open(rules_path,'r')
    rules_list = json.load(rules_file)
    rules_file.close()

    for i in range(len(apk_name)):
        logger.info(' [VulsTotal Metadata Process] for '+ apk_name[i])
        scan_failure_list = [1,1,1,1,1,1,1,1,1,1,1] # scan success is 1,or is 0
        apk_name[i] = os.path.splitext(apk_name[i])[0]
        apk_folder = os.path.join(reports_folder,apk_name[i])
        report_list = os.listdir(apk_folder)
        single_apk_folder = os.path.join(reports_folder,apk_name[i])
        AUSERA_single_vlun, AUERA_single_desc = [0],[0]
        Androbugs_single_vlun, androbugs_single_desc = [0],[0]                         
        MobSF_single_vuln, MobSF_single_desc = [0],[0]
        qark_single_vuln = [0]
        super_single_vuln, super_single_desc = [0],[0]
        jaadas_single_vuln = [0]
        marvin_single_vuln, marvin_vuln_single_desc = [0],[0]
        speck_single_vuln, speck_rule29_single_descs = [0],[0]
        APKHunt_single_vuln = [0]
        Trueseeing_single_vuln, Trueseeing_single_descs = [0],[0]
        DroidStatx_single_vuln = [0]
        if report_name(0) in report_list and report_name(1) in report_list:
            AUSERA_single_vlun, AUERA_single_desc = get_ausera(single_apk_folder)
        if report_name(2) in report_list and report_name(3) in report_list:
            Androbugs_single_vlun, androbugs_single_desc = get_Androbugs(single_apk_folder)
        if report_name(4) in report_list and report_name(5) in report_list:
            MobSF_single_vuln, MobSF_single_desc = get_MobSF(single_apk_folder)
        if report_name(6) in report_list :
            qark_single_vuln = get_qark(single_apk_folder)
        if report_name(7) in report_list and report_name(8) in report_list:
            super_single_vuln, super_single_desc = get_super(single_apk_folder)
        if report_name(9) in report_list :
            jaadas_single_vuln = get_jaadas(single_apk_folder)
        if report_name(10) in report_list and report_name(11) in report_list:
            marvin_single_vuln, marvin_vuln_single_desc = get_marvin(single_apk_folder)
        if report_name(12) in report_list and report_name(13) in report_list:
            speck_single_vuln, speck_rule29_single_descs = get_speck(single_apk_folder)
        if report_name(14) in report_list:
            APKHunt_single_vuln,APKHunt_single_descs = get_APKHunt(single_apk_folder)
        if report_name(15) in report_list and report_name(16) in report_list:
            Trueseeing_single_vuln, Trueseeing_single_descs = get_trueseeing(single_apk_folder)
        if report_name(17) in report_list:
            DroidStatx_single_vuln = get_droidstatx(single_apk_folder)[0]

        if(AUSERA_single_vlun == [0]):
            scan_failure_list[0] = 0
        if(Androbugs_single_vlun == [0]):
            scan_failure_list[1] = 0
        else:
            Androbugs_single_vlun,androbugs_single_desc = screen_demo_Androbugs(Androbugs_single_vlun,androbugs_single_desc)
        if(MobSF_single_vuln == [0]):
            scan_failure_list[2] = 0
        else:
            MobSF_single_vuln,MobSF_single_desc = screen_demo_MobSF(MobSF_single_vuln,MobSF_single_desc)
        if(qark_single_vuln == [0]):
            scan_failure_list[3] = 0
        if(super_single_vuln == [0]):
            scan_failure_list[4] = 0
        if(jaadas_single_vuln == [0]):
            scan_failure_list[5] = 0
        if(marvin_single_vuln == [0]):
            scan_failure_list[6] = 0
        if(speck_single_vuln == [0]):
            scan_failure_list[7] = 0
        if(APKHunt_single_vuln == [0]):
            scan_failure_list[8] = 0
        if(Trueseeing_single_vuln == [0]):
            scan_failure_list[9] = 0
        if(DroidStatx_single_vuln == [0]):
            scan_failure_list[10] = 0

        (AUSERA_single_vlun, Androbugs_single_vlun, MobSF_single_vuln, 
        qark_single_vuln, super_single_vuln, jaadas_single_vuln, marvin_single_vuln, 
        speck_single_vuln, APKHunt_single_vuln, Trueseeing_single_vuln, DroidStatx_single_vuln,
        AUSERA_unique_item,Androbugs_unique_item,
        MobSF_unique_item,qark_unique_item,super_unique_item,jaadas_unique_item,
        marvin_unique_item,speck_unique_item, APKHunt_unique_item, 
        Trueseeing_unique_item, DroidStatx_unique_item) = corresponding_overlap(apk_name[i], 
                                AUSERA_single_vlun, Androbugs_single_vlun,
                                MobSF_single_vuln, qark_single_vuln, 
                                super_single_vuln,jaadas_single_vuln, 
                                marvin_single_vuln, speck_single_vuln, 
                                AUERA_single_desc, androbugs_single_desc,
                                MobSF_single_desc, super_single_desc, 
                                marvin_vuln_single_desc,
                                speck_rule29_single_descs,
                                APKHunt_single_vuln,APKHunt_single_descs,
                                Trueseeing_single_vuln,
                                Trueseeing_single_descs,DroidStatx_single_vuln,
                                rules_list)
        # get the final result via the majar vote method
        singe_name_vul= overlap(apk_name[i], AUSERA_single_vlun, Androbugs_single_vlun,
                                        MobSF_single_vuln, qark_single_vuln, 
                                        super_single_vuln,jaadas_single_vuln, 
                                        marvin_single_vuln, speck_single_vuln,
                                        APKHunt_single_vuln, Trueseeing_single_vuln, 
                                        DroidStatx_single_vuln,
                                        scan_failure_list,rules_list,stra_option,confiden_option,CSV_folder)
        
        uniqe_item(apk_name[i],AUSERA_unique_item ,Androbugs_unique_item ,
                   MobSF_unique_item ,qark_unique_item ,
                   super_unique_item ,jaadas_unique_item ,
                   marvin_unique_item ,speck_unique_item,
                   APKHunt_unique_item,Trueseeing_unique_item, DroidStatx_unique_item, CSV_folder )
    
        
        single_vul_list.append(singe_name_vul)
    return single_vul_list

def get_min_apk_set(all_apk_vul):
    for i in range(len(all_apk_vul)):
        all_apk_vul[i]['len'] = len(all_apk_vul[i]['true_vuln_list'])
    all_apk_vul.sort(key = lambda x : x['len'])
    all_apk_vul.reverse()
    all_list = []
    min_apk_set = []
    for i in range(len(all_apk_vul)):
        all_list = all_list + all_apk_vul[i]['true_vuln_list']
    all_list = list(set(all_list))
    vul_length = len(all_list)
    logger.info(' All covered vuln types numbers is ' + str(len(all_list))+'')
    for i in range(len(all_apk_vul)):
        valid_list = []
        for j in range(len(all_apk_vul[i]['true_vuln_list'])):
            if(all_list == []):
                break
            if(all_apk_vul[i]['true_vuln_list'][j] in all_list):
                valid_list.append(all_apk_vul[i]['true_vuln_list'][j])
                all_list.remove(all_apk_vul[i]['true_vuln_list'][j])
        if not (valid_list == []):
            apk_info = {'apk_name':all_apk_vul[i]['apk_name'],'true_vuln_list' : all_apk_vul[i]['true_vuln_list']}
            min_apk_set.append(apk_info)
    logger.info(' The Min APK Set is following, and the list including the vuls id contain in the apk.')
    # print('---------------------'+str(logger.msg_queue.qsize()))
    for i in range(len(min_apk_set)):
        logger.info(' '+str(min_apk_set[i]))
    logger.info(' Min_apk_set length is '+str(len(min_apk_set))+"")        
    
    return vul_length,min_apk_set

def parseArgument():
    parser = argparse.ArgumentParser(description='VulsTotal - A Unified Platform for Evaluating and Benchmarking SAST Tools for Android')
    parser.add_argument("-d","--apk_folder",help="The APK folder stored the target APKs",type = str, required = True)
    parser.add_argument("-s","--strategy",help="The strategy option(0:customized majority voting; 1:granularity-aware majority voting)",type = int, required = True)
    parser.add_argument("-f","--confidence",help="The confidence option(please in the number in [50,100)",type = int, required = True)
    args = parser.parse_args()
    return args

def run(apk_folder, stra_option, confiden_option):
    # Prepare the rules
    current_folder = os.getcwd()
    rules_path = os.path.join(current_folder,'frameworkrule.json')
    rules_file = open(rules_path,'r')
    rules_list = json.load(rules_file)
    rules_file.close()

    # Prepare for the necessary folder
    reports_folder = os.path.join(current_folder,'VulsTotal_Report')
    if not(os.path.exists(reports_folder)):
        os.mkdir(reports_folder)
    CSV_folder = os.path.join(current_folder,'CSV_Result')
    if not(os.path.exists(CSV_folder)):
        os.mkdir(CSV_folder)

    all_apk_vul = []
    apk_name = apk_name_handle(apk_folder)
    logger.info(' [VulsTotal ] Analyzing... Please wait for a moment.')
    # scan(reports_folder, apk_folder)
    single_vul_list = data_single_merge(apk_name=apk_name,reports_folder=reports_folder,CSV_folder=CSV_folder,stra_option=stra_option,confiden_option=confiden_option)
    '''    
    for i in range(len(single_vul_list)):
        all_apk_vul.append(single_vul_list[i])
    vul_length,min_apk_set = get_min_apk_set(all_apk_vul)
    name_file = os.path.join(current_folder,'Download_res',os.path.basename(apk_folder)+'_minAppSetResult.txt')
    with open(name_file,'w+') as f:
        f.write('************************************************************************************\n')
        f.write('*                           VulsTotal Analysis Results                             *\n')
        f.write('************************************************************************************\n')
        for i in range(len(min_apk_set)):
            f.write('*The app ' + str(min_apk_set[i]['apk_name']) + ' contains the vulnerability types: \n')
            for j in range(len(min_apk_set[i]['true_vuln_list'])):
                index = min_apk_set[i]['true_vuln_list'][j]
                f.write('['+str(rules_list[index]['title'])+']\n')
            f.write('************************************************************************************\n')
    logger.info(' [VulsTotal Scanning] Finished!')
    '''   
    return vul_length,min_apk_set,all_apk_vul

if __name__ == '__main__':
    args = parseArgument()
    apk_folder = args.apk_folder
    stra_option = args.strategy
    confiden_option = args.confidence

    vul_length,min_apk_set,all_apk_vul = run(apk_folder, stra_option, confiden_option)








