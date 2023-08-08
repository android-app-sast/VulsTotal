# -*- coding: UTF-8 -*-
# "Best_Gra": "AUSERA" // 最高颗粒度标记
import json
import re
from pprint import pprint
import os
import shutil
import traceback
from speck_file_script import speck_file_pro
import operator
# [1,"Base64 Encode"]  1 为or  2为and 

'''
def trash():
    if(key == "AUSERA") and ("AUSERA_desc" not in rules[i].keys()):
        if(len(content)==1):
            match = re.search(content[0],AUSERA_vlun)
            if match:
                print(match.group())
        elif(len(content)>1):
            length = len(content)
            match_list = []
            for j in range(length):
                match = re.search(content[j+1],AUSERA_vlun)
                if(match):
                    match_list.append(1)
                else:
                    match_list.append(0)
            if(1 in match_list):
                a = 1

    elif (key == "AUSERA") and ("AUSERA_desc" in rules[i].keys()):
        if(len(content)==1):
            match_vuln = re.search(content[0],AUSERA_vlun)
            if(match_vuln):
                pattern  = rules[i]["AUSERA_desc"]
                if(len(pattern)== 1):
                    match_desc = re.search(pattern[0],AUSERA_desc)
                    if(match_desc):
                        print(match.group())
                elif(len(pattern)>1):
                    length = len(pattern)
                    match_desc_list = []
                    for j in range(length):
                        match_desc = re.search(pattern[j+1],AUSERA_desc)
                        if(match_desc):
                            match_desc_list.append(1)
                        else:
                            match_desc_list.append(0)
                    if(1 in match_desc_list):
                        a = 1
'''

def super_vuln_pro(rules_singe,vuln_desc,tool_desc,i,tool_vuln):
    pattern  = rules_singe[vuln_desc]
    single_vuln = "NULL"
    if(len(pattern)== 1):
        # print("desc一个条件")

        # print(tool_desc[i])
        # print(len(tool_desc))
        if(len(list(tool_desc[i]))>0):
            for a in range(len(tool_desc[i])):
                match_desc = re.search(pattern[0],tool_desc[i][a])
                if(match_desc):
                    single_vuln = rules_singe["title"]
                    # print("---------------desc一个条件-------确认-----------------"+str(single_vuln))
                    # print(single_vuln)
                    break
    elif(len(pattern)>1):
        # print("desc多个条件")
        length = len(pattern)
        match_desc_list = []
        if(len(tool_desc[i])>0):
            for a in range(len(tool_desc[i])):
                # print(tool_desc[i][a])
                for j in range(length-1):
                    match_desc = re.search(pattern[j+1],tool_desc[i][a])
                    # print(pattern[j+1])
                    if(match_desc):
                        match_desc_list.append(1)
                    else:
                        match_desc_list.append(0)
                if(1 in match_desc_list):
                    single_vuln = rules_singe["title"]
                    # print("---------------desc多个条件---------------确认-----------------"+str(tool_vuln))
                    # print(single_vuln)
                    break
    return single_vuln

'''
def speck_vuln_pro(rules_singe,vuln_desc,tool_desc,i):
    pattern  = rules_singe[vuln_desc]
    if(len(pattern)== 1):
        # print("desc一个条件")
        if(len(tool_desc[i])>0):
            for a in range(len(tool_desc[i])):
                match_desc = re.search(pattern[0],tool_desc[i][a])
                if(match_desc):
                    tool_vuln = rules_singe["title"]
                    print("---------------desc一个条件---------确认-----------------"+str(tool_vuln))
                    print(tool_vuln)
                    a = 1
                    break
    elif(len(pattern)>1):
        # print("desc多个条件")
        length = len(pattern)
        match_desc_list = []
        if(len(tool_desc[i])>0):
            for a in range(len(tool_desc)):
                for j in range(length-1):
                    match_desc = re.search(pattern[j+1],tool_desc[i][a])
                    if(match_desc):
                        match_desc_list.append(1)
                    else:
                        match_desc_list.append(0)
                if(1 in match_desc_list):
                    tool_vuln = rules_singe["title"]
                    print("---------------desc多个条件------------确认-----------------"+str(tool_vuln))
                    print(tool_vuln)
                    a = 1
                    break
    return tool_vuln
'''

def uniqe_pro(tool_vuln):
    print('2222222222222222')
    print(tool_vuln)
    with open('/home/dell/zjy/tool_overlap_0311/frameworkrule.json') as rulesF:
        tool_uniqe = 'NULL'
        rules = json.load(rulesF)
        title_list = []
        for i in range(len(rules)):
            title_list.append(rules[i]["title"])
        for i in range(len(tool_vuln)):
            
            if(tool_vuln[i] != "NULL") and (tool_vuln[i] not in title_list):
                print("000000000000000"+ tool_vuln[i])
                tool_uniqe = tool_vuln[i]
                tool_vuln[i] = "NULL"
    return tool_uniqe

def vlun_valid(rules_singe,vuln_name,vuln_desc,tool_vuln, tool_desc):
    # single_vuln = tool_vuln
    single_vuln = "NULL"
    if(vuln_name == "Super"):
        for key,content in rules_singe.items():
            if(key == vuln_name):
                if(len(content)==1):
                    # print("只有一个vuln条件")
                    match = re.search(content[0],tool_vuln)
                    if match:
                        if(vuln_desc in rules_singe.keys()):
                            # print("需要再次确认desc")
                            if rules_singe["vlunid"] == 7:
                                single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc, 0, tool_vuln)
                            elif(rules_singe["vlunid"] == 8):
                                single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc, 0, tool_vuln)
                            elif(rules_singe["vlunid"] == 9):
                                single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc, 0, tool_vuln)
                            elif(rules_singe["vlunid"] == 10):
                                single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc, 0, tool_vuln)
                            elif(rules_singe["vlunid"] == 41):
                                single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc, 2, tool_vuln)
                            elif(rules_singe["vlunid"] == 42):
                                single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc, 2, tool_vuln)
                        else:
                            # print("不需要再次确认desc")
                            single_vuln = rules_singe["title"]
                            # print("---------------不需要再次确认desc------------确认-----------------"+str(single_vuln))
                            # print(single_vuln)
                            break
                elif(len(content)>1):
                    # print("有几个vuln条件 不用确认desc条件")
                    length = len(content)
                    match_list = []
                    for j in range(length-1):
                        match = re.search(content[j+1],tool_vuln)
                        if(match):
                            match_list.append(1)
                        else:
                            match_list.append(0)
                    if(1 in match_list):
                        single_vuln = rules_singe["title"]
                        # print("---------------有几个vuln条件 不用确认desc条件---确认-----------------"+str(single_vuln))
                        # print(single_vuln)
                        break
    elif(vuln_name == "Speck"):
        for key,content in rules_singe.items():
            if(key == vuln_name):
                if(len(content)==1):
                    # print("只有一个vuln条件")
                    match = re.search(content[0],tool_vuln)
                    if match:
                        if(vuln_desc in rules_singe.keys()):
                            # print("需要再次确认desc")
                            if(len(tool_desc)>0):
                                if rules_singe["vlunid"] == 7:
                                    # print('id = 7')
                                    single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc,0,tool_vuln)
                                elif(rules_singe["vlunid"] == 8):
                                    # print('id = 8')
                                    single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc,0,tool_vuln)
                                elif(rules_singe["vlunid"] == 9):
                                    # print('id = 9')
                                    single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc,0,tool_vuln)
                                elif(rules_singe["vlunid"] == 10):
                                    # print('id = 10')
                                    single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc,0,tool_vuln)
                                elif(rules_singe["vlunid"] == 41):
                                    # print('id = 41')
                                    single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc,1,tool_vuln)
                                elif(rules_singe["vlunid"] == 42):
                                    # print('id = 42')
                                    single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc,1,tool_vuln)
                        else:
                            # print("不需要再次确认desc")
                            single_vuln = rules_singe["title"]
                            # print("---------------不需要再次确认desc------------确认-----------------"+str(single_vuln))
                            # print(single_vuln)
                            break     
                elif(len(content)>1):
                    # print("有几个vuln条件 不用确认desc条件")
                    length = len(content)
                    match_list = []
                    for j in range(length-1):
                        match = re.search(content[j+1],tool_vuln)
                        if(match):
                            match_list.append(1)
                        else:
                            match_list.append(0)
                    if(1 in match_list):
                        single_vuln = rules_singe["title"]
                        # print("---------------有几个vuln条件 不用确认desc条件---确认-----------------"+str(single_vuln))
                        # print(single_vuln)
                        break
    elif(vuln_name == "Marvin"):
        for key,content in rules_singe.items():
            if(key == vuln_name):
                if(len(content)==1):
                    # print("只有一个vuln条件")
                    match = re.search(content[0],tool_vuln)
                    if match:
                        if(vuln_desc in rules_singe.keys()):
                            # print("需要再次确认desc")
                            pattern  = rules_singe[vuln_desc]
                            if(len(pattern)== 1):
                                # print("desc一个条件")
                                for a in range(len(tool_desc)):
                                    match_desc = re.search(pattern[0],tool_desc[a]['description'])
                                    if(match_desc):
                                        single_vuln = rules_singe["title"]
                                        # print("---------------desc一个条件---------确认-----------------"+str(single_vuln))
                                        # print(single_vuln)
                                        break
                            elif(len(pattern)>1):
                                # print("desc多个条件")
                                length = len(pattern)
                                match_desc_list = []
                                for a in range(len(tool_desc)):
                                    for j in range(length-1):
                                        match_desc = re.search(pattern[j+1],tool_desc[a]['description'])
                                        if(match_desc):
                                            match_desc_list.append(1)
                                        else:
                                            match_desc_list.append(0)
                                    if(1 in match_desc_list):
                                        single_vuln = rules_singe["title"]
                                        # print("---------------desc多个条件------------确认-----------------"+str(single_vuln))
                                        # print(single_vuln)
                                        break
                        else:
                            # print("不需要再次确认desc")
                            single_vuln = rules_singe["title"]
                            # print("---------------不需要再次确认desc------------确认-----------------"+str(single_vuln))
                            # print(single_vuln)
                            break         
                elif(len(content)>1):
                    # print("有几个vuln条件 不用确认desc条件")
                    length = len(content)
                    match_list = []
                    for j in range(length-1):
                        match = re.search(content[j+1],tool_vuln)
                        if(match):
                            match_list.append(1)
                        else:
                            match_list.append(0)
                    if(1 in match_list):
                        single_vuln = rules_singe["title"]
                        # print("---------------有几个vuln条件 不用确认desc条件---确认-----------------"+str(single_vuln))
                        # print(single_vuln)
                        break
    else:
        for key,content in rules_singe.items():
            if(key == vuln_name):
                if(len(content)==1):
                    # print("只有一个vuln条件")
                    match = re.search(content[0],tool_vuln)
                    if match:
                        if(vuln_desc in rules_singe.keys()):
                            # print("需要再次确认desc")
                            pattern  = rules_singe[vuln_desc]
                            if(len(pattern)== 1):
                                # print("desc一个条件")
                                for a in range(len(tool_desc)):
                                    match_desc = re.search(pattern[0],tool_desc[a])
                                    if(match_desc):
                                        single_vuln = rules_singe["title"]
                                        # print("---------------desc一个条件---------确认-----------------"+str(single_vuln))
                                        # print(single_vuln)
                                        break
                            elif(len(pattern)>1):
                                # print("desc多个条件")
                                length = len(pattern)
                                match_desc_list = []
                                for a in range(len(tool_desc)):
                                    for j in range(length-1):
                                        match_desc = re.search(pattern[j+1],tool_desc[a])
                                        if(match_desc):
                                            match_desc_list.append(1)
                                        else:
                                            match_desc_list.append(0)
                                    if(1 in match_desc_list):
                                        single_vuln = rules_singe["title"]
                                        # print("---------------desc多个条件------------确认-----------------"+str(single_vuln))
                                        # print(single_vuln)
                                        break
                        else:
                            # print("不需要再次确认desc")
                            single_vuln = rules_singe["title"]
                            # print("---------------不需要再次确认desc------------确认-----------------"+str(single_vuln))
                            # print(single_vuln)
                            break
                elif(len(content)>1):
                    # print("有几个vuln条件 不用确认desc条件")
                    length = len(content)
                    match_list = []
                    for j in range(length-1):
                        match = re.search(content[j+1],tool_vuln)
                        if(match):
                            match_list.append(1)
                        else:
                            match_list.append(0)
                    if(1 in match_list):
                        single_vuln = rules_singe["title"]
                        # print("---------------有几个vuln条件 不用确认desc条件---确认-----------------"+str(single_vuln))
                        # print(single_vuln)
                        break
    
    return single_vuln


def corresponding(tool_name,tool_vuln,tool_uniqe,rules,tool_desc=[]):
    # with open('/home/dell/zjy/tool_overlap_0311/frameworkrule.json') as rulesF:
        # rules = json.load(rulesF)
        tool_uniqe = "NULL"
        single_vuln = "NULL"
        vuln_list = []
        flag = 0
        # print('==========='+tool_vuln)
        if(tool_name == "AUSERA"):
            for i in range(len(rules)):
                single_vuln = vlun_valid(rules[i],"AUSERA","AUSERA_desc",tool_vuln, tool_desc)
                vuln_list.append(single_vuln)
                if single_vuln != "NULL":
                    flag = flag +1 
                
        elif(tool_name == "Androbugs"):
            for i in range(len(rules)):
                single_vuln = vlun_valid(rules[i],"Androbugs","Androbugs_desc",tool_vuln, tool_desc)
                vuln_list.append(single_vuln)
                if single_vuln != "NULL":
                    flag = flag +1 
                
        elif(tool_name == "MobSF"):
            for i in range(len(rules)):
                single_vuln = vlun_valid(rules[i],"MobSF","MobSF_desc",tool_vuln, tool_desc)
                vuln_list.append(single_vuln)
                if single_vuln != "NULL":
                    flag = flag +1 
                
        elif(tool_name == "QARK"):
            for i in range(len(rules)):
                single_vuln = vlun_valid(rules[i],"QARK","QARK_desc",tool_vuln, tool_desc)
                vuln_list.append(single_vuln)
                if single_vuln != "NULL":
                    flag = flag +1 
                
        elif(tool_name == "Super"):
            for i in range(len(rules)):
                single_vuln = vlun_valid(rules[i],"Super","Super_desc",tool_vuln, tool_desc)
                vuln_list.append(single_vuln)
                if single_vuln != "NULL":
                    flag = flag +1 
                
        elif(tool_name == "Jaadas"):
            for i in range(len(rules)):
                single_vuln = vlun_valid(rules[i],"Jaadas","Jaadas_desc",tool_vuln, tool_desc)
                vuln_list.append(single_vuln)
                if single_vuln != "NULL":
                    flag = flag +1 
                
        elif(tool_name == "Marvin"):
            for i in range(len(rules)):
                single_vuln = vlun_valid(rules[i],"Marvin","Marvin_desc",tool_vuln, tool_desc)
                vuln_list.append(single_vuln)
                if single_vuln != "NULL":
                    flag = flag +1 
                
        elif(tool_name == "Speck"):
            for i in range(len(rules)):
                single_vuln = vlun_valid(rules[i],"Speck","Speck_desc",tool_vuln, tool_desc)
                vuln_list.append(single_vuln)
                if single_vuln != "NULL":
                    flag = flag +1 

        if (flag == 0):
            tool_uniqe = tool_vuln
        vuln_list = list(set(vuln_list))
        for i in reversed(range(len(vuln_list))):
            if(vuln_list[i] == "NULL"):
                del vuln_list[i]
        # print(vuln_list)
        return vuln_list,tool_uniqe

def speck_util():
    fdroid_path = '/media/dell/WD_BLACK/fdroid/'
    reports_folder = '/home/dell/zjy/tool_overlap_0311/F_droid_Report_3568'
    report_tree = os.listdir(reports_folder)
    apks_folder = os.listdir(fdroid_path)
    for i in reversed(range(len(apks_folder))):
        if (apks_folder[i].endswith('rar')):
            del apks_folder[i]

    for i in range(len(apks_folder)):
        apks_path = os.path.join(fdroid_path,apks_folder[i])
        apks_cate = os.listdir(apks_path)
        for j in range(len(apks_cate)):
            cate_path = os.path.join(apks_path,apks_cate[j])
    # reports_folder_monk = '/home/dell/zjy/tool_overlap_0311/APK_total_Report_1'
    # apks_folder_monk = '/media/dell/WD_BLACK/apk_monk_all'
    # reports_folder = '/home/dell/zjy/tool_overlap_0311/APK_total_Report'
    # apks_folder = '/home/dell/zjy/GHERA/'
            apk_path = os.listdir(cate_path)
            for a in range(len(apk_path)):
                try:
                    apkname = os.path.splitext(apk_path[a])[0]
                    speck_report_path = os.path.join(reports_folder,apkname,apkname +'_speak.txt')
                    speck_rule_context_fin,speck_rule29_desc = speck_file_pro(speck_report_path)

                    for j in range(len(speck_rule_context_fin)):
                        speck_rule_context_fin[j] = speck_rule_context_fin[j].encode('ascii')

                    apk_report_folder = os.path.dirname(speck_report_path)
                    ausera_vlun_file = os.path.join(apk_report_folder,'Speck_single_vlun_file.txt')
                    ausera_desc_file = os.path.join(apk_report_folder,'Speck_single_desc_file_1.txt')
                    if(len(speck_rule_context_fin)>0):
                        with open (ausera_vlun_file,'w+') as f:
                            f.write(str(speck_rule_context_fin))
                    else:
                        with open (ausera_vlun_file,'w+') as f:
                            f.write("[]")

                    if(len(speck_rule29_desc)>0):
                        with open (ausera_desc_file,'w+') as f:
                            f.write(str(speck_rule29_desc))
                    else:
                        with open (ausera_desc_file,'w+') as f:
                            f.write("[]")
                except:
                    print("Exception: "+apkname)
                    traceback.print_exc()
            print(len(apk_path))


'''
            for key,content in rules[i].items():
                if(key == "AUSERA"):
                    if(len(content)==1):
                        match = re.search(content[0],AUSERA_vlun)
                        if match:
                            if("AUSERA_desc" in rules[i].keys()):
                                pattern  = rules[i]["AUSERA_desc"]
                                if(len(pattern)== 1):
                                    match_desc = re.search(pattern[0],AUSERA_desc)
                                    if(match_desc):
                                        print(match.group())
                                elif(len(pattern)>1):
                                    length = len(pattern)
                                    match_desc_list = []
                                    for j in range(length):
                                        match_desc = re.search(pattern[j+1],AUSERA_desc)
                                        if(match_desc):
                                            match_desc_list.append(1)
                                        else:
                                            match_desc_list.append(0)
                                    if(1 in match_desc_list):
                                        a = 1
                            else:
                                print(match.group())
                    elif(len(content)>1):
                        length = len(content)
                        match_list = []
                        for j in range(length):
                            match = re.search(content[j+1],AUSERA_vlun)
                            if(match):
                                match_list.append(1)
                            else:
                                match_list.append(0)
                        if(1 in match_list):
                            a = 1
'''                      

                               

        #         if(key == "Androbugs"):
        #             len_list.append(len(content))
        #         if(key == "MobSF"):
        #             len_list.append(len(content))
        #         if(key == "QARK"):
        #             len_list.append(len(content))

        #         if(key == "Super"):
        #             len_list.append(len(content))
        #             # if(len(content)==1):
        #             #     match = re.search(content[0],AUSERA_vlun)
        #             # if(len(content)==3):
        #             #     if content[0] == 1:
        #             #         # 是or模式
        #             #         match_1 = re.search(content[1],AUSERA_vlun)
        #             #         match_2 = re.search(content[2],AUSERA_vlun)
        #             #         if(match_1 or match_2):
        #             #             print('Yes')
        #         if(key == "Jaadas"):
        #             len_list.append(len(content))
        #         if(key == "Marvin"):
        #             len_list.append(len(content))
        #         if(key == "Speck"):
        #             len_list.append(len(content))
        # len_list = list(set(len_list))
        # print(len_list)
        # print(max(len_list))







if __name__ == '__main__':
    AUSERA_vlun = "WebView password leakage jiahushfa"
    AUSERA_desc = "jdiaojdaojdsi"
    # speck_util()
    # corresponding("AUSERA",AUSERA_vlun,AUSERA_desc)
    STRING = "RSA/ECB/nopadding"
    pattern = ".*RSA\/.*\/nopadding.*"
    a = re.search(pattern,STRING)
    print(a.group())
    reports_folder_monk = '/home/dell/zjy/tool_overlap_0311/APK_total_Report_1'
    fdroid_path = '/media/dell/WD_BLACK/fdroid/'
    reports_folder = '/home/dell/zjy/tool_overlap_0311/F_droid_Report_3568'
    # report_tree = os.listdir(reports_folder)
    # apks_folder = os.listdir(fdroid_path)
    # for i in reversed(range(len(apks_folder))):
    #     if (apks_folder[i].endswith('rar')):
    #         del apks_folder[i]
    speak_num = 0
    filure_num = 0
    # MobSF_pro()
    # for i in range(len(apks_folder)):
    #     apks_path = os.path.join(fdroid_path,apks_folder[i])
    #     apks_cate = os.listdir(apks_path)
    #     for j in range(len(apks_cate)):
    #         cate_path = os.path.join(apks_path,apks_cate[j])
    # dir = os.listdir(reports_folder)
    # for i in range(len(dir)):
    #     rule_num = 0
    #     dir_abs = os.path.join(reports_folder,dir[i])
    #     dir_content = os.listdir(dir_abs)
    #     speck_abs = os.path.join(reports_folder,dir[i],dir[i]+'_speak.txt')
    #     speck_name_path = dir[i]+'_speak.txt'
    #     speak_file = open(speck_abs,'r')
    #     speak_text = speak_file.readlines()
    #     for j in range(len(speak_text)):
    #         if(operator.contains(speak_text[j],"RULE: ")):
    #             rule_num = rule_num +1
    #     if(rule_num >= 32):
    #         speak_num = speak_num +1
    #     else:
    #         filure_num = filure_num +1
    #         speak_desc = 'Speck_single_desc_file.txt'
    #         speak_vuln = 'Speck_single_vlun_file.txt'
    #         speak_desc_path  = os.path.join(dir_abs,speak_desc)
    #         speak_vuln_path  = os.path.join(dir_abs,speak_vuln)
    #         print(speak_desc_path)
    #         print(speak_vuln_path)
    #         if(os.path.exists(speak_desc_path)):
    #             os.remove(speak_desc_path)
    #         if(os.path.exists(speak_vuln_path)):
    #             os.remove(speak_vuln_path)
    # print(speak_num) 
    # print(filure_num)      
        