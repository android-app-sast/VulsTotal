# -*- coding: UTF-8 -*-
import json
import re
from pprint import pprint
import os
import shutil
import traceback
from speck_file_script import speck_file_pro
import operator

def super_vuln_pro(rules_singe,vuln_desc,tool_desc,i,tool_vuln):
    pattern  = rules_singe[vuln_desc]
    single_vuln = "NULL"
    if(len(pattern)== 1):
        if(len(list(tool_desc[i]))>0):
            for a in range(len(tool_desc[i])):
                match_desc = re.search(pattern[0],tool_desc[i][a])
                if(match_desc):
                    single_vuln = rules_singe["title"]
                    break
    elif(len(pattern)>1):
        length = len(pattern)
        match_desc_list = []
        if(len(tool_desc[i])>0):
            for a in range(len(tool_desc[i])):
                for j in range(length-1):
                    match_desc = re.search(pattern[j+1],tool_desc[i][a])
                    if(match_desc):
                        match_desc_list.append(1)
                    else:
                        match_desc_list.append(0)
                if(1 in match_desc_list):
                    single_vuln = rules_singe["title"]
                    break
    return single_vuln

def uniqe_pro(tool_vuln):
    curremt_folder = os.getcwd()
    frameworkrule = os.path.join(curremt_folder,'frameworkrule.json')
    with open(frameworkrule) as rulesF:
        tool_uniqe = 'NULL'
        rules = json.load(rulesF)
        title_list = []
        for i in range(len(rules)):
            title_list.append(rules[i]["title"])
        for i in range(len(tool_vuln)):
            
            if(tool_vuln[i] != "NULL") and (tool_vuln[i] not in title_list):
                tool_uniqe = tool_vuln[i]
                tool_vuln[i] = "NULL"
    return tool_uniqe

def vlun_valid(rules_singe,vuln_name,vuln_desc,tool_vuln, tool_desc):
    single_vuln = "NULL"
    if(vuln_name == "Super"):
        for key,content in rules_singe.items():
            if(key == vuln_name):
                if(len(content)==1):
                    match = re.search(content[0],tool_vuln)
                    if match:
                        if(vuln_desc in rules_singe.keys()):
                            if rules_singe["vlunid"] == 5:
                                single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc, 0, tool_vuln)
                            elif(rules_singe["vlunid"] == 6):
                                single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc, 0, tool_vuln)
                            elif(rules_singe["vlunid"] == 19):
                                single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc, 0, tool_vuln)
                            elif(rules_singe["vlunid"] == 20):
                                single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc, 0, tool_vuln)
                            elif(rules_singe["vlunid"] == 11):
                                single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc, 2, tool_vuln)
                            elif(rules_singe["vlunid"] == 30):
                                single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc, 2, tool_vuln)
                        else:
                            single_vuln = rules_singe["title"]
                            break
                elif(len(content)>1):
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
                        break
    elif(vuln_name == "Speck"):
        for key,content in rules_singe.items():
            if(key == vuln_name):
                if(len(content)==1):
                    match = re.search(content[0],tool_vuln)
                    if match:
                        if(vuln_desc in rules_singe.keys()):
                            if(len(tool_desc)>0):
                                if rules_singe["vlunid"] == 5:
                                    # print('id = 7')
                                    single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc,0,tool_vuln)
                                elif(rules_singe["vlunid"] == 6):
                                    # print('id = 8')
                                    single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc,0,tool_vuln)
                                elif(rules_singe["vlunid"] == 19):
                                    # print('id = 9')
                                    single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc,0,tool_vuln)
                                elif(rules_singe["vlunid"] == 20):
                                    # print('id = 10')
                                    single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc,0,tool_vuln)
                                elif(rules_singe["vlunid"] == 11):
                                    # print('id = 41')
                                    single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc,1,tool_vuln)
                                elif(rules_singe["vlunid"] == 30):
                                    # print('id = 42')
                                    single_vuln = super_vuln_pro(rules_singe,vuln_desc,tool_desc,1,tool_vuln)
                        else:
                            single_vuln = rules_singe["title"]
                            break     
                elif(len(content)>1):
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
                        break
    elif(vuln_name == "Marvin"):
        for key,content in rules_singe.items():
            if(key == vuln_name):
                if(len(content)==1):
                    match = re.search(content[0],tool_vuln)
                    if match:
                        if(vuln_desc in rules_singe.keys()):
                            pattern  = rules_singe[vuln_desc]
                            if(len(pattern)== 1):
                                for a in range(len(tool_desc)):
                                    match_desc = re.search(pattern[0],tool_desc[a]['description'])
                                    if(match_desc):
                                        single_vuln = rules_singe["title"]
                                        break
                            elif(len(pattern)>1):
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
                                        break
                        else:
                            single_vuln = rules_singe["title"]
                            break         
                elif(len(content)>1):
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
                        break
    else:
        for key,content in rules_singe.items():
            if(key == vuln_name):
                if(len(content)==1):
                    match = re.search(content[0],tool_vuln)
                    if match:
                        if(vuln_desc in rules_singe.keys()):
                            pattern  = rules_singe[vuln_desc]
                            if(len(pattern)== 1):
                                for a in range(len(tool_desc)):
                                    match_desc = re.search(pattern[0],tool_desc[a])
                                    if(match_desc):
                                        single_vuln = rules_singe["title"]
                                        break
                            elif(len(pattern)>1):
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
                                        break
                        else:
                            single_vuln = rules_singe["title"]
                            break
                elif(len(content)>1):
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
                        break
    
    return single_vuln


def corresponding(tool_name,tool_vuln,tool_uniqe,rules,tool_desc=[]):
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
        return vuln_list,tool_uniqe


        