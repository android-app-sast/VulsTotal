# -*- coding: UTF-8 -*-
import os
import re
import logging
import subprocess
import json
import requests
import csv
from multiprocessing.dummy import Pool as ThreadPool

logger = logging.getLogger('my_logger')
logger.setLevel(logging.DEBUG)  # 设置日志级别，这里是DEBUG，可以改为INFO, WARNING, ERROR等
# 创建一个handler，用于写入日志文件
fh = logging.FileHandler('/home/dell/下载/androzoo.log')  # 指定义日志文件名
# 定义handler的输出格式
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
# 给logger添加handler
logger.addHandler(fh)

def open_csv(csv_file):
    cvename_package = {}
    with open(csv_file, 'r') as csvfile:
        reader = csv.reader(csvfile)
        # 遍历每一行
        next(reader)

        for row in reader:
            key = row[0]
            value = row[1].replace(' ','').replace('\t','').replace('.','\.')
            cvename_package[key] = value
    return cvename_package

def open_csv_version(csv_file):
    # 获取cveName,packageName,version,三组key-value对
    all_cvename_package_version = []
    with open(csv_file, 'r') as csvfile:
        reader = csv.reader(csvfile)
        # 遍历每一行
        next(reader)
        for row in reader:
            cvename_package_version = {}
            cvename_package_version["cveName"] = row[0]
            cvename_package_version["packageName"] = row[1]
            cvename_package_version["version"] = row[2]
            all_cvename_package_version.append(cvename_package_version)
    return all_cvename_package_version
        
def androzpp_1(cvename_package_version,json_file,json_file_install):
    # 输入是带有[cveName,packageName,version]的list
    # json_file : 读取json
    # json_file_install : 排除后得到的json
    # 排查already的版本数

    have_cve_name = []
    have_androzoo_cve_name = []

    with open(json_file,'r') as f:
        # 获取所有符合日期的cve的androzoo的记录
        data = f.read()
        json_objects = re.findall(r'\{.*?\}', data, re.DOTALL)
        parsed_objects = [json.loads(obj) for obj in json_objects] # 提取所有1348条字典

    for obj in parsed_objects:
        for single_version in cvename_package_version:
            if(single_version["cveName"] == obj["cveName"]):
                obj["version"] = single_version["version"]
                have_cve_name.append(obj)
                break

    with open(json_file_install,'r') as f:
        # 获取已经解析出来的androzoo记录，防止重复工作
        data = f.read()
        json_objects = re.findall(r'\{.*?\}', data, re.DOTALL)
        parsed_objects = [json.loads(obj) for obj in json_objects]
    for obj in parsed_objects:
        have_androzoo_cve_name.append(obj["cveName"])
    
    have_cve_name = sorted(have_cve_name,key=lambda x: x.get("cveName"))
    
    for obj in have_cve_name:
        if(obj["cveName"] ):  
            print("==================目前判断的是cve是->"+str(obj["cveName"])+"==================")
            if(obj["androzoo"]):
                print("该CVE存在规定范围内的androzoo记录")
                for single_androzoo in obj["androzoo"]:
                    try:
                        androzoo_version = str(single_androzoo).split(',')[6]
                        # print("==================目前判断的是cve是->"+str(obj["cveName"])+"==================")
                        # print(str(obj["cveName"])+" 的androzoo版本号是: "+ androzoo_version)
                        need_version = obj["version"].replace('0','').replace('.','.*') 
                        need_version_pattern = pattern_res = re.match(need_version,androzoo_version)
                        if(need_version_pattern):
                            print("++++++++++++++匹配到++++++++++++++")
                            print(str(obj["cveName"])+" 的本条androzoo版本号是: "+ androzoo_version)
                            print(str(obj["cveName"])+" 的[需要的]版本号: "+ obj["version"])
                            print("匹配到need_version_pattern = " + need_version_pattern.group()+'--------------------')
                            with open(json_file_install,'a+') as f:
                                androzoo_obj = {}
                                androzoo_obj['packageName'] = obj['packageName']
                                androzoo_obj['need_version'] = obj['version']
                                androzoo_obj['andro_version'] = androzoo_version
                                androzoo_obj['cveName'] = obj['cveName']
                                androzoo_obj['androzoo'] = single_androzoo

                                json.dump(androzoo_obj,f,ensure_ascii=False,indent=4)
                        else:
                            print("++++++++++++++没有匹配到++++++++++++++")
                            # print("==================目前判断的是cve是->"+str(obj["cveName"])+"==================")
                            print(str(obj["cveName"])+" 的本条androzoo版本号是: "+ androzoo_version)
                            print(str(obj["cveName"])+" 的需要的版本号: "+ obj["version"])
                        user_input = raw_input('请输入')
                    except:
                        logger.warning(str(obj["cveName"])+" 的androzoo版本号是: "+ androzoo_version)
                        logger.warning("需要的版本号："+ obj["version"])
            else:
                print("该CVE不存在规定范围内的androzoo记录")


def parse_json(json_file):
    # 提取json文件中的每个{}字典
    have_cve_name = []
    with open(json_file,'r') as f:
        data = f.read()
        json_objects = re.findall(r'\{.*?\}', data, re.DOTALL)
    parsed_objects = [json.loads(obj) for obj in json_objects]
    return parsed_objects
    

def androzoo(cvename_package):
    # 通过包名找sha5
    androzoo_file = '/home/dell/下载/latest.csv'
    # json_file = '/home/dell/下载/androzoo_parse.json'
    json_file = '/home/dell/下载/andro_parsed_package_noneed.json' # 是提取出的符合条件的androzoo条目

    have_cve_name = []
    # json_objects = re.findall(r'\{.*?\}', your_json_string, re.DOTALL)
    with open(json_file,'r') as f:
        # data = json.load(f)
        data = f.read()
        json_objects = re.findall(r'\{.*?\}', data, re.DOTALL)
    parsed_objects = [json.loads(obj) for obj in json_objects]
    for obj in parsed_objects:
        have_cve_name.append(obj["cveName"])

    num = 1
    for cvename, package_name in cvename_package.items():
        print(str(num) +" ==>" + package_name)
        num = num + 1
        if(cvename in have_cve_name):
            cve_year = cvename.split('-')[1]
            # awk_cmd = "awk -F ',' 'split($9,a,\"-\"); ($6 ~ /\""+ package_name +"\"/)  && (a[1] <= "+ cve_year + ")' " + androzoo_file
            # awk_cmd = "awk -F ',' '$6 ~ /\""+ package_name +"\"/' " + androzoo_file

            awk_cmd = "awk -F ',' '{split($9,a,\"-\"); if(a[1] <= "+ cve_year+" && $6 ~ /\""+ package_name +"\"/)  print $0 }' " + androzoo_file
            print(awk_cmd)
            # p = subprocess.Popen(awk_cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE,shell=True)
            # (output,err) = p.communicate()
            # # print(output)

            # json_data = {}
            # json_data["cveName"] = cvename
            # json_data["packageName"] = package_name
            # json_data["androzoo"] = []


            # split_line = str(output).split('\n')
            # for line in split_line:
            #     if(line != ''):
            #         json_data["androzoo"].append(line)
            

            # with open(json_file,'a+') as f:
            #     json.dump(json_data,f,ensure_ascii=False,indent=4)


def androzpp_2(parsed_objects,json_file_install):
    # 从找到的sha5中排查
    parsed_json_dic = sorted(parsed_objects,key=lambda x: x.get("cveName"))
    
    for obj in parsed_json_dic:
        logger.info("==================目前判断的是cve是->"+str(obj["cveName"])+"==================")
        print("==================目前判断的是cve是->"+str(obj["cveName"])+"==================")
        if(obj["androzoo"]):
            print("该CVE存在规定范围内的androzoo记录")
            logger.info("该CVE存在规定范围内的androzoo记录")
            for single_androzoo in obj["androzoo"]:
                try:
                    androzoo_version = str(single_androzoo).split(',')[6]
                    print(str(obj["cveName"])+" 的androzoo版本号是: "+ androzoo_version)
                    print(str(obj["cveName"])+" 的包名是: "+ str(obj['packageName']))
                    logger.info(str(obj["cveName"])+" 的androzoo版本号是: "+ androzoo_version)

                    user_input = raw_input("请判断是否留存: \n")

                    if(str(user_input) == "Y" or str(user_input) == 'y' or str(user_input) == '1'):
                        with open(json_file_install,'a+') as f:
                            androzoo_obj = {}
                            androzoo_obj['packageName'] = obj['packageName']
                            androzoo_obj['andro_version'] = androzoo_version
                            androzoo_obj['cveName'] = obj['cveName']
                            androzoo_obj['androzoo'] = single_androzoo
                            json.dump(androzoo_obj,f,ensure_ascii=False,indent=4)
                        break
                        
                except:
                    logger.warning(str(obj["cveName"])+" 的androzoo版本号是: "+ androzoo_version)
                    # logger.warning("需要的版本号："+ obj["version"])
        else:
            # print("该CVE不存在规定范围内的androzoo记录")
            logger.info("该CVE不存在规定范围内的androzoo记录")


def handel_noneed():
    json_file = '/home/dell/下载/andro_parsed_package_noneed.json'
    json_file_install = '/home/dell/下载/andro_filtered_package_noneed.json'

    parsed_objects = parse_json(json_file)
    androzpp_2(parsed_objects,json_file_install)

def find_cve(csv_file):
    # 从含有一列数据的csv文件提取出来
    cve_list = []
    with open(csv_file,'r') as f:
        cve_list = f.readlines()
    for i in range(len(cve_list)):
        cve_list[i] = cve_list[i].replace('\n','').replace('\r','')
    return cve_list

def diff_cve():
    # 找三个cve—list之间的不同
    csv_file_total = '/home/dell/下载/20240613Androzoo_filter/total.csv'
    csv_file_1 = '/home/dell/下载/20240613Androzoo_filter/csv01.csv'
    csv_file_2 = '/home/dell/下载/20240613Androzoo_filter/csv02.csv'
    cve_list_total = find_cve(csv_file_total)
    cve_list_01 = find_cve(csv_file_1)
    cve_list_02 = find_cve(csv_file_2)
    for i in reversed(range(len(cve_list_total))):
        if(cve_list_total[i] in cve_list_01):
            del cve_list_total[i]
        if(cve_list_total[i] in cve_list_02):
            del cve_list_total[i]
    print(cve_list_total)

def main_00():
    # 确定custom系列的版本号
    json_file = '/home/dell/下载/20240613Androzoo_filter/03androzoo_custom_filternull_noneed_103.json'
    json_file_install = '/home/dell/下载/20240613Androzoo_filter/andro_filtered_package_noneed.json'
    parsed_objects = parse_json(json_file=json_file)
    androzpp_2(parsed_objects,json_file_install)

def main_01():
    # 确定already系列的版本号
    csv_file = '/home/dell/下载/20240613Androzoo_filter/androzoo_version.csv'
    all_cvename_package_version = open_csv_version(csv_file)
    json_file = '/home/dell/下载/20240613Androzoo_filter/00androzoo_already_search_androzoo_1348.json'
    json_file_install = '/home/dell/下载/20240613Androzoo_filter/00androzoo_already_search_androzoo_1348.json'
    androzpp_1(all_cvename_package_version,json_file,json_file_install)

def find_duplicates(lst):
    seen = set()
    duplicates = set()
    for item in lst:
        if item in seen:
            duplicates.add(item)
        else:
            seen.add(item)
    return list(duplicates)


def main_02():
    # 将没有找到androzoo的条目筛选掉
    json_file = '/home/dell/下载/20240613Androzoo_filter/00androzoo_already_search_androzoo_1348.json'
    json_filtered_file_1255 = '/home/dell/下载/20240613Androzoo_filter/00androzoo_already_search_androzoo_1255.json'
    json_filtered_1003_file = '/home/dell/下载/20240613Androzoo_filter/00androzoo_already_search_androzoo_1003.json'
    json_filtered_252_file = '/home/dell/下载/20240613Androzoo_filter/01androzoo_already_filtered_androzoo_252.json'
    parsed_objects = parse_json(json_file=json_filtered_file_1255)
    filtered_list = parse_json(json_file=json_filtered_252_file)
    filtered_list_1006 = parse_json(json_file=json_filtered_1003_file)
    cve_name_list = []

    for obj in filtered_list:
        cve_name_list.append(obj['cveName'])

    androzoo_num = 0
    for obj in filtered_list_1006:
        for single_androzoo in obj['androzoo']:
            androzoo_num = androzoo_num +1 
            # with open(json_filtered_1003_file,'a+') as f:
            #     json.dump(obj,f,ensure_ascii=False,indent=4)
    print(androzoo_num)

def download_androzoo(json_filtered_252_file):
    parsed_objects = parse_json(json_file=json_filtered_252_file)
    apikey = '5af51b84f189e6051983d078706a7043da6a4c3014a9a28e74a86c63f34c5fc8'


    for obj in parsed_objects:
        for single_androzoo in obj['androzoo']:
            sha5 =  str(single_androzoo).split(',')[0]
            packageName =  str(single_androzoo).split(',')[5]
            versionCode =  str(single_androzoo).split(',')[6]
            base_url = 'https://androzoo.uni.lu/api/download?apikey={0}&sha256={01}'


    

if __name__ == '__main__':
    # handel_noneed()
    # diff_cve()
    main_02()
