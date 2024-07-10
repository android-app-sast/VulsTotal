# -*- coding: UTF-8 -*-

import os
import re
import logging
import csv
import copy
import traceback
import json

from os import remove



def folder_dir_list(folder_dir):
    # 提取package信息
    list = os.listdir(folder_dir)
    package_info_list = []
    for dir in list:
        dir_abs_path = os.path.join(folder_dir,dir)
        report_name = dir
        androbugs_report_file = report_name+'_androbugs.txt'
        androbugs_report_file_path = os.path.join(dir_abs_path,androbugs_report_file)
        if(os.path.exists(androbugs_report_file_path)):
            package_info = {}
            with open(androbugs_report_file_path,'r') as f:
                file_data = f.readlines()
            for line in file_data:
                if('Package Name: ' in line):
                    package_info['packageName'] = line.replace('Package Name: ','').replace('\n','')
                elif('Package Version Name: ' in line):
                    package_info['versionName'] = line.replace('Package Version Name: ','').replace('\n','')
                elif('Package Version Code: ' in line):
                    package_info['versionCode'] = line.replace('Package Version Code: ','').replace('\n','')
            package_info_list.append(package_info)
    json_file = '/home/dell/下载/20240613AndrozooFilter/04androbugs_package_info.json'
    package_info_list = sorted(package_info_list,key=lambda x: x.get("packageName"))
    with open(json_file,'w') as f:
        json.dump(package_info_list,f,ensure_ascii=False,indent=4)


def parse_json(json_file):
    # 提取json文件中的每个{}字典
    have_cve_name = []
    with open(json_file,'r') as f:
        data = f.read()
        json_objects = re.findall(r'\{.*?\}', data, re.DOTALL)
    # for obj in json_objects:
    #     print(obj)
    #     json.loads(obj)
    parsed_objects = [json.loads(obj) for obj in json_objects]
    return parsed_objects


def info_diff():
    # 提取json文件信息，与csv文件对比
    csv_file = '/home/dell/下载/20240613AndrozooFilter/csv/1348_105.csv'
    new_csv_file = '/home/dell/下载/20240613AndrozooFilter/csv/1253_105.csv'
    new_csv_file_1122 = '/home/dell/下载/20240613AndrozooFilter/csv/1111.csv'
    csv_145 = '/home/dell/下载/20240613AndrozooFilter/androzoo_custom_record_package.csv'
    json_file = '/home/dell/下载/20240613AndrozooFilter/04androbugs_package_info.json'
    json_file_1255 = '/home/dell/下载/20240613AndrozooFilter/00androzoo_already_search_androzoo_1255.json'
    json_file_1348 = '/home/dell/下载/20240613AndrozooFilter/00androzoo_already_search_androzoo_1348.json'
    json_file_252 = '/home/dell/下载/20240613AndrozooFilter/01androzoo_already_filtered_androzoo_252.json'
    json_file_103 = '/home/dell/下载/20240613AndrozooFilter/03androzoo_custom_filternull_noneed_103.json'

    json_1255 = parse_json(json_file_1255)
    json_1348 = parse_json(json_file_1348)
    json_252 = parse_json(json_file_252)
    json_103 = parse_json(json_file_103)

    with open(json_file, 'r') as file:
        packageInfo = json.load(file)
    
    with open(csv_file,'r') as f:
        reader = csv.DictReader(f)
        all_csv_data = list(reader)
    with open(csv_145,'r') as f:
        reader = csv.DictReader(f)
        csv_145_data = list(reader)
    
    cve_145 = []
    for row in csv_145_data:
        cve_145.append(row['CVE-name'])


    cve_252 = []
    for obj in json_252:
        cve_252.append(obj['cveName'])
    cve_93 = []
    for obj in json_1348:
        if(obj not in json_1255):
            cve_93.append(obj['cveName'])
    cve_103 = []
    for obj in json_103:
        cve_103.append(obj['cveName'])

    cve_145_103 = []
    for cve in cve_145:
        if(cve not in cve_103):
            cve_145_103.append(cve)

    num = 0
    for line in all_csv_data:
        if(line['CVE-name'] in cve_93 or line['CVE-name'] in cve_145_103):
            line['androzoo_info'] = 'Not Exists in Androzoo'
        elif(line['CVE-name'] in cve_252):
            need_version = line['version']
            for json_obj in packageInfo:
                if(line['package'] == json_obj['packageName']):
                    print('-------------CVE-name----------------------------')
                    num = num +1
                    androzoo_version_name = json_obj['versionName']
                    androzoo_version_code = json_obj['versionCode']
                    print('需要的版本号是：'+str(need_version))
                    print('提供的版本号是：'+str(androzoo_version_name))
                    print('提供的版本码是：'+str(androzoo_version_code))
                    if(need_version == androzoo_version_name):
                        line['androzoo_info'] = androzoo_version_code
                    else:
                        new_need_version = need_version+'.0'
                        if(new_need_version == androzoo_version_name):
                            line['androzoo_info'] = androzoo_version_code
                        else:
                            user_input = raw_input('请输入判断')
                            if(user_input == 'Y' or user_input == 'y' or user_input == '1'):
                                line['androzoo_info'] = androzoo_version_code
                            else:
                                line['androzoo_info'] = 'Code False ' + androzoo_version_code

    with open(new_csv_file, mode='w') as file:
        # 获取字段名，这里假设所有字典的键都是一样的，直接使用第一个字典的键
        fieldnames = ['package', 'CVE-name', 'version', 'desc','androzoo_info']
        print(fieldnames)
        # 创建DictWriter对象
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        # 写入表头
        writer.writeheader()
        # 写入数据行
        for row in all_csv_data:
            writer.writerow(row)



def have_androzoo_cve():
    new_csv_file = '/home/dell/下载/20240613AndrozooFilter/csv/1253_105.csv'
    new_csv_file_1318 = '/home/dell/下载/20240613AndrozooFilter/csv/1111.csv'

    with open(new_csv_file,'r') as f:
        reader = csv.DictReader(f)
        all_csv_data = list(reader)
    num = 0
    print('开始所有csv数量'+str(len(all_csv_data)))
    filtered_list = []
    scan_list = []
    for line in all_csv_data:
        if('Code False' in line['androzoo_info'] or line['androzoo_info']==''):
            filtered_list.append(line)
        elif not ('Not' in line['androzoo_info']):
            scan_list.append(line)
   
    print('筛选后所有csv数量'+str(len(filtered_list)))
    print('需要扫描的数量' + str(len(scan_list)))

    with open(new_csv_file_1318, mode='w') as file:
        # 获取字段名，这里假设所有字典的键都是一样的，直接使用第一个字典的键
        fieldnames = ['package', 'CVE-name', 'version', 'desc','androzoo_info']
        print(fieldnames)
        # 创建DictWriter对象
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        # 写入表头
        writer.writeheader()
        # 写入数据行
        for row in filtered_list:
            writer.writerow(row)

    return scan_list

def apk_list(folder_path):
    apk_name = os.listdir(folder_path)
    for i in reversed(range(len(apk_name))):
        if not ('.apk' in apk_name[i]):
            del apk_name[i]
    apk_name.sort()
    return apk_name




def read_csv(csv_file):
    with open(csv_file,'r') as f:
        reader = csv.DictReader(f)
        all_csv_data = list(reader)
    return all_csv_data
 
def read_json(json_file):
    with open(json_file, 'r') as file:
        packageInfo = json.load(file)
    return packageInfo

def write_csv(new_csv_file,all_csv_data):
    with open(new_csv_file, mode='w') as file:
        # 获取字段名，这里假设所有字典的键都是一样的，直接使用第一个字典的键
        fieldnames = ['package', 'CVE-name', 'version', 'desc','androzoo_info']
        print(fieldnames)
        # 创建DictWriter对象
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        # 写入表头
        writer.writeheader()
        # 写入数据行
        for row in all_csv_data:
            writer.writerow(row)


def main03(package_info):
    # 根据androbugs得到的package信息，与我们需要的version进行比较
    new_csv_file_1122 = '/home/dell/下载/20240613AndrozooFilter/csv/1111.csv'
    andbugs_json_file = '/home/dell/下载/20240613AndrozooFilter/04androbugs_package_info.json'
    cve_1122 = read_csv(new_csv_file_1122)  # 我们需要的
    # package_info = read_json(andbugs_json_file) # 目前找到的
    for cve in cve_1122:
        need_version = cve['version']
        for package in package_info:
            if(package['packageName'] == cve['package'] ):
                print('-------------CVE-name----------------------------')
                androzoo_version_name = package['versionName']
                androzoo_version_code = package['versionCode']
                print('需要的版本号是：'+str(need_version))
                print('提供的版本号是：'+str(androzoo_version_name))
                print('提供的版本码是：'+str(androzoo_version_code))
                if(need_version == androzoo_version_name):
                    cve['androzoo_info'] = androzoo_version_code
                else:
                    new_need_version = need_version+'.0'
                    if(new_need_version == androzoo_version_name):
                        cve['androzoo_info'] = androzoo_version_code
                    else:
                        user_input = raw_input('请输入判断: ')
                        if(user_input == 'Y' or user_input == 'y' or user_input == '1'):
                            cve['androzoo_info'] = androzoo_version_code
                        else:
                            cve['androzoo_info'] = 'Code False ' + androzoo_version_code
                break
    
    # write_csv(new_csv_file_1122,cve_1122)

def main04():
    # 找到符合要求的androzoo记录
    new_csv_file_1122 = '/home/dell/下载/20240613AndrozooFilter/csv/1111.csv'
    cve_1122 = read_csv(new_csv_file_1122)  # 我们需要的
    scan_list = []
    for cve in cve_1122:
        if not ('Code' in cve['androzoo_info']):
            scan_list.append(cve)
    print(len(scan_list))
    return scan_list


def main02():
    scan_list = main04()
    apk_1003 = '/media/dell/WD_BLACK1/androzoo_apk_1003'
    apk_scan= '/media/dell/WD_BLACK1/apk_scan_androzoo_1'
    apk_1003_list = apk_list(apk_1003)
    apk_scan_list = apk_list(apk_scan)

    num = 0
    for list in scan_list:
        package_name = list['package']
        versionCode = list['androzoo_info']
        for apk_name in apk_1003_list:
            splite_list = apk_name.split('_')
            version_code = splite_list[-1].replace('.apk','')
            if(package_name in apk_name and versionCode == version_code):
                # print(apk_name)
                num = num + 1
                apk_path = os.path.join(apk_1003,apk_name)
                new_path = os.path.join(apk_scan,apk_name)
                # print(apk_path)
                # print(new_path)
                if(os.path.exists(apk_path)):
                    os.rename(apk_path,new_path)
    print(num )
    print(len(scan_list))

def main05():
    # 判断非x509漏洞的androzoo情况
    need_repro = []
    cve_65 = '/home/dell/下载/20240613AndrozooFilter/cve_65.csv'
    cve_65_data = read_csv(cve_65)
    cve_1122 = '/home/dell/下载/20240613AndrozooFilter/csv/1111.csv'
    cve_1122_data = read_csv(cve_1122)
    num = 0
    for cve in cve_65_data:
        for cve_data in cve_1122_data:
            if(cve['Name'] == cve_data['CVE-name']):
                if not ('Code' in cve_data['androzoo_info']):
                    num = num + 1
                    need_repro.append(cve_data)
                    print(cve)
    # print(num)
    # main03(need_repro)



if __name__ == '__main__':
    # info_diff()
    ANDROBUGS_REPORT_DIR = '/home/dell/zjy/VulsTotal/platform/androbugs_androzoo/'
    folder_dir_list(ANDROBUGS_REPORT_DIR)
    # main03()
    # main05()


