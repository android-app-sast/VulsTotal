# -*- coding: UTF-8 -*-

import subprocess
from multiprocessing.dummy import Pool as ThreadPool
import os
import re
import json

from androzoo import androzoo



# 替换为你自己的API Key
API_KEY = "5af51b84f189e6051983d078706a7043da6a4c3014a9a28e74a86c63f34c5fc8"

# 指定下载保存的根目录
DOWNLOAD_DIR = "/media/dell/WD_BLACK1/androzoo_apk_103"
DOWNLOAD_DIR = "/media/dell/WD_BLACK1/androzoo_apk_1003"
# DOWNLOAD_DIR = "/media/dell/WD_BLACK1/androzoo_apk"

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


def download_with_curl(single_androzoo):
    # 根据SHA256哈希值查找对应的自定义文件名
    sha256 =  str(single_androzoo).split(',')[0]
    packageName =  str(single_androzoo).split(',')[5].replace('"','')
    versionCode =  str(single_androzoo).split(',')[6]
    print("packageName是——————")
    print(packageName)
    custom_name = packageName+'_'+sha256+'_'+versionCode+'.apk'
    print('正在进行的是：'+str(custom_name))
    output_path = os.path.join(DOWNLOAD_DIR, custom_name)
    if not(os.path.exists(output_path)):
        command = ["curl", "-o", output_path, "-G", "-d", "apikey={}".format(API_KEY), "-d", "sha256={}".format(sha256), "https://androzoo.uni.lu/api/download"]
        print(command)
        subprocess.call(command)

if __name__ == '__main__':

    # 使用线程池并发执行下载任务
    pool = ThreadPool(10)  # 最大并发数为20


    try:
        '''
        # json_filtered_252_file = '/home/dell/下载/20240613AndrozooFilter/01androzoo_already_filtered_androzoo_252.json'
        json_filtered_103_file = '/home/dell/下载/20240613AndrozooFilter/03androzoo_custom_filternull_noneed_103.json'
        json_filtered_103_file = '/home/dell/下载/20240613AndrozooFilter/00androzoo_already_search_androzoo_1003.json'
        json_filtered_1003_file = '/home/dell/下载/20240613AndrozooFilter/00androzoo_already_search_androzoo_1003_add.json'
        parsed_objects = parse_json(json_file=json_filtered_1003_file)
        num = 0
        parsed_objects = sorted(parsed_objects,key=lambda x: x.get("cveName"))
        # for obj in parsed_objects:
        #     num = num + 1
        #     print('开始:'+str(num))
        #     print(obj['androzoo'])
        #     download_with_curl(obj['androzoo'])
            # pool.apply_async(download_with_curl, args=(obj['androzoo'],))
        for obj in parsed_objects:
            for single_androzoo in obj['androzoo']:
                num = num + 1
                print('开始:'+str(num))
                # print(single_androzoo)
                download_with_curl(single_androzoo)
            # pool.apply_async(download_with_curl, args=(obj['androzoo'],))
        # for obj in parsed_objects:
        #     if(len(obj['androzoo'])>2):
        #         obj['androzoo'] =  [obj['androzoo'][0], obj['androzoo'][-1]]
        # for obj in parsed_objects:
        #     with open(json_filtered_1003_file,'a+') as f:
        #         json.dump(obj,f,ensure_ascii=False,indent=4)                
        ** /
        '''
        path = '/home/dell/下载/20240613AndrozooFilter/androzoo_3.txt'
        with open(path,'r') as f:
            content = f.readlines()
        # single_androzoo = []
        num = 0
        for line in content:
            line = line.replace('\n','').replace("\"","").replace("\\","")
            # single_androzoo.append(line)
            print("————下载第"+str(num+1)+"个中————")
            # print(line)
            num = num + 1
            download_with_curl(line)
    finally:
        # pool.close()
        # pool.join()
        a = 1

