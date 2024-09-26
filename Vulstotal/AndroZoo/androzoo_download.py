# -*- coding: UTF-8 -*-

import subprocess
from multiprocessing.dummy import Pool as ThreadPool
import os
import re
import json

from androzoo import androzoo



API_KEY = ""

DOWNLOAD_DIR = ""

def parse_json(json_file):
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
    sha256 =  str(single_androzoo).split(',')[0]
    packageName =  str(single_androzoo).split(',')[5].replace('"','')
    versionCode =  str(single_androzoo).split(',')[6]
    print(packageName)
    custom_name = packageName+'_'+sha256+'_'+versionCode+'.apk'
    output_path = os.path.join(DOWNLOAD_DIR, custom_name)
    if not(os.path.exists(output_path)):
        command = ["curl", "-o", output_path, "-G", "-d", "apikey={}".format(API_KEY), "-d", "sha256={}".format(sha256), "https://androzoo.uni.lu/api/download"]
        print(command)
        subprocess.call(command)

if __name__ == '__main__':

    pool = ThreadPool(10)  


    try:
        path = ''
        with open(path,'r') as f:
            content = f.readlines()
        # single_androzoo = []
        num = 0
        for line in content:
            line = line.replace('\n','').replace("\"","").replace("\\","")
            # single_androzoo.append(line)
            print("————"+str(num+1)+"个中————")
            # print(line)
            num = num + 1
            download_with_curl(line)
    finally:
        # pool.close()
        # pool.join()
        a = 1

