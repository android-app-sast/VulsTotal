from imp import reload
import os
import json
import time
import logging
import subprocess
import traceback
import sys
reload(sys)
sys.setdefaultencoding('utf8')

class TimeoutError(Exception):  
    pass  

def jaadas_scan(jaadas_apk_path, jaadas_report_file):
    try:
        jaadas_apk_name = jaadas_apk_path.split('/')[-1]
        jaadas_apk = os.path.splitext(jaadas_apk_name)[0]        
        jaadas_report = os.path.join(jaadas_report_file, jaadas_apk)
        if not (os.path.exists(jaadas_report)):
            os.mkdir(jaadas_report)
        # jaadas_cmd_1 = 'java -jar /home/dell/zjy/06JAADAS-master/jaadas/jade-0.1.jar vulnanalysis -f ' + jaadas_apk_path + ' -p /home/dell/zjy/06JAADAS-master/jaadas/android-platforms -c /home/dell/zjy/06JAADAS-master/jaadas/config/ -o ' + jaadas_report + '/ --enableFlowOut'
        # jaadas_cmd_2 = 'java -jar /home/dell/zjy/06JAADAS-master/jaadas/jade-0.1.jar vulnanalysis -f ' + jaadas_apk_path + ' -p /home/dell/zjy/06JAADAS-master/jaadas/android-platforms -c /home/dell/zjy/06JAADAS-master/jaadas/config/ -o ' + jaadas_report + '/ --fastanalysis'
        jaadas_cmd_1 = ['java','-jar','/home/dell/zjy/06JAADAS-master/jaadas/jade-0.1.jar','vulnanalysis','-f',jaadas_apk_path,'-p','/home/dell/zjy/06JAADAS-master/jaadas/android-platforms','-c','/home/dell/zjy/06JAADAS-master/jaadas/config/','-o',jaadas_report,'--enableFlowOut']
        jaadas_cmd_2 = ['java','-jar','/home/dell/zjy/06JAADAS-master/jaadas/jade-0.1.jar','vulnanalysis','-f',jaadas_apk_path,'-p','/home/dell/zjy/06JAADAS-master/jaadas/android-platforms','-c','/home/dell/zjy/06JAADAS-master/jaadas/config/','-o',jaadas_report,'--fastanalysis']
        jaadas_report_abso_path = ''
        timeout = 360
        flag = 0
        
        log_1 = open('jaadas_log_output.txt','w+')
        log_1.write('Jaadas log file \n')
        log_1.flush()
        log_2 = open('jaadas_log_err.txt','w+')
        log_2.write('Jaadas log file \n')
        log_2.flush()
        
        p = subprocess.Popen(jaadas_cmd_1,
                            stdout=log_1,
                            stderr=log_2,
                            close_fds=True,
                            shell=False)
        t_beginning = time.time()
        while True:
            if p.poll() is not None:
                logging.info('scan successfully in full mode!')
                break
            seconds_passed = time.time() - t_beginning
            if timeout and seconds_passed > timeout:  
                p.terminate()
                msg = 'This app '+ jaadas_apk_name + ' is timeout and needs to analysis in fast mode!'
                logging.warning(msg)
                break
            time.sleep(1)
        p.wait()
        log_1.flush()
        log_2.flush()
        log_1.seek(os.SEEK_SET)
        log_2.seek(os.SEEK_SET)
        err = log_2.read()
        output = log_1.read()
        t_ending = time.time()
        different_time = t_ending-t_beginning
        print(different_time)
        time_path = '/home/dell/zjy/tool_overlap_0311/Time_Record_0721/jaadas_time_record.txt'
        time_file = open(time_path,'a')
        time_file.write(jaadas_apk_path+' : ')
        time_file.write(str(different_time))
        time_file.write('\n')
        time_file.close()
        
        log_1.close()
        log_2.close()
        for line in output.decode().splitlines():
            if ('analysis finished, see results at' in line):
                jaadas_report_abso_path = line.split(' ')[5]
        jaadas_report_old_name = jaadas_report_abso_path
        
        jaadas_report_new_name = os.path.join(jaadas_report,jaadas_apk + '_jaadas.txt')
        print(jaadas_report_new_name)
        os.rename(jaadas_report_old_name, jaadas_report_new_name)
        return jaadas_report_new_name
    except Exception as e:
        # logging.critical('[Jaadas]the app has somethins wrong like'+str(e))
        traceback.print_exc()
        a = 0


def jaadas_pro(jaadas_report_path):
    try:
        jaadas_report_file = open(jaadas_report_path, 'r')
        jaadas_report = jaadas_report_file.read()
        jaadas_report_dict = json.loads(jaadas_report)
        jaadas_report_results = jaadas_report_dict['results']
        jaadas_report_file.close()
        jaadas_vuln = []
        for i in range(len(jaadas_report_results)):
            jaadas_vuln.append(jaadas_report_results[i]['desc'])
        return jaadas_vuln
    except Exception as e:
        logging.critical('something wrong happened in jaadas file process! '+ str(e))


def jaadas_file_scan_batch(jaadas_scanapks_path, jaadas_report_file):
    
    jaadas_scan_apks = os.listdir(jaadas_scanapks_path)
    
    for i in reversed(range(len(jaadas_scan_apks))):
        if not (jaadas_scan_apks[i].split('.')[-1] == 'apk'):
            del jaadas_scan_apks[i]
    for i in reversed(range(len(jaadas_scan_apks))):
        apk = os.path.splitext(jaadas_scan_apks[i])[0]
        report_folder = os.path.join(jaadas_report_file,apk)
        if not (os.path.exists(report_folder)):
            os.mkdir(report_folder)
        tree = os.listdir(report_folder)
        speck = apk +'_jaadas.txt'
        if (speck in tree ):
            del jaadas_scan_apks[i]


    jaadas_scan_apks_abso_path = []
    for i in range(len(jaadas_scan_apks)):
        jaadas_scan_apks_abso_path.append(os.path.join(jaadas_scanapks_path, jaadas_scan_apks[i]))

    for i in range(len(jaadas_scan_apks_abso_path)):
        try:
            logging.info('Now begin to scan apk using JAADAS____'+jaadas_scan_apks[i]+'('+ str(i + 1) + '/' + str(len(jaadas_scan_apks_abso_path))+')' )
            jaadas_report_new_name = jaadas_scan(jaadas_scan_apks_abso_path[i], jaadas_report_file)
            jaadas_single_vuln = jaadas_pro(jaadas_report_new_name)
            apk_report_folder = os.path.dirname(jaadas_report_new_name)
            ausera_vlun_file = os.path.join(apk_report_folder,'Jaadas_single_vlun_file.txt')
            with open (ausera_vlun_file,'w+') as f:
                f.write(str(jaadas_single_vuln))
        except Exception as e:
            logging.critical('something happened in jaadas ' + str(jaadas_scan_apks[i]) + repr(e))

