#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from IPy import IP
import requests
import nmap
import threading
import socket
import json
import time
import copy
import subprocess
from flask import Flask
import random
import os
import paramiko
from scp import SCPClient


this_fingerprint = None
app = Flask('flask')

@app.route("/")
def home():
    return this_fingerprint

class Scanner():
    report = {}
    project_conf = {}
    lock = None
    active_scanner = 0
    # 最大等待循环
    scan_max_number = 500
    # 每次检测时间
    scan_check_sec = 5
    # 全局等待循环
    global_scan_max_number = 500
    # 全局检测时间
    global_scan_check_sec = 5
    # 全局数据保留时间
    global_report_delete_sec = 600
    authentication_keys = {}

    def __init__(self) -> None:
        self.file_path = os.path.abspath(__file__)
        self.root_path = os.path.dirname(self.file_path)
        self.lock = threading.Lock()
        with open(os.path.join(self.root_path, 'data/project_conf.json'), 'r') as f:
            self.project_conf = json.load(f)
        with open(os.path.join(self.root_path, 'authentication/authentication_config.json'), 'r') as f:
            self.authentication_keys = json.load(f)
        self.report['project'] = {
            'project_id': self.project_conf['project_id'],
            'web_info_port': self.project_conf['web_info_port'],
            'this_fingerprint': str(random.random())[2:],
            'project_tar': '/tmp/scanner_test/'+self.project_conf['project_id']+'.tar'
        }
        self.report['sys_info'] = {
            'hostname': socket.gethostname(),
            'ips': self.getIPAddrs(),
            'service': self.scanService('127.0.0.1'),
        }

    def getIPAddrs(self):
        p = subprocess.Popen("hostname -I", shell=True, stdout=subprocess.PIPE)
        data = p.stdout.read()  # 获取命令输出内容
        data = str(data, encoding='UTF-8')  # 将输出内容编码成字符串
        ip_list = data.split(' ')  # 用空格分隔输出内容得到包含所有IP的列表
        if "\n" in ip_list:  # 发现有的系统版本输出结果最后会带一个换行符
            ip_list.remove("\n")
        if "127.0.0.1" in ip_list:  # 去除lo ip
            ip_list.remove("\n")
        # TODO 把掩码算出来
        return ip_list

    def scanService(self, target):
        nm = nmap.PortScanner()
        res = nm.scan(target, '1-65535', '-sS')
        return res['scan']

    def run_lateral_penetration(self, ipinfo):
        # 自动横向,收集数据并汇总
        # 地址获取
        if 'ipv4' in ipinfo['addresses']:
            ip = ipinfo['addresses']['ipv4']
        elif 'ipv6' in ipinfo['addresses']:
            ip = ipinfo['addresses']['ipv6']
        else:
            return
        print("scan_ip_start: ", ip, flush=True)

        # 目前只判断22端口是否开启,并使用测试私钥尝试登录
        if 22 not in ipinfo['tcp']:
            return

        # 尝试ssh登录
        ssh_port = 22
        # ssh密钥加载
        for key in self.authentication_keys['ssh']:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            name = key['name']
            type = key['type']
            if type == 'RSAKey':
                file_path = key['file_path']
                private_key = paramiko.RSAKey.from_private_key_file(
                    os.path.join(self.root_path, 'authentication/', file_path))
                try:
                    # 登录密钥不对
                    ssh_client.connect(hostname=ip, port=ssh_port, username=name, pkey=private_key)
                    scpclient = SCPClient(ssh_client.get_transport(), socket_timeout=15.0)
                except:
                    return
                print("had_find_ssh_login: ", ip, flush=True)
                # TODO密钥登录失败处理
                stdin, stdout, stderr = ssh_client.exec_command(f"ls /tmp/scanner_test")
                stdout_str = str(stdout.read())
                if self.project_conf['project_id'] in stdout_str:
                    # 已经扫描过的主机
                    return
                self.lock.acquire()
                self.active_scanner += 1
                self.lock.release()
                ssh_client.exec_command('rm -rf /tmp/scanner_test/*')
                ssh_client.exec_command('mkdir /tmp/scanner_test')
                ssh_client.exec_command(f"rm -rf /tmp/scanner_test/{self.project_conf['project_id']}/*")
                time.sleep(5)
                scpclient.put(self.report['project']['project_tar'], '/tmp/scanner_test')
                time.sleep(5)
                ssh_client.exec_command(f"tar -xvf {self.report['project']['project_tar']} -C /tmp/scanner_test")
                ssh_client.exec_command(f"cd /tmp/scanner_test/{self.project_conf['project_id']} && python3 run.py &> /tmp/scanner_test/scan_report.txt")
                while(True):
                    try:
                        time.sleep(3)
                        print("start_sub_edge_ip_fingerprint_scan: ", ip, flush=True)
                        res = requests.get(f"http://{ip}:{self.project_conf['web_info_port']}")
                        res2 = json.loads(res.text)
                        ip_fingerprint = res2['this_fingerprint']
                        self.lock.acquire()
                        self.report['connect'][ip]['ip_fingerprint'] = ip_fingerprint
                        self.lock.release()
                        print("end_sub_edge_ip_fingerprint_scan: ", ip, flush=True)
                        break
                    except:
                        pass
                for i in range(self.scan_max_number):
                    time.sleep(self.scan_check_sec)
                    print("scaning_ip: ", ip, f"{i}/{self.scan_max_number}", flush=True)
                    stdin, stdout, stderr = ssh_client.exec_command(f"ls /tmp/scanner_test/{self.project_conf['project_id']}_flag")
                    stdout_str = str(stdout.read(), encoding = "utf-8")
                    if 'flag' in stdout_str:
                        stdin, stdout, stderr = ssh_client.exec_command(f"ls /tmp/scanner_test/{self.project_conf['project_id']}/data/report")
                        stdout_str = str(stdout.read(), encoding = "utf-8")
                        files = stdout_str.split('\n')
                        print("find reports:", files, flush=True)
                        for file in files:
                            if 'flag' in file or file == '':
                                continue
                            scpclient.get(f"/tmp/scanner_test/{self.project_conf['project_id']}/data/report/{file}",
                                        f"/tmp/scanner_test/{self.project_conf['project_id']}/data/report/")
                            print(f"transport report:{file}", flush=True)
                        ssh_client.exec_command(f"rm -rf /tmp/scanner_test/{self.project_conf['project_id']}/*")
                        break
                # 没能按照规定时间得到相应。
                # TODO 给个报错
                print("scan_ip_over: ", ip, flush=True)
                self.lock.acquire()
                self.active_scanner -= 1
                self.lock.release()
                return

    def host_discovery(self):
        # 目前只扫描本网段ip,不考虑路由跳转情况
        scan_ip_list = []
        for ip in self.report['sys_info']['ips']:
            ip_network = '.'.join(ip.split('.')[:3])+'.0'
            ips = IP(f"{ip_network}/24")
            # TODO 把掩码算出来
            scan_ip_list.append(str(ips))

        self.report['connect'] = self.scanService(' '.join(scan_ip_list))

    def scan_remote(self):
        for ip in list(self.report['connect'].keys()):
            # 剔除本机
            if ip in self.report['sys_info']['ips']:
                self.report['connect'].pop(ip)
                continue
            if self.project_conf['web_info_port'] in self.report['connect'][ip]['tcp']:
                try:
                    # 已经被扫描过的设备,会开启一个固定端口,由此获取指纹,避免循环扫描
                    print(f"{ip},had open port {self.project_conf['web_info_port']}", flush=True)
                    res = requests.get(f'http://{ip}:{self.project_conf["web_info_port"]}')
                    res2 = json.loads(res.text)
                    ip_fingerprint = res2['this_fingerprint']
                    self.report['connect'][ip]['ip_fingerprint'] = ip_fingerprint
                    print(f"{ip},had scan,don't start.", flush=True)
                    continue
                except:
                    pass

            thread_scan = threading.Thread(target=self.run_lateral_penetration, args=[copy.deepcopy(self.report['connect'][ip])])
            thread_scan.start()
            # self.run_lateral_penetration(copy.deepcopy(self.report['connect'][ip]))

    def check_active_thread(self):
        check_success_cnt = 0
        for i in range(self.global_scan_max_number):
            time.sleep(self.global_scan_check_sec)
            active_scanner = 0
            self.lock.acquire()
            active_scanner = self.active_scanner
            self.lock.release()
            print("all active scanner:",active_scanner, flush=True)
            if active_scanner == 0:
                check_success_cnt += 1
            else:
                check_success_cnt == 0
            if check_success_cnt >= 3:
                return

    def run(self):
        # 启动flask 简化二次扫描
        global this_fingerprint
        this_fingerprint = json.dumps({'this_fingerprint': self.report['project']['this_fingerprint']})
        flask_thread = threading.Thread(target=app.run, args=['0.0.0.0', self.report['project']['web_info_port']])
        flask_thread.start()

        # 主机发现
        self.host_discovery()
        # 尝试登录,脚本下发
        self.scan_remote()
        # 检测子任务是否完成
        self.check_active_thread()
        # 保存数据
        with open(os.path.join(self.root_path, f"data/report/{self.report['project']['this_fingerprint']}.json"), 'w') as f:
            json.dump(self.report, f)
        with open(self.root_path+'_flag', 'w') as f:
            f.write('1')

        # 留出拉去数据的时间,过期自动删除数据
        print(f"scan over,it will down after {self.global_report_delete_sec}", flush=True)
        time.sleep(self.global_report_delete_sec)
        os.popen(f"rm -rf /tmp/scanner_test/{self.project_conf['project_id']}/*")


if __name__ == '__main__':
    scanner = Scanner()
    scanner.run()
