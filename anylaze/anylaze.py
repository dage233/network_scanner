import os
import json
from py2neo import Graph, Node, Relationship
report_dir = '/home/csustoj/project/neo4j_scan_test/docker_test/n1_tmp/scanner_test/abcdefg1234567890/data/report'
files = os.listdir(report_dir)

g = Graph('http://1.2.3.12:7474', auth=("neo4j", "passw0rd"), name="neo4j")
tx = g.begin()
# 删除数据库所有节点和关系
tx.run('match (n) detach delete n')

reports = []
for file in files: #遍历文件夹
    if os.path.isdir(file):
        continue #判断是否是文件夹，不是文件夹才打开
    with open(os.path.join(report_dir, file)) as f:
        report = json.load(f)
    reports.append(report)

nodes = {}
for report in reports:
    fingerprint = report['project']['this_fingerprint']
    node = Node('Node',name='N' + report['sys_info']['ips'][0].split('.')[-1], ips=report['sys_info']['ips'])
    nodes[fingerprint] = node
    tx.create(node)

for report in reports:
    fingerprint = report['project']['this_fingerprint']
    for ip in report['connect']:
        if 'ip_fingerprint' in report['connect'][ip]:
            connect = Relationship(nodes[fingerprint], "connect", nodes[report['connect'][ip]['ip_fingerprint']])
            tx.create(connect)

g.commit(tx)