#!/usr/bin/env python
# encoding: utf-8
# 2016.11.8 17:21 by drop 342737268(qq)


import re
import os
import sys
import csv
import time
import operator
import itertools

COMPAT = False
if '2.7' in sys.version:
    COMPAT = True

def install_pyexcel():
    path = os.environ.get('PATH')
    if sys.platform == 'linux':
        os.system('easy_install install pyexcel')
        os.system('easy_install install pyexcel_xlsx')
    elif sys.platform == 'win32':
        if re.search(r'[Pp]ython\d+\\[Ss]cripts', path):
            os.system('pip install pyexcel')
            os.system('pip install pyexcel_xlsx')
            return 0
        path = re.search(r'[CcDdEeFfGg]:\\.+?[Pp]ython\d+\\', path)
        if path:
            os.chdir(path.group() + 'Scripts')
            if not os.path.isfile('./pip.exe'):
                print('Please reinstall python!')
                return 0
            os.system('pip install pyexcel')
            os.system('pip install pyexcel_xlsx')
    return 1

try:
    import pyexcel
    import pyexcel_xlsx
except:
    install_pyexcel()
    import pyexcel
    import pyexcel_xlsx


class GetIPVuls(object):
    def __init__(self):
        assert len(sys.argv) >= 2, 'CommandError {}'.format(sys.argv)
        self.fn = sys.argv[1]
        assert os.path.isfile(self.fn), 'File not exist %s' %self.fn
        # filter highest version
        self.sheet1 = 'IP漏洞表'
        self.sheet2 = '漏洞分类表'
        self.sheet3 = '端口分类表'
        # raw_fmt = ("Plugin ID", "CVE", "CVSS", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Description", "Solution", "See Also", "Plugin Output")
        self.sheet1_fmt = ("Host", "Protocol", "Name", "Port", "Risk", "CVE", "Synopsis", "Description", "Solution", "See Also", "Plugin Output", "Plugin ID")
        self.sheet2_fmt = ("Name", "Host", "CVSS", "Risk", "CVE", "Protocol", "Synopsis", "Description", "Solution", "See Also", "Plugin Output", "Plugin ID")
        self.sheet3_fmt = ("Host", "Protocol", "Name", "Port", "Risk", "CVE", "Synopsis", "Description", "Solution", "See Also", "Plugin Output", "Plugin ID")
        if COMPAT:
            self.sheet1 = self.sheet1.decode('utf-8')
            self.sheet2 = self.sheet2.decode('utf-8')
            self.sheet3 = self.sheet3.decode('utf-8')
        self.patt = re.compile(r'(\d+\.\d+\.\d+\.\d+)|(\d+\.\d+\.\d+)|(\d+\.\d+)')
        self.data = []
        self.run()

    def run(self):
        csv_reader = csv.reader(open(self.fn), delimiter=',')
        heading = next(csv_reader)
        self.idx_risk = heading.index('Risk')
        self.idx_name = heading.index('Name')
        self.idx_plugin = heading.index('Plugin ID')
        self.idx_host = heading.index('Host')
        self.idx_port = heading.index('Port')
        self.idx_cvss = heading.index('CVSS')
        self.heading = heading
        self.filter_level(csv_reader)
        self.filter_pluginID()
        self.filter_upgrade()
        self.collect_ip()
        self.get_iptables()
        self.resort_column()
        self.build_xlsx()

    def filter_level(self, csv_reader):
        """ remove vulnerability of level with 'low' or 'None' """
        risk = {"Critical": "严重", "High": "高危", "Medium": "中危"}
        idx = self.idx_risk
        for i in csv_reader:
            if i[self.idx_risk] in ('Low', 'None'):
                continue
            if 'PCI' in i[self.idx_name]:
                continue
            i[idx] = risk[i[idx]]
            self.data.append(i)
        print('[stage1] remove level (low, None) vulnerability) finished!')

    def filter_pluginID(self):
        """ remove vulnerability of repeat with ('Plugin ID', 'Host', 'Name') """
        data = []
        idx, host, name = self.idx_plugin, self.idx_host, self.idx_name
        get_item = operator.itemgetter(idx, host, name)
        for k, g in itertools.groupby(self.data, key=get_item):
            data.append(next(g))
        self.data = data
        print("[stage2] remove vulnerability of repeat with ('Plugin ID', 'Host', 'Name')")

    def filter_upgrade(self):
        """
            remove resemble vulnerability with '<'
            eg: Apache Tomcat 7.0.x < 7.0.57 Multiple Vulnerabilities
            get: Apache Tomcat 7.0.57
        """
        # sort (host, name.split('<')[0], version) by descending
        self.data = sorted(self.data, key=self.sort_host_name_ver, reverse=True)
        data = []
        for k, g in itertools.groupby(self.data, key=self.group_host_port_name):
            data.append(next(g))
        self.data = {self.sheet1: data}
        print('[stage3] get best upgrade version ok! ')
        print('[stage3] Collected {} lines.'.format(len(data)))

    def sort_host_name_ver(self, line):
        """ sorted key function for filter_upgrade """
        host = line[self.idx_host]
        name = line[self.idx_name]
        lst = self.patt.findall(name)
        if not lst:
            return host + name
        # if line like "(ntpd) 4.x < 4.2.8p8 / 4.3.x < 4.3.93", you will get 4.3.93
        vers = [''.join(i) for i in lst if 'x' not in i]
        ver = sorted(vers)[-1]
        return host + re.split(r'\d\.', name)[0].strip() + ver

    def group_host_port_name(self, line):
            name = line[self.idx_name]
            host = line[self.idx_host]
            port = line[self.idx_port]
            return (host, port, re.split(r'\d\.', name)[0].strip())

    def collect_ip(self):
        idx, idx_name, idx_host = self.idx_cvss, self.idx_name, self.idx_host
        vuls = dict()
        for i in self.data[self.sheet1]:
            name = i[idx_name]
            if not vuls.get(i[idx_name]):
                vuls[name] = i[:]
                vuls[name][idx] = 1
                continue
            vuls[name][idx_host] += ', {}'.format(i[idx_host])
            vuls[name][idx] += 1
        self.data[self.sheet2] = []
        for k, i in vuls.items():
            self.data[self.sheet2].append(i)
        print('[state4] collect ip successful! Collected {} lines.'.format(len(vuls)))

    def get_iptables(self):
        result = []
        data = self.data[self.sheet1][:]
        data = sorted(data, key=self.sort_host_port_risk, reverse=True)
        host = self.idx_host
        port = self.idx_port
        for k, g in itertools.groupby(data, key=operator.itemgetter(host, port)):
            result.append(next(g))
        self.data[self.sheet3] = result
        print('[state5] get iptables successful!')

    def sort_host_port_risk(self, line):
        """sorted key function for get_iptables"""
        host = line[self.idx_host]
        port = line[self.idx_port]
        risk = line[self.idx_risk]
        risk_num = {"严重": '9', "高危": '6', "中危": '3'}
        return host + port + risk_num[risk]

    def resort_column(self):
        cn = {"Plugin ID": "Plugin ID", "CVE": "CVE", "CVSS": "IP计数", "Risk": "风险", "Host": "IP", "Protocol": "协议", "Port": "端口", "Name": "漏洞", "Synopsis": "摘要", "Description": "描述", "Solution": "解决方案", "See Also": "参考", "Plugin Output": "数据包"}
        self.data[self.sheet1] = self.sort_column(cn, self.sheet1_fmt, self.data[self.sheet1])
        self.data[self.sheet2] = self.sort_column(cn, self.sheet2_fmt, self.data[self.sheet2])
        self.data[self.sheet3] = self.sort_column(cn, self.sheet3_fmt, self.data[self.sheet3])
        print('[state6] resort column successful!')

    def sort_column(self, cn, fmt, data):
        raw = self.heading
        head = [cn[i] for i in fmt]
        idx = tuple([raw.index(i) for i in fmt])
        get_line = operator.itemgetter(*idx)
        sheet = [head]
        for i in data:
            sheet.append(get_line(i[:]))
        return sheet

    def build_xlsx(self):
        dest = self.fn.split('.csv')[0] + '.xlsx'
        pyexcel.save_book_as(bookdict=self.data, dest_file_name=dest)
        print('[state7] build file "{}" successful!'.format(dest))


if __name__ == '__main__':
    t0 = time.time()
    help = '[help] $python nessus_report.py filename.csv'
    if len(sys.argv) < 2:
        print(help)
        sys.exit()
    GetIPVuls()
    print('[ time ] used: {}s'.format(round(time.time() - t0, 2)))

