#!/usr/bin/env python3
# coding: utf-8
# 2016-10-19 14:17:16

import re
import os
import sys
import time

COMPAT = False
if '2.7' in sys.version:
    COMPAT = True


def get_module(modules):
    """:modules: list, install module list"""
    for i in modules:
        os.system('pip install {}'.format(i))
    print('\n\t**Decpendencies may be ok, please run me again!**')
    sys.exit()


def install_module(modules):
    path = os.environ.get('PATH').split(';')
    patt_path = re.compile(r'([Pp]ython(\d+)?\\[Ss]cripts)|([A-Za-z]:\\.*[Pp]ython(\d+)?\\?)')
    if sys.platform == 'linux':
        os.system('easy_install pip')
    elif sys.platform == 'win32':
        path_py = [i for i in path if patt_path.search(i)]
        if (len(path_py) == 1) or ('scripts' not in ';'.join(path_py).lower()):
            os.chdir(os.path.join(path_py.group(), 'Scripts'))
            if not os.path.isfile('./pip.exe'):
                print('Please reinstall python!')
                return 0
    get_module(modules)

try:
    import pyexcel
except:
    modules = ['pyexcel', 'pyexcel_xlsx']
    install_module(modules)


def get_port(file):
    # @file: file handler, file = open(fn)
    port_patt = r'<td class="vul_port">(\d+)</td>'
    for line in file:
        port = re.findall(port_patt, line)
        if not port:
            continue
        return port[0]

def get_proto_serv(file):
    # get proto/service
    proto_patt = r'<td>(.*)</td>'
    for line in file:
        proto = re.findall(proto_patt, line)
        if not proto:
            continue
        return proto[0]

def get_vul(file):
    sub_str = 'level_danger_'
    vul_patt = r'>(.+)<'
    level_patt = r'class="(.+?)"'
    for line in file:
        if sub_str not in line:
            continue
        vul = re.findall(vul_patt, line)[0]
        level = re.findall(level_patt, line)[0]
        return (level, vul)


def get_lines(fn, ip):
    # @fn: str, filename
    lines = []
    risk = {'level_danger_high': '高危', 'level_danger_middle': '中危'}
    file = open(fn, encoding='utf-8')
    for line in file:
        port = get_port(file)
        proto = get_proto_serv(file)
        serv = get_proto_serv(file)
        res= get_vul(file)
        if res == None:
            break
        level, vul = res
        if level == 'level_danger_low':
            continue
        lines.append([ip, port, proto, serv, risk[level], vul])
    return lines

def traverse_dir(curent_dir='.'):
    dirs = os.listdir(curent_dir)
    dirs = [i for i in dirs if i.endswith('.html')]
    lines = []
    patt = re.compile(r'\d+\.\d+\.\d+\.\d+')
    i = 0
    length = len(dirs)
    for fn in dirs:
        ip = patt.findall(fn)
        if not ip:
            continue
        ip = ip[0]
        fn = os.path.join(curent_dir, fn)
        lines.extend(get_lines(fn, ip))
        i += 1
        print('{}/{}\t{}'.format(i, length, ip))
    print('End!')
    return lines

def get_xlsx(curent_dir):
    wdata = []
    wdata.append(['IP', '端口', '协议', '服务', '风险', '漏洞'])
    wdata.extend(traverse_dir(curent_dir))
    wfile = 'iptables@{}.xlsx'.format(int(time.time()))
    try:
        pyexcel.save_as(array=wdata, dest_file_name=wfile)
    except:
        print('Build xlsx error!')
        return False
    print('Successful output file: {}'.format(wfile))


if __name__ == '__main__':
    try:
        get_xlsx(r'./host')
    except:
        print('\n\tOops! I am already killed!' * 10)
