#!/usr/bin/env python
# coding: utf-8

import re
import os
import sys
import time
import ctypes
import configparser
from subprocess import Popen
from collections import OrderedDict


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


error = ''
try:
    import win32api
    import win32con
    import wmi
except:
    modules = ['wmi']
    install_module(modules)
    error = '请手动安装 pywin32.exe'


COMPAT = False
if '2.7' in sys.version:  # python2.7
    COMPAT = True
    input = raw_input
    error = error.decode('utf-8').encode('cp936')
if error:
    print(error)
    input()


class NetConfig(object):
    def __init__(self, fn='c:/ipconfig.ini'):
        self.ip_patt = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        self.proxy_patt = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*:\s*\d+')
        self.interface = self.get_interface()
        self.fn = fn
        if not os.path.isfile(fn):
            self.build_config(fn)
        self.config = self.parse_config(fn)
        self.run()

    def build_config(self, fn):
        config = configparser.ConfigParser()
        config['default_ip'] = OrderedDict([('ip', '192.168.1.100'),
                                         ('netmask', '255.255.255.0'),
                                         ('gateway', '192.168.1.1'),
                                         ('dns1', '8.8.8.8'),
                                         ('dns2', '114.114.114.114')])
        config['burpsuite'] = {'proxy': '127.0.0.1:8080'}
        with open(fn, 'w') as f:
            config.write(f)
        print('Please finish config file!')
        time.sleep(2)
        os.popen(fn)

    def parse_config(self, fn):
        cfg = configparser.ConfigParser(strict=True)
        cfg.read_string(open(fn).read())
        for k in cfg:
            if 'ip' in cfg[k]:
                self.check_static_ip(cfg[k])
            elif 'proxy' in cfg[k]:
                if not self.proxy_patt.search(cfg[k]['proxy']):
                    print('ConfigError: {}'.format(cfg[k]))
                    os.popen(fn)
                    sys.exit(1)
        return cfg

    def check_static_ip(self, section):
        lst = ['ip', 'netmask', 'gateway']
        for k in lst:
            if not self.ip_patt.search(section[k]):
                print('ConfigError: {}'.format(section))
                os.popen(self.fn)
                sys.exit(1)

    def get_interface(self):
        s = os.popen('ipconfig').read().split('\n')
        s = [i for i in s if i.startswith('以太网适配器') and 'VM' not in i][0]
        s = s.replace(':', '').split()[1]
        return s

    def run(self):
        menu = '''\
****************************by_dr0p******************************
[e] 编辑 IP 配置文件
[d] 启用DHCP 并更新IP(管理员权限)
[i] 选择静态IP(python需管理员权限)
[t] 定时关机（秒，可用表达式 8*3600）
[c] 取消定时关机
[k] 启用默认静态IP
[n] nslookup 检测上网状态
[b] 启用默认代理（burpsuite 127.0.0.1:8080）
[u] 选择代理配置 (配置文件中更改)
[r] 关闭代理(代理配置会自动关闭 IE)
[p] ping 网关
[s] IP 配置状态
[z] 退出  [w] 重置IP 配置文件
Input > '''
        if COMPAT:
            menu = menu.decode('utf-8').encode('cp936')
        done = False
        funcs = {'e': self.edit,
                 'd': self.dhcp,
                 'i': self.select_ip,
                 't': self.shutdown,
                 'c': self.shutdown_cancel,
                 'k': self.set_defult_ip,
                 'n': self.check_dns,
                 'b': self.set_defult_proxy,
                 'u': self.select_proxy,
                 'r': self.disable_proxy,
                 'p': self.ping_gateway,
                 's': self.ipconfig,
                 'z': self.exit,
                 'w': self.reset_conf
                 }
        while not done:
            try:
                option = input(menu).strip().lower()
                if not option:
                    continue
                option = option[0]
                assert option in funcs
                funcs[option]()
            except (KeyError, KeyboardInterrupt):
                print('Input error, try again!')

    def edit(self):
        if not os.path.isfile(self.fn):
            self.reset_conf()
        os.popen('notepad {}'.format(self.fn))

    def dhcp(self):
        iface = self.interface
        os.system('netsh interface ip set address "{}" dhcp'.format(iface))
        os.system('netsh interface ip set dns "{}" dhcp'.format(iface))
        os.system('ipconfig /release')
        os.system('ipconfig /renew')

    def select_ip(self):
        c = self.config
        fmt = '{}) [{}]  ip {}  mask {}  gateway {}  dns1 {}  dns2 {}'
        k_lst = []
        for k in c:
            if 'ip' not in c[k]:
                continue
            k_lst.append(k)
            print(fmt.format(len(k_lst), k, c[k]['ip'], c[k]['gateway'],
                             c[k]['netmask'], c[k]['dns1'], c[k]['dns2']))
        while k_lst:
            option = input('Input num > ').strip()[0].lower()
            if option == 'z':
                return 0
            try:
                option = int(option) - 1
            except:
                print('ValueError: input again!')
            if option in range(len(k_lst)):
                break
            print('ValueError: input again!')
        self.set_ip(c[k_lst[option]])

    def set_ip(self, section):
        iface = self.interface
        ip, netmask = section['ip'], section['netmask']
        gateway, dns1, dns2 = section['gateway'], section['dns1'], section['dns2']
        error = os.system('netsh interface ip set address "{}" static {} {} {}\
                          '.format(iface, ip, netmask, gateway))
        if dns1:
            error = os.system('netsh interface ip set dns "{}" static {} primary\
                              '.format(iface, dns1))
        if dns2:
            error = os.system('netsh interface ip set dns "{}" static {} primary\
                              '.format(iface, dns2))
        if error:
            print("Plese check python.exe's permission!\n")

    def shutdown(self):
        prompt = '''您希望多少秒后关机 ？  '''
        if COMPAT:
            prompt = prompt.decode('utf-8').encode('cp936')
        try:
            sec = eval(input(prompt))
            os.system('shutdown /s /t %s' % sec)
        except:
            print('Input Error! Try again!')

    def shutdown_cancel(self):
        os.system('shutdown /a')

    def set_defult_ip(self):
        self.set_ip(self.config['default'])

    def check_dns(self):
        os.system('nslookup mail.silence.com.cn')

    def set_defult_proxy(self):
        self.proxy()

    def proxy(self, ip_port='127.0.0.1:8080', enable=True):
        self.kill_ie()
        if enable:
            self.changeIEProxy('ProxyServer', ip_port)
            self.changeIEProxy('ProxyEnable', '1')
        else:
            self.changeIEProxy('ProxyEnable', 0, enable=False)
        Popen(r'C:\Program Files\Internet Explorer\iexplore.exe')
        print('Proxy setting finished!')

    def kill_ie(self):
        c = wmi.WMI()
        kernel32 = ctypes.windll.kernel32
        for process in c.Win32_Process():
            if process.Name == 'iexplore.exe':
                kernel32.TerminateProcess(
                    kernel32.OpenProcess(1, 0, process.ProcessId), 0)

    def changeIEProxy(self, keyName, keyValue, enable=True):
        pathInReg = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, pathInReg, 0, win32con.KEY_ALL_ACCESS)
        if enable:
            win32api.RegSetValueEx(key, keyName, 0, win32con.REG_SZ, keyValue)
        else:
            win32api.RegSetValueEx(key, keyName, 0, win32con.REG_DWORD, keyValue)

    def select_proxy(self):
        lst = []
        c = self.config
        for i in c:
            if 'proxy' not in c[i]:
                continue
            lst.append(lst)
            print('{}) [{}] {}'.format(len(lst), i, c[i]['proxy']))
        while True:
            option = input('Input num > ').strip()[0].lower()
            if option == 'z':
                return 0
            try:
                option = int(option)
            except:
                print('Input error! Try again!')
            if option in range(len(lst)):
                break
            print('Input error! Try again!')
        if lst:
            self.proxy(c[lst[option]])

    def disable_proxy(self):
        self.proxy(enable=False)

    def ping_gateway(self):
        s = os.popen('ipconfig').read().split('以太网适配器')
        s = [i for i in s if ('WLAN' not in i) and ('VM' not in i)][0]
        s = s.split('默认网关')[1]
        gateway = self.ip_patt.findall(s)[0]
        try:
            os.system('ping -t {}'.format(gateway))
        except:
            return 0

    def ipconfig(self):
        os.system('ipconfig')

    def exit(self):
        sys.exit()

    def reset_conf(self):
        self.build_config(self.fn)

if __name__ == '__main__':
    NetConfig()
