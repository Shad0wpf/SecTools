#!/usr/bin/env python
# coding: utf-8
# code for version 2.7.11 / 3.x win7/ xp/win8
# 2016-03-25 01:25:43

import re
import os
import sys
import ctypes
import platform
from subprocess import Popen, PIPE
# import configparser

import warnings

warnings.simplefilter("ignore")
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

error = ''
try:
    import win32api
    import win32con
    import wmi
except:
    modules = ['wmi']
    install_module(modules)
    print('请手动安装 pywin32.exe')

INTERFACE = '以太网'  # win10, win8
try:
    v = platform.uname().release
    if v not in ('10', '8.1', '8'):
        INTERFACE = '本地连接'
except:  # py2.7
    v = platform.uname()[2]
    if v not in ('10', '8.1', '8'):
        INTERFACE = '本地连接'

if '2.7' in sys.version:  # python2.7
    input = raw_input
    INTERFACE = INTERFACE .decode('utf-8').encode('cp936')
    error = error.decode('utf-8').encode('cp936')
if error:
    print(error)
    input()


def check_ip(groups, infile):
    ''' check ip and return ip_groups
    @groups: ['ip_group0', 'ip_group1', ..., 'proxy0', 'proxy1',...]
    @infile: str, config file name
    @RTN: ['ip_group0', 'ip_group1', ....]
    '''
    assert type(groups) == list
    assert type(infile) == str
    ip_groups = [grp for grp in groups if '=' in grp]
    for grp in ip_groups:
        group = grp.split('\n')
        error = ''
        if len(group) not in (4, 5, 6):
            error = 'Lack parameters in "{}" ip group "{}"'.format(infile, group[0])
            print(error)
            return False
        elif ']' not in group[0] or '[' not in group[0]:
            error = 'Check "[ip_name]" in "{}" ip group "{}"'.format(infile, group[0])
        elif 'ip' not in grp:
            error = 'Check "ip" in "{}" ip group "{}"'.format(infile, group[0])
        elif 'netmask' not in grp:
            error = 'Check "netmask" in "{}" ip group "{}"'.format(infile, group[0])
        elif 'gateway' not in grp:
            error = 'Check "gateway" in "{}" ip group "{}"'.format(infile, group[0])
        if error:
            print(error)
            return False
    return ip_groups


def check_proxy(groups, infile):
    ''' check ip and return ip_groups
    @groups: ['ip_group0', 'ip_group1', ..., 'proxy0', 'proxy1',...]
    @infile: str, config file name
    @RTN: ['pxy_group0', 'pxy_group1', ....]
    '''
    assert type(groups) == list
    assert type(infile) == str
    pxy_groups = [grp for grp in groups if '=' not in grp]
    for grp in pxy_groups:
        group = grp.split('\n')
        error = ''
        if len(group) != 2:
            error = 'Lack parameters in "{}" proxy "{}"'.format(infile, group[0])
            print(error)
            return False
        elif not re.findall(r'\d+\.\d+\.\d+\.\d+\s*:\s*\d+', group[1]):
            error = 'Proxy config error, format like "127.0.0.1:8080"'
        elif not group[1].replace('.', '').replace(' ', '').replace(':', '').isdigit():
            error = 'Proxy config error, "ip:port" cannot cotain letter!'
        if error:
            print(error + '\nCheck {} proxy "{}"" "{}"'.format(infile, group[0], group[1]))
            return False
    return pxy_groups


def check_config(infile):
    '''check  config file and return [lst_ip_groups, lst_pxy_groups]'''
    assert type(infile) == str
    string = ''.join([i for i in open(infile).readlines()
                      if i.strip() and not i.strip().startswith('#')])
    groups = [i.strip() for i in string.split('[end]') if i.strip()]
    ip_groups = check_ip(groups, infile)
    pxy_groups = check_proxy(groups, infile)
    if not ip_groups or not pxy_groups:
        return [False, False]
    return [ip_groups, pxy_groups]


def parse_para(groups):
    assert type(groups) == list
    for i in range(len(groups)):
        groups[i] = '[{}] '.format(i) + groups[i].replace('[', '').replace(']', '')
    if '=' not in groups[0]:
        return dict([i.split('\n') for i in groups])
    dicX = {}
    for grp in groups:
        lst = grp.split('\n')
        lst0 = []
        for para in lst[1:]:
            lst0.append([i.strip() for i in para.split('=')])
        dicX[lst[0]] = dict(lst0)
    return dicX


def parse_config(infile):
    """ parse ip config file
    @infile: str, file of name
    @retn[0]: dict, {'ip0':{'ip': 'xxx',  'netmask': 'xxx', 'gateway': 'xxx',
            'dns0': 'xxx', 'dns1': 'xxx'}, 'ip1': {...}, configC: {...}, ...}
    @retn[1]: list, ['group_ip0', group_ip1'...] for print
    @retn[2]: dict, {'proxy0':'ip: port', 'proxy1':'ip: port',...}
    @retn[3]: list, ['proxy0', 'proxy1', ...] for print
    """
    assert type(infile) == str
    try:
        ip_groups, pxy_groups = check_config(infile)
    except IOError:
        print('IOError: config file not exist! ')
        sys.exit()
    if not ip_groups or not pxy_groups:
        return [False, False, False, False]
    return [parse_para(ip_groups), ip_groups, parse_para(pxy_groups), pxy_groups]


def set_ip(dic_config, group):
    ''' set static ip with group in ipconfig file
    @dic_config: dict, get from parse_config()
    @group: str, user choosed ip group setting
    '''
    assert type(dic_config) == dict and dic_config
    assert type(group) == str and group
    global INTERFACE
    d = dic_config[group]
    error = os.system('netsh interface ip set address "{}" static {} {} {}'
                      .format(INTERFACE, d['ip'], d['netmask'], d['gateway']))
    if d['dns1']:
        error = os.system('netsh interface ip set dns "{}" static {} primary'.format(INTERFACE, d['dns1']))
    if d['dns2']:
        error = os.system('netsh interface ip set dns "{}" static {} primary'.format(INTERFACE, d['dns2']))
    if error:
        print("Plese check python.exe's permission!\n")


def show_ip():
    os.system('ipconfig')


def edit(infile):
    if not os.path.isfile(infile):
        reset_conf(infile)
    os.popen('notepad {}'.format(infile))


def reset_conf(infile):
    s0 = '#' + '-' * 10 + 'static_ip_config' + '-' * 10 + '\n'
    s1 = ['[default]\n', 'ip=\n', 'netmask=\n', 'gateway=\n', 'dns1=\n', 'dns2=\n', '[end]\n\n']
    s2 = ['[home]\n', 'ip=\n', 'netmask=\n', 'gateway=\n', 'dns1=\n', 'dns2=\n', '[end]\n\n']
    s3 = '#' + '-' * 10 + 'proxy_config' + '-' * 10 + '\n'
    s4 = ['[burpsuite]\n', '127.0.0.1:8080\n', '[end]\n\n', '[charles]\n', '127.0.0.1:9090\n', '[end]\n\n']
    with open(infile, 'w') as f:
        f.write(s0)
        f.writelines(s1)
        f.writelines(s2)
        f.write(s3)
        f.writelines(s4)


def dhcp():
    global INTERFACE
    os.system('netsh interface ip set address "{}" dhcp'.format(INTERFACE))
    os.system('netsh interface ip set dns "{}" dhcp'.format(INTERFACE))
    os.system('ipconfig /release')
    os.system('ipconfig /renew')


def choose(infile, beProxy=False):
    s = parse_config(infile)
    if beProxy:
        s = s[2:]
        print('choose a proxy from follows:\n')
    else:
        s = s[0: 2]
        print('choose a static IP as your setting: \n')
    for grp in s[1]:
        print(grp+'\n')
    try:
        sub_opt = int(input('Input Num > ').strip())
    except:
        print('Input wrong, try again!')
        return False
    if sub_opt not in range(len(s[1])):
        return False
    if beProxy:
        idx = s[1][sub_opt].split('\n')[0]
        proxy(s[0][idx])
    else:
        set_ip(s[0], s[1][sub_opt].split('\n')[0])
    print('{}'.format(s[1][sub_opt]))
    return True


def shutdown(cancel=False):
    prompt = '''您希望多少秒后关机 ？  '''
    if '2.7' in sys.version:
        prompt = prompt.decode('utf-8').encode('cp936')
    if cancel:
        os.system('shutdown /a')
        return 0
    try:
        sec = eval(input(prompt))
        os.system('shutdown /s /t %s' % sec)
    except Exception as e:
        print(str(e))


def ping(ip):
    try:
        os.system('ping -t {}'.format(ip))
    except KeyboardInterrupt:
        return True
    except:
        return False


def kill_ie():
    c = wmi.WMI()
    kernel32 = ctypes.windll.kernel32
    for process in c.Win32_Process():
        if process.Name == 'iexplore.exe':
            kernel32.TerminateProcess(kernel32.OpenProcess(1, 0, process.ProcessId), 0)


def changeIEProxy(keyName, keyValue, enable=True):
    pathInReg = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, pathInReg, 0, win32con.KEY_ALL_ACCESS)
    if enable:
        win32api.RegSetValueEx(key, keyName, 0, win32con.REG_SZ, keyValue)
    else:
        win32api.RegSetValueEx(key, keyName, 0, win32con.REG_DWORD, keyValue)
    win32api.RegCloseKey(key)


def proxy(ip_port='127.0.0.1:8080', enable=True):
    kill_ie()
    if enable:
        changeIEProxy('ProxyServer', ip_port)
        changeIEProxy('ProxyEnable', '1')
    else:
        changeIEProxy('ProxyEnable', 0, enable=False)
    Popen(r'C:\Program Files\Internet Explorer\iexplore.exe')
    print('Proxy setting finished!')


def show_menu(infile):
    menu0 = '''\
****************************by_dr0p******************************
[e] 编辑 IP 配置文件
[d] 启用DHCP 并更新IP(管理员权限)
[i] 选择静态IP(python需管理员权限)
[t] 定时关机（秒，可用表达式 8*3600）
[c] 取消定时关机
[k] 启用默认静态IP
[n] 公司IP查询 当前网段查询
[b] 启用默认代理（burpsuite 127.0.0.1:8080）
[u] 选择代理配置 (配置文件中更改)
[r] 关闭代理(代理配置会自动关闭 IE)
[p] ping -t
[s] IP 配置状态
[z] 退出  [w] 重置IP 配置文件
choice: '''.format(infile)
    if '2.7' in sys.version:
        menu0 = menu0.decode('utf-8').encode('cp936')
    done = False
    while not done:
        try:
            opt = input(menu0).strip().lower()[0]
        except:
            print('Input error, try again!')
            continue
        print('*' * 66)
        if opt not in 'editcknburpszw':
            print('Input wrong, try again!')
            continue
        elif opt == 'e':
            edit(infile)
        elif opt == 'd':
            dhcp()
        elif opt == 'i':
            if not choose(infile):
                print('Error choice, try again!')
                continue
        elif opt == 't':
            shutdown()
        elif opt == 'c':
            shutdown(cancel=True)
        elif opt == 'k':
            s = parse_config(infile)[0: 2]
            set_ip(s[0], s[1][0].split('\n')[0])
            print('{}'.format(s[1][0]))
        elif opt == 'n':
            try:
                os.system('nslookup mail.silence.com.cn')
            except:
                pass
        elif opt == 'b':
            proxy()
        elif opt == 'u':
            ip_port = choose(infile, beProxy=True)
            if not ip_port:
                print('ProxyError: check your proxy address!')
                continue
        elif opt == 'r':
            proxy(enable=False)
        elif opt == 'p':
            ip = input('ping ')
            if not ping(ip):
                print('Input error, try again!')
        elif opt == 's':
            show_ip()
        elif opt == 'z':
            sys.exit()
        elif opt == 'w':
            reset_conf(infile)
            os.popen('notepad {}'.format(infile))


if __name__ == '__main__':
    infile = r'c:\ip_proxy.ini'
    show_menu(infile)
    input()
