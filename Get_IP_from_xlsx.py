#!/usr/bin/env python
# encoding: utf-8
# pip install pyexcel
# pip install pyexcel_xlsx

import re
import os
import sys
from pyexcel_xlsx import get_data
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

try:
    import pyexcel
    from bs4 import BeautifulSoup
    from bs4 import NavigableString
except:
    modules = ['pyexcel', 'pyexcel_xlsx']
    install_module(modules)


def get_ip(fn):
    result = []
    data = get_data(fn)
    fn2 = fn.split('.xlsx')[0] + '.txt'
    for sheet in data:
        name = sheet
        if COMPAT:
            name = sheet.encode('utf-8')
        result.append('\n\n\n' + name + '\n')
        result.extend(strip_ip(str(data[sheet])))
    with open(fn2, 'w') as f:
        f.writelines(result)
    print('{} build!'.format(fn2))


def strip_ip(s):
    patt = r'(\d+\.\d+\.\d+\.\d+/\d+\s)|(\d+\.\d+\.\d+\.\d+)'
    ip_lst = [''.join(i) for i in re.findall(patt, s)]
    result = [i+'\n' for i in ip_lst]
    return result


if __name__ == '__main__':
    files = [i for i in os.listdir('.') if i.endswith('.xlsx') or i.endswith('.xls')]
    for fn in files:
        try:
            get_ip(fn)
        except:
            print('\n\tOops! I am already killed!' * 6)
