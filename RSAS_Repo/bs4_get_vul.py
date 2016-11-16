#!/usr/bin/env python
# encoding: utf-8
"""
2016.11.03 15:21:46-11.10 21:11  with Beautiful Soup4
    by drop 342737268(QQ)
"""
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
    from bs4 import BeautifulSoup
    from bs4 import NavigableString
except:
    modules = ['beautifulsoup4', 'pyexcel', 'pyexcel_xlsx', 'lxml']
    install_module(modules)

PATTERN = re.compile(r'(<span\s+class="level_danger_high") |(<span\s+class="level_danger_middle")')


class GetVulOfNsfocus(object):
    '''get vulnerability infomation of HTML report export by nsfocus scanner'''
    def __init__(self, xlsx_name='nsfocus_scan_report.xlsx', sheet='IP漏洞表'):
        self.hosts = [i for i in os.listdir('./host') if i.endswith('.html')]
        heading = ['IP地址', '漏洞分级', 'CVE编号', '漏洞', '端口',
                   '协议', '服务', '操作系统', '详细描述', '解决办法', ]
        self.array = [heading]
        self.sheet = sheet
        self.xlsx_name = xlsx_name
        self.run()

    def run(self):
        count = 0
        t0 = time.time()
        a = len(self.hosts)
        tmp = '{:%s}/{}  ' % (len(str(a)))
        string = tmp + '{:16} count: {:3}\tlines: {} \telapsed: {:3}s'
        all_count = 0
        for host in self.hosts:
            # if host == '10.113.4.182.html':
            #    ipdb.set_trace()
            vul_count = self.get_vul('./host/' + host)
            count += 1
            all_count += vul_count
            print(string.format(count, a, host[:-5], vul_count,
                                all_count, int(time.time() - t0)))
        self.get_xlsx()

    def get_vul(self, host):
        '''get excel lines of target host'''
        if COMPAT:
            html = open(host).read().decode('utf-8')
        else:
            html = open(host, encoding='utf-8').read()
        if not PATTERN.search(html):
            return 0    # optimize speed 26%
        host_soup = BeautifulSoup(html, 'lxml')
        # ['IP地址', '操作系统']
        host_summary = self.get_summary(host_soup)
        # {name_port: ['name', '端口', '协议', '服务', '漏洞', '漏洞分级']}
        vul_summary = self.get_vul_summary(host_soup)
        # dic[name_port].extend(['详细描述', '解决办法', 'CVE编号'])
        detail = self.get_detail(host_soup, vul_summary)
        self.combine_result(host_summary, detail)
        return len(detail)

    def combine_result(self, host_summary, detail):
        for name_port in detail:
            line = []
            line.extend(host_summary)
            line.extend(detail[name_port])
            if len(line) != 10:
                print(line)
                raise ValueError
            ip, osx, vul, port, proto, serv, level, descri, solu, cve = line
            line = [ip, level, cve, vul, port, proto, serv, osx, descri, solu]
            self.array.append(line)

    def get_summary(self, host_soup):
        ''' host report -> section 1: host summary, return list '''
        result = []
        condition = (u'IP地址', u'操作系统')
        p = host_soup.find('tr', class_='even').parent
        for i in p.contents:
            if type(i) is NavigableString:
                continue
            elif i.th.string in condition:
                result.append(i.td.string)
        if len(result) < 2:
            result.append(None)
        return result

    def get_vul_summary(self, host_soup):
        ''' host report -> section 2.1: vulnerability summary, return dict '''
        result = dict()
        p = host_soup.find('div', id='title2_1')
        if not p:   # security host have no title2_1
            return False
        trs = p.parent.table.tbody.find_all('tr')
        for tr in trs:
            result = self.get_vul_port_proto_serv(tr, result)
        return result

    def get_vul_port_proto_serv(self, tr, result):
        level = {'level_danger_high': '高危', 'level_danger_middle': '中危',
                 'level_danger_low': '低危'}
        port, proto, service = [i.string for i in tr.find_all('td')[0: 3]]
        for tag in tr.find_all('span'):
            cls, name = (tag['class'][0], tag.string)
            if cls == 'level_danger_low':
                continue
            result[name+port] = [name, port, proto, service, level[cls]]
        return result

    def get_detail(self, host_soup, vul_summary):
        ''' host report -> section 2.2: vulnerability detail, return dict '''
        name_detail_lst = host_soup.find('div', id='vul_detail').table.contents
        same_vuls = []
        for i in name_detail_lst:
            if type(i) is NavigableString:
                continue
            if i.span:
                name = i.span.string
                for name_port in vul_summary:
                    if name in name_port:
                        same_vuls.append(name_port)
            elif same_vuls:
                # in case of repeat vulnerability but differ port
                lst_solu = self.get_solution(i)
                for name_port in same_vuls:
                    lst = vul_summary.get(name_port)
                    if lst and (len(lst) == 5):
                        vul_summary[name_port].extend(lst_solu)
                same_vuls = []
        return vul_summary

    def get_solution(self, tag):
        '''['详细描述', '解决办法', 'CVE编号'] '''
        value = []
        tr_lst = tag.table.contents
        for i in tr_lst:
            if type(i) is NavigableString:
                continue
            if i.th.string in (u'详细描述', u'解决办法'):
                val = [i.strip() for i in i.td.strings]
                val = '\n'.join(val).replace('\n*', '*')
                value.append(val)
            elif i.th.string == u'CVE编号':
                value.append(i.td.string)
        if len(value) == 2:
            value.append(None)
        return value

    def get_xlsx(self):
        try:
            pyexcel.save_as(array=self.array,
                            dest_file_name=self.xlsx_name,
                            dest_sheet_name=self.sheet)
        except KeyboardInterrupt as e:
            print(str(e))
            return False
        print('Successful output file: {}'.format(self.xlsx_name))


if __name__ == '__main__':
    t0 = time.time()
    try:
        GetVulOfNsfocus()
        print('time used:\t{}s'.format(round(time.time() - t0, 2)))
    except:
        print('\n\tOops! I am already killed!' * 6)
