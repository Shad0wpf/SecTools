#!/usr/bin/env python3
# coding: utf-8
# 2016-07-13 23:55:13
'''
    read_data
        ipdb> p data
OrderedDict([('Sheet1', [['IP', 'OS', 'Port', 'Protocol', 'Service', 'Banner']])])
    对应excel
        --+---+-----+--------+------+----------+
        |IP | OS | PORT|    PROTO |  SERV |   Banner|
        --+---+-----+--------+------+----------+ 
        |__|_____|______|_________|______|____________|       
                            
    添加数据
        line = [_IP, OS, Port, Prototocol, Service, Banner]
        data.append(line)
'''


from libnmap.parser import NmapParser
from pyexcel_xlsx import read_data, save_data


def get_xml_info(filename):
    # get one line info for excel 
    # line = [ip, os_type, port, protocol, service, banner]
    rep = NmapParser.parse_fromfile(filename)
    print("{0}/{1} hosts up".format(rep.hosts_up, rep.hosts_total))
    count = 0
    for host in rep.hosts:
        if not host.is_up():
            continue
        count += 1
        print("{0}/{1} {2} {3}".format(count, rep.hosts_up, host.address,
            " ".join(host.hostnames)))
        ip = host.address
        os_type = ''
        if host.os.osmatch():
            os_type = host.os.osmatch()[0]
        for s in host.services:
            port = s.port
            protocol = s.protocol
            service = s.service
            banner = s.banner.replace('product: ', '')
            if os_type == 'Microsoft Windows XP SP2 or Windows Server 2003 SP1 or SP2':
                os_type = 'Windows: XP SP2 or Server2003 SP1/SP2'
            yield [ip, os_type, port, protocol, service, banner]


def gen_xlsx(xlsx_filename, xml_filename):
    try:
        #  data with format {'sheet1': [[line1], [line2]]}
        print('Reading data from xlsx....')
        data = read_data(xlsx_filename)
    except:
        raise ValueError('*.xlsx and program must be in same directory!')
    #  get first sheet name
    sheet_1 = list(data.keys())[0]
    first_line = ['IP', 'OS', 'Port', 'Protocol', 'Service', 'Banner']
    data[sheet_1][0] = first_line
    lines = get_xml_info(xml_filename)
    for i in lines:
        data[sheet_1].append(i)
    print('saving data to result.xlsx')
    try:
        save_data('result.xlsx', data)
    except:
        print('Close result.xlsx and try again!')

if __name__ == '__main__':
    import time
    t0 = time.time()
    gen_xlsx('port.xlsx', 'a.xml')
    print('used: {}s'.format(time.time() - t0))
