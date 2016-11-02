# -*- coding: utf-8 -*-
# !/usr/bin/python
'''
1.需安装paramiko模块 
pip install paramiko
2.账号密码放在同目录list.txt中，格式如下：
user:pass:10.10.10
'''
import paramiko
from multiprocessing.dummy import Pool, Lock

lock = Lock()

out_file = 'log.txt'
print("create outfile:"+out_file)

def log(result):
    # e.g :192.168.1.85:[u'/tmp/gates.lod']
    # found /tmp/gates.lod on server 192.168.1.1
    ip, result = result
    lock.acquire()
    with open(out_file, 'a') as out:
        out.write(ip+':'+str(result)+'\n')
    lock.release()


def ssh2(ip, username, passwd,  cmd):
    results = []
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, 22, username, passwd, timeout=5)
		

        # executing command
        for m in cmd:
            stdin, stdout, stderr = ssh.exec_command(m)
            out = stdout.readlines()
            for o in out:
                results.append(o.strip())
        ssh.close()


    except Exception, e:
        results.append(str(e))

    finally:
        return ip, results


if __name__ == '__main__':
    commands = [
        'find /tmp -name gates.lod',
        'find /tmp -name moni.lod',
        'find /tmp -name conf.n',
        'find /tmp -name 25000',
        'find /tmp -name SYSTEM',
        'find /usr/bin/ -name getty',
        'find /usr/bin/ -name getty.lock',
        'find /usr/bin -name .sshd',
        'find /etc/init.d/ -name DbSecuritySpt',
		'find /etc/rc.d/init.d/ -name DbSecuritySpt',
        'find /lib -name libgcc4.so',
        'find /lib -name libkill.so',
    ]
    pool = Pool(50)
    # read server info from list.txt
    # Format: user:pwd:server
    for line in open('list.txt'):
        line = line.strip()
        user, pwd, server = line.split(':')
        pool.apply_async(
            ssh2,
            (server, user, pwd,  commands),
            callback=log
        )
    pool.close()
    pool.join()

print "outfile out:"+out_file


