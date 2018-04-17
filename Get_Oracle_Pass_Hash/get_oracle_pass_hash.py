# coding=utf-8

'''
# 数据库IP、端口、SID、用户名、密码，按以下格式写入oracle_user_list.txt文件中，使用Tab分隔。
Example：
192.168.123.203	1521	EE	SYSTEM	oracle
192.168.123.204	1521	EE	SYSTEM	oracle

# 结果文件内容使用追加模式写入，不会覆盖已有内容。

2018.4.17 v0.1 By Shad0wpf

'''

# 工具库导入
import pandas as pd
import cx_Oracle

# 注：设置环境编码方式，可解决读取数据库乱码问题
import os
os.environ['NLS_LANG'] = 'SIMPLIFIED CHINESE_CHINA.UTF8'

# Oracle数据库账号清单文件
oracle_user_list = "oracle_user_list.txt"

# 实现查询并返回dataframe


def oracle_query(host, port, sid, db_user, db_pass):
    try:
        host = host     # 数据库ip
        port = port     # 端口
        sid = sid       # 数据库名称
        dsn = cx_Oracle.makedsn(host, port, sid)
        conn = cx_Oracle.connect(db_user, db_pass, dsn)

        # SQL语句，可以定制，实现灵活查询
        # sql = sql_line
        get_hash = 'select a.username, b.password, a.account_status from dba_users a, sys.user$ b where a.username=b.name'
        get_version = 'select version from v$instance'

        # 使用pandas 的read_sql函数，可以直接将数据存放在dataframe中
        hash_result = pd.read_sql(get_hash, conn)
        version_result = pd.read_sql(get_version, conn)
        result = str(version_result) + '\n' + str(hash_result)

        conn.close
        print(host, '- Hash获取成功')
        return result
    except Exception as e:
        print(host, '- Hash获取失败', ':', e)
        return str(e)


# 从文件中读取Oracle用户
userfile = open(oracle_user_list, 'r')
userlists = userfile.readlines()
userfile.close()


for userline in userlists:
    userline2 = userline.replace('\n', '').split('\t')

    host = userline2[0]
    port = userline2[1]
    sid = userline2[2]
    db_user = userline2[3]
    db_pass = userline2[4]

    # 查询数据库
    oracle_hash = oracle_query(host, port, sid, db_user, db_pass)
    # 写入IP对应文件中
    filename = host + '_oracle_hash.txt'
    file1 = open(filename, 'w+')
    file1.write(str(oracle_hash))
    file1.close()
