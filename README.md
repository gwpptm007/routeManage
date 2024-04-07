
<a name="yK3MU"></a>
## 功能介绍
实现IPv4/IPv6双栈路由的添加和删除，提供了两种方式实现共享库libzrouter.so以及可执行文件 zrouter
<a name="aS7VT"></a>
### 共享so库
以` libzrouter.so`，`wq_route.h`文件共享so形式提供接口调用，相比传统命令调用性能更好
<a name="CsBUx"></a>
### 进程zrouter
./zrouter -A -n 100 -d 172.16.50.165 -g 172.16.30.168 -m 255.255.255.255 -i eth0<br />./zrouter -A -n 1 -d 2001:db8::777 -g fe80::7 -m 64 -i eth1

<a name="PvsJQ"></a>
### 编译
```bash
[root@WQ]# ll
total 12
drwxr-xr-x 2 root root  153 Mar 27 11:41 inc
-rw-r--r-- 1 root root  798 Mar 27 09:46 Makefile
-rw-r--r-- 1 root root  229 Mar 21 10:51 Makefile.bk
-rw-r--r-- 1 root root 3014 Mar 21 13:57 routeManage.c
drwxr-xr-x 2 root root  163 Apr  7 16:26 src
[root@WQ]#
[root@WQ]# make
gcc -c src/zrouter.c -o src/zrouter.o -Wall -shared -fPIC -Iinc
gcc -c src/log.c -o src/log.o -Wall -shared -fPIC -Iinc
gcc -c src/util_net.c -o src/util_net.o -Wall -shared -fPIC -Iinc
gcc -c src/router.c -o src/router.o -Wall -shared -fPIC -Iinc
gcc -c src/ll_map.c -o src/ll_map.o -Wall -shared -fPIC -Iinc
gcc -o libzrouter.so src/zrouter.o src/log.o src/util_net.o src/router.o src/ll_map.o -Wall -shared -fPIC -Iinc
sudo setcap 'cap_net_admin+ep' libzrouter.so
gcc -o zrouter src/zrouter.o src/log.o src/util_net.o src/router.o src/ll_map.o -Wall -Iinc
sudo setcap 'cap_net_admin+ep' zrouter
[root@WQ]#
[root@WQ]# ll
total 164
drwxr-xr-x 2 root root   153 Mar 27 11:41 inc
-rwxr-xr-x 1 root root 78472 Apr  7 16:26 libzrouter.so
-rw-r--r-- 1 root root   798 Mar 27 09:46 Makefile
-rw-r--r-- 1 root root   229 Mar 21 10:51 Makefile.bk
-rw-r--r-- 1 root root  3014 Mar 21 13:57 routeManage.c
drwxr-xr-x 2 root root   243 Apr  7 16:26 src
-rwxr-xr-x 1 root root 70376 Apr  7 16:26 zrouter
```
<a name="a9HZB"></a>
## so接口
`**wq_route.h**`
```cpp
/******************************************************************
 *  @brief  : wq_route_add_ip4
 *            添加一条IPv4路由 
 *            sudo ip route add 172.16.40.117/32 via 172.16.40.254 dev eth1 table 123
 *            ip route show table 123         
 *  @param  :
 *      IN  : uip[4]                -- 目的ip，子网掩码固定32
 *            gip[4]                -- 网关ip(下一跳ip地址)
 *            ifname[16]            -- 网卡接口，最大16
 *            tabid                 -- 路由表名称 取值0-255
 *      OUT : NONE
 *  @return : SUCC     --   0
 *            FAILED   --  -1 
 *  @author : wangqi
 *  @time   : 2024/03/27
 ****************************************************************/
int wq_route_add_ip4(unsigned char uip[4], unsigned char gip[4], unsigned char ifname[IFNAMSIZ], int tabid);
```
```cpp
/******************************************************************
 *  @brief  : wq_route_add_ip6
 *            添加一条IPv6路由 
 *            sudo ip -6 route add 2001:db8::777/128 via fe80::1 dev eth1  table 125
 *            ip -6 route show table 125          
 *  @param  :
 *      IN  : uip[16]                -- 目的ip，子网掩码固定128
 *            gip[16]                -- 网关ip(下一跳ip地址)
 *            ifname[16]             -- 网卡接口，最大16
 *            tabid                  -- 路由表名称 取值0-255
 *      OUT : NONE
 *  @return : SUCC     --   0
 *            FAILED   --  -1 
 *  @author : wangqi
 *  @time   : 2024/03/27
 ****************************************************************/
int wq_route_add_ip6(unsigned char uip[16], unsigned char gip[16], unsigned char ifname[IFNAMSIZ], int tabid);
```
```cpp
/******************************************************************
 *  @brief  : wq_route_delete_ip4
 *            删除一条IPv4路由 
 *            sudo ip route del 172.16.40.117/32 via 172.16.40.254 dev eth1 table 123         
 *  @param  :
 *      IN  : uip[4]                -- 目的ip，子网掩码固定32
 *            gip[4]                -- 网关ip(下一跳ip地址)
 *            ifname[16]            -- 网卡接口，最大16
 *            tabid                 -- 路由表名称 取值0-255
 *      OUT : NONE
 *  @return : SUCC     --   0
 *            FAILED   --  -1 
 *  @author : wangqi
 *  @time   : 2024/03/27
 ****************************************************************/
int wq_route_delete_ip4(unsigned char uip[4], unsigned char gip[4], unsigned char ifname[IFNAMSIZ], int tabid);
```
```cpp
/******************************************************************
 *  @brief  : wq_route_delete_ip6
 *            删除一条IPv6路由 
 *            sudo ip -6 route del 2001:db8::777/128 via fe80::1 dev eth1  table 127          
 *  @param  :
 *      IN  : uip[16]                -- 目的ip，子网掩码固定128
 *            gip[16]                -- 网关ip(下一跳ip地址)
 *            ifname[16]             -- 网卡接口，最大16
 *            tabid                  -- 路由表名称 取值0-255
 *      OUT : NONE
 *  @return : SUCC     --   0
 *            FAILED   --  -1 
 *  @author : wangqi
 *  @time   : 2024/03/27
 ****************************************************************/
int wq_route_delete_ip6(unsigned char uip[16], unsigned char gip[16], unsigned char ifname[IFNAMSIZ], int tabid);
```

<a name="hM0O2"></a>
## so测试
测试代码引入`libzrouter.so`，`wq_route.h`文件
<a name="ITONV"></a>
### IPv4测试 routev4.c
```c
//gcc -o routev4 routev4.c -L. -lzrouter
//export LD_LIBRARY_PATH=$(pwd):$LD_LIBRARY_PATH

//sudo LD_LIBRARY_PATH=$(pwd):$LD_LIBRARY_PATH ./routev4 add
```

<a name="BkXVW"></a>
### IPv6测试 routev6.c
```c
//gcc -o routev6 routev6.c -L. -lzrouter
//export LD_LIBRARY_PATH=$(pwd):$LD_LIBRARY_PATH

//sudo LD_LIBRARY_PATH=$(pwd):$LD_LIBRARY_PATH ./routev6 add
```
<a name="R5RFF"></a>
## 进程zrouter测试
```bash
[root@WQ]# ./zrouter -help
        -A : run in ADD mode
        -R : run in RM mode
        -h : print version and this help
-----------------------------------------------IPv4---------------------------------------
        ./zrouter -A -n 100 -d 172.16.50.165 -g 172.16.30.168 -m 255.255.255.255 -i eth0
        ./zrouter -D -n 100 -d 172.16.50.165 -g 172.16.30.168 -m 255.255.255.255 -i eth0
-----------------------------------------------IPv6---------------------------------------
        ./zrouter -A -n 1 -d 2001:db8::777 -g fe80::7 -m 64 -i eth1
        ./zrouter -D -n 1 -d 2001:db8::777 -g fe80::7 -m 64 -i eth1
[root@testserver114 virtualIP_test]#
```
```bash
[root@WQ]# ./zrouter -A -n 1 -d 172.16.40.117 -g 172.16.40.254 -m 255.255.255.255 -i eth1


2023-08-08 19:19:06   zroute_init add route items:200000 success(cost time =1.980614 s)
2023-08-08 19:19:06   I'm off!
```

`./zrouter -A -n 1 -d 172.16.40.117 -g 172.16.40.254 -m 255.255.255.255 -i eth1`<br />`./zrouter -A -n 1 -d 2001:db8::777 -g fe80::7 -m 64 -i eth1`
> **-A  add路由        -D**   del路由

> **-n 1**   路由条数

> **-d 172.16.40.117**   目的ip，子网掩码固定IPv4: 32    IPv6: 128 可定制

> **-g  172.16.40.254**  网关ip(下一跳ip地址)

> **-m 255.255.255.255**     -m 64    子网掩码 

> **-i  eth0**     网卡

