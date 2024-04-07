#include <stdio.h>
#include <string.h>
#include "router.h"
//#include "util_net.h"


/** execute 
    gcc -o routeManage routeManage.c -L$(pwd) -lzrouter -I./inc
    export LD_LIBRARY_PATH=$(pwd):$LD_LIBRARY_PATH

    sdpovertcp <command1>    <command2>
    command1 : ipv4   ipv6
    command2 : add    del
    ./routeManage   ipv4 (or) ipv6  add (or) del
*/
int main(int argc, char *argv[]) {

    if (argc != 3) {
        printf("Usage: %s [ipv4|ipv6] [add|del]\n", argv[0]);
        return 1;
    }

    route_entry_t entry;
    memset(&entry, 0, sizeof(route_entry_t)); // 初始化结构体
    
    // 示例中将路由信息设置为固定值，实际应用中应根据实际情况设置
    entry.enable = 1; // 启用
    strcpy(entry.ifname, "eth1"); // 使用网卡名称
    //对IPv6需要修改为合适的地址
    //strcpy(entry.dst, "172.16.40.117"); // 目标网络 
    strcpy(entry.dst, "2001:db8::1234"); // 目标网络 
    //对IPv6需要修改为合适的地址
    //strcpy(entry.netmask, "255.255.255.255"); // 子网掩码 
    strcpy(entry.netmask, "64"); // 子网掩码 
    //对IPv6需要修改为合适的地址
    //strcpy(entry.gateway, "172.16.40.254"); // 网关
    strcpy(entry.gateway, "fe80::7"); // 网关
    //对IPv6需要修改为合适的地址
    //entry.dst_len = 32; // 目的地子网掩码长度
    entry.dst_len = 64; // 目的地子网掩码长度


    int result = -1;
    if (strcmp(argv[1], "ipv4") == 0) 
    {
        if (strcmp(argv[2], "add") == 0) 
        {
            result = ipv4_route_add(&entry);

            /**调用添加路由的函数,另一种方法调用：ip_route_add_one
            struct rtnl_handle rth;
            memset(&rth, 0, sizeof(rth));
            if (rtnl_open(&rth) < 0)
            {
                printf("[ROUTE] Open netlink failed");
                return -1;
            }
            result = ip_route_add_one(&rth, &entry);
            */
        } else if (strcmp(argv[2], "del") == 0) 
        {
            result = ipv4_route_del(&entry);
        } else {
            printf("Invalid operation. Use 'add' or 'del'.\n");
            return 1;
        }

    } else if (strcmp(argv[1], "ipv6") == 0) {
        // 需要根据IPv6情况修改entry中的值
        // 例如：strcpy(entry.dst, "2001:0db8::1");
        // entry.dst_len = 64;
        if (strcmp(argv[2], "add") == 0) {
            result = ipv6_route_add(&entry);
        } else if (strcmp(argv[2], "del") == 0) {
            result = ipv6_route_del(&entry);
        } else {
            printf("Invalid operation. Use 'add' or 'del'.\n");
            return 1;
        }
    } else {
        printf("Invalid IP type. Use 'ipv4' or 'ipv6'.\n");
        return 1;
    }

    if (result == 0) {
        printf("Route %s successfully.\n", argv[2]);
    } else {
        printf("Failed to %s route.\n", argv[2]);
    }

    return 0;
}





