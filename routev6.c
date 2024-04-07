#include <stdio.h>
#include <string.h>
#include "wq_route.h"


//gcc -o routeTest routeTest.c -L. -lzrouter -I/path/to/wq_route_header
//gcc -o routev6 routev6.c -L. -lzrouter
//export LD_LIBRARY_PATH=$(pwd):$LD_LIBRARY_PATH

//sudo LD_LIBRARY_PATH=$(pwd):$LD_LIBRARY_PATH ./routev6 add


int main(int argc, char *argv[]) {
	
	if (argc != 2) {
        printf("Usage: %s add|del\n", argv[0]);
        return 1;
    }
	
	//ip -6 route del 2001:d78::1234/128 via fe80::1 dev eth1
	
	//ip -6 route add 2001:d78::1234/128 via fe80::1 dev eth1
	
	
    //unsigned char uip[4] = {172, 16, 40, 107};  // 示例IPv4地址
    //unsigned char gip[4] = {172, 16, 40, 254};  // 示例网关IPv4地址
	
	unsigned char uip[16] = {0x20,0x01,0x0d,0x78,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x12,0x34};
	unsigned char gip[16] = {0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};

    unsigned char ifname[IFNAMSIZ] = "eth1";    // 示例接口名称
	int  tabid = 125;

    printf("正在添加路由...\n");
   // printf("IP: %d.%d.%d.%d\n", uip[0], uip[1], uip[2], uip[3]);
   // printf("网关: %d.%d.%d.%d\n", gip[0], gip[1], gip[2], gip[3]);
    printf("接口: %s\n", ifname);
	printf("路由表: %d\n", tabid);

	if (strcmp(argv[1], "add") == 0) {
        printf("Adding route...\n");
        //int result = wq_route_add_ip4(uip, gip, (unsigned char *)ifname);
		int result = wq_route_add_ip6(uip, gip, (unsigned char *)ifname, tabid);
        if (result == 0) {
            printf("Route added successfully.\n");
        } else {
            fprintf(stderr, "Failed to add route.\n");
        }
    } else if (strcmp(argv[1], "del") == 0) {
        printf("Deleting route...\n");
        //int result = wq_route_delete_ip4(uip, gip, (unsigned char *)ifname);
		int result = wq_route_delete_ip6(uip, gip, (unsigned char *)ifname, tabid);
        if (result == 0) {
            printf("Route deleted successfully.\n");
        } else {
            fprintf(stderr, "Failed to delete route.\n");
        }
    } else {
        fprintf(stderr, "Invalid command. Use 'add' or 'del'.\n");
        return 1;
    }

    return 0;
}