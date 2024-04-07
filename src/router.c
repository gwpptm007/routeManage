#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>


#include "util_net.h"
#include "ll_map.h"
#include "router.h"
#include "log.h"


/**
 * Adding a static route to a network with route add
 * ip route add 10.38.0.0/16 via 192.168.100.1 table xxxx
 *
 * @param re  a pointer to route entry
 * @retval  0: success, -1: failed
 */
int ipv4_route_add(route_entry_t *re)
{
    struct {
        struct nlmsghdr	n;
        struct rtmsg	r;
        char			buf[4096];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
        .n.nlmsg_type = RTM_NEWROUTE,
        .r.rtm_family = AF_INET,
        .r.rtm_table = RT_TABLE_MAIN,
        .r.rtm_scope = RT_SCOPE_NOWHERE,
    };

    struct rtnl_handle rth;
    uint32_t dst, mask;
    int ret;
    unsigned int idx = 0;

    memset(&rth, 0, sizeof(rth));
    if (rtnl_open(&rth) < 0)
    {
        //printf("[ROUTE] Open netlink failed");
        log_msg(L_ERR, "[ROUTE] Open netlink failed");
        return -1;
    }

    req.r.rtm_protocol = RTPROT_BOOT;
    req.r.rtm_scope = RT_SCOPE_UNIVERSE;
    req.r.rtm_type = RTN_UNICAST;

    req.r.rtm_src_len = 0;
    req.r.rtm_dst_len = re->dst_len;

    mask = get_ip_subnet_mask(re->dst_len);
    mask = htonl(mask);
    dst = inet_addr(re->dst);
    dst &= mask;
    /* RTA_DST and RTA_GW are the two esential parameters for adding a route,
       there are other parameters too which are not discussed here. For ipv4,
       the length of the address is 4 bytes. */
    addattr_l(&req.n, sizeof(req), RTA_DST, &dst, 4);
    if (strlen(re->gateway) > 0)
    {
        uint32_t gw;
        gw = inet_addr(re->gateway);
        addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &gw, 4);
    }

    if (re->table < RT_ID_MAX)
    {
        req.r.rtm_table = re->table;
    }
    else
    {
        req.r.rtm_table = RT_TABLE_UNSPEC;
        addattr32(&req.n, sizeof(req), RTA_TABLE, re->table);
    }

    if (strlen(re->ifname) > 0)
    {
        idx = ll_name_to_index(re->ifname);
        if (!idx)
        {
            log_msg(L_ERR, "[ROUTE] Cannot find device %s", re->ifname);
            rtnl_close(&rth);
            return -1;
        }
        addattr32(&req.n, sizeof(req), RTA_OIF, idx);
    }

    addattr32(&req.n, sizeof(req), RTA_PRIORITY, re->metric);

    /*printf("-v4add--- [ROUTE] ip route add %s/%u via %s dev %s table %d,ifindex %u\n",
            re->dst, re->dst_len, re->gateway, re->ifname, re->table, idx);*/
    log_msg(L_ERR, "-v4add--- [ROUTE] ip route add %s/%u via %s dev %s table %d,ifindex %u\n",
            re->dst, re->dst_len, re->gateway, re->ifname, re->table, idx);
    /* sending the message to the kernel. */
    ret = rtnl_talk(&rth, &req.n, NULL);

    //printf("-v4add-1---- ret=%d\n", ret);
    if (ret < 0)
    {
        if (errno == NL_ERR_FILE_EXIST)
        {
            log_msg(L_ERR,"-v4Route already exists\n");
            rtnl_close(&rth);
            ret = 0;
        }
        else
        {
            log_msg(L_ERR, "[ROUTE] Add route to %s/%u via %s dev %s failed: %s\n",
                    re->dst, re->dst_len, re->gateway, re->ifname,
                    safe_strerror(errno));
        }
    }
    rtnl_close(&rth);
	//printf("-v4add-2---- ret=%d\n", ret);
    return ret;
}

/**
 * Adding a static route to a network with route add
 * ip -6 route add 2001:db8::1/64 via gateway table xxxx
 * ip -6 route add 2001:db8::1/64 via fe80::1 dev eth1
 * sudo ip -6 route add 2001:db8::777/128 via fe80::1 dev eth1  table 127
 *
 * @param re  a pointer to route entry
 * @retval  0: success, -1: failed
 */
int ipv6_route_add(route_entry_t *re)
{
    struct {
        struct nlmsghdr n;
        struct rtmsg r;
        char buf[4096];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
        .n.nlmsg_type = RTM_NEWROUTE,
        .r.rtm_family = AF_INET6,
        .r.rtm_table = RT_TABLE_MAIN,
        .r.rtm_scope = RT_SCOPE_NOWHERE,
    };

    struct rtnl_handle rth;
    struct in6_addr dst;
    int ret;
    unsigned int idx = 0;

    memset(&rth, 0, sizeof(rth));
    if (rtnl_open(&rth) < 0) {
        log_msg(L_ERR,"[ROUTE] Open netlink failed\n");
        return -1;
    }

    req.r.rtm_protocol = RTPROT_BOOT;
    req.r.rtm_scope = RT_SCOPE_UNIVERSE;
    req.r.rtm_type = RTN_UNICAST;

    req.r.rtm_src_len = 0;
    req.r.rtm_dst_len = re->dst_len;

    if (inet_pton(AF_INET6, re->dst, &dst) <= 0) {
        log_msg(L_ERR,"[ROUTE] Invalid IPv6 address: %s\n", re->dst);
        rtnl_close(&rth);
        return -1;
    }
    addattr_l(&req.n, sizeof(req), RTA_DST, &dst, sizeof(dst));

    if (strlen(re->gateway) > 0) {
        struct in6_addr gw;
        if (inet_pton(AF_INET6, re->gateway, &gw) <= 0) {
            log_msg(L_ERR,"[ROUTE] Invalid IPv6 gateway: %s\n", re->gateway);
            rtnl_close(&rth);
            return -1;
        }
        addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &gw, sizeof(gw));
    }

    if (re->table < RT_ID_MAX)
    {
        req.r.rtm_table = re->table;
    }
    else
    {
        req.r.rtm_table = RT_TABLE_UNSPEC;
        addattr32(&req.n, sizeof(req), RTA_TABLE, re->table);
    }

    if (strlen(re->ifname) > 0) {
        idx = ll_name_to_index(re->ifname);
        if (!idx) {
            log_msg(L_ERR,"[ROUTE] Cannot find device %s\n", re->ifname);
            rtnl_close(&rth);
            return -1;
        }
        addattr32(&req.n, sizeof(req), RTA_OIF, idx);
    }

    addattr32(&req.n, sizeof(req), RTA_PRIORITY, re->metric);

    /*printf("-v6add---[ROUTE] ip -6 route add %s/%u via %s dev %s table %d, ifindex %u\n",
            re->dst, re->dst_len, re->gateway, re->ifname, re->table, idx);*/

    log_msg(L_ERR, "-v6add---[ROUTE] ip -6 route add %s/%u via %s dev %s table %d, ifindex %u\n",
            re->dst, re->dst_len, re->gateway, re->ifname, re->table, idx);

    ret = rtnl_talk(&rth, &req.n, NULL);

    //printf("-v6add-1---- ret=%d\n", ret);
    if (ret < 0) {
        if (errno != EEXIST) { // If route already exists, consider it a success
            log_msg(L_ERR,"[ROUTE] Add IPv6 route to %s/%u via %s dev %s failed: %s\n",
                    re->dst, re->dst_len, re->gateway, re->ifname,
                    strerror(errno));
        } else {
            log_msg(L_ERR, "-v6Route already exists\n");
            rtnl_close(&rth);
            ret = 0; // Route already exists
        }
    }
    rtnl_close(&rth);

    //printf("-v6add-2---- ret=%d\n", ret);

    return ret;
}


/** 向系统路由表中添加IPv4路由
    使用Netlink套接字与内核通信来操作路由表
*/
int ipv4_route_add_one(struct rtnl_handle* rth, route_entry_t *re)
{
    struct { //1.结构体初始化
        struct nlmsghdr	n; //Netlink消息头，包含了消息的长度、类型、标志等信息。
        struct rtmsg	r; //路由消息结构体，包含了路由项的属性，如地址族、目的地址长度、源地址长度等。
        char			buf[4096]; //用来存放附加的属性（如目的地址、网关地址等）
    } req = { //2.消息头和路由消息的设置
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),  //计算Netlink消息长度，包含rtmsg结构体的大小。
        .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL, //Netlink消息的标志，表示这是一个请求消息，请求创建一个新路由，如果路由已经存在则失败
        .n.nlmsg_type = RTM_NEWROUTE, //Netlink消息类型，表示这是一个新建路由的请求
        .r.rtm_family = AF_INET, //地址族，表示这是一个IPv4路由。
        .r.rtm_table = RT_TABLE_MAIN,
        .r.rtm_scope = RT_SCOPE_NOWHERE, //路由范围，表示这个路由是全局有效的
    };
    log_msg(L_ERR,"ipv4_route_add_one------start------\n");

    uint32_t dst, mask;
    int ret = 0;
    unsigned int idx = 0;

    req.r.rtm_protocol = RTPROT_BOOT;
    req.r.rtm_scope = RT_SCOPE_UNIVERSE;
    req.r.rtm_type = RTN_UNICAST;

    req.r.rtm_src_len = 0;
    req.r.rtm_dst_len = re->dst_len;

    mask = get_ip_subnet_mask(re->dst_len);
    mask = htonl(mask);
    dst = inet_addr(re->dst);
    dst &= mask;
    /* RTA_DST and RTA_GW are the two esential parameters for adding a route,
       there are other parameters too which are not discussed here. For ipv4,
       the length of the address is 4 bytes. */
    //3.目的地址和网关的设置
    addattr_l(&req.n, sizeof(req), RTA_DST, &dst, 4);
    if (strlen(re->gateway) > 0)
    {
        uint32_t gw;
        gw = inet_addr(re->gateway);//将点分十进制的IP地址转换成网络字节序的整数形式
        addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &gw, 4);//向Netlink消息添加属性，例如目的地址（RTA_DST）、网关地址（RTA_GATEWAY）
    }

    if (re->table < RT_ID_MAX)
    {
        req.r.rtm_table = re->table;
    }
    else
    {
        req.r.rtm_table = RT_TABLE_UNSPEC;
        addattr32(&req.n, sizeof(req), RTA_TABLE, re->table);
    }

    /**4.接口索引的获取和设置：
    如果指定了接口名称（ifname），则使用ll_name_to_index函数获取对应的接口索引，
    然后通过addattr32函数添加到Netlink消息中
    */
    if (strlen(re->ifname) > 0)
    {
        idx = ll_name_to_index(re->ifname);
        if (!idx)
        {
            log_msg(L_ERR, "[ROUTE] Cannot find device %s", re->ifname);
            //rtnl_close(&rth);
            return -1;
        }
        addattr32(&req.n, sizeof(req), RTA_OIF, idx);
    }

    addattr32(&req.n, sizeof(req), RTA_PRIORITY, re->metric);

    log_msg(L_ERR,"[ROUTE] ip route add %s/%u via %s dev %s, ifindex %u\n",
            re->dst, re->dst_len, re->gateway, re->ifname, idx);
    printf("[ROUTE] ip route add %s/%u via %s dev %s, ifindex %u\n",
            re->dst, re->dst_len, re->gateway, re->ifname, idx);

	/* sending the message to the kernel. */
    //发送构造的Netlink消息给内核，并接收内核的回应。这个函数处理了消息的发送和接收过程
    ret = rtnl_talk(rth, &req.n, NULL);
    if (ret < 0)
    {
        if (errno == NL_ERR_FILE_EXIST)
        {
            ret = 0;
        }
        else
        {
            log_msg(L_ERR,"[ROUTE] Add route to %s/%u via %s dev %s failed: %s\n",
                    re->dst, re->dst_len, re->gateway, re->ifname,
                    safe_strerror(errno));
        }
    }		

    //log_msg(L_ERR,"ipv4_route_add_one----------end---------ret=%d\n", ret);
    return ret;
}


int ipv6_route_add_one(struct rtnl_handle* rth, route_entry_t *re) {
    struct {
        struct nlmsghdr n;
        struct rtmsg r;
        char buf[4096];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
        .n.nlmsg_type = RTM_NEWROUTE,
        .r.rtm_family = AF_INET6,
        .r.rtm_table = RT_TABLE_MAIN,
        .r.rtm_protocol = RTPROT_BOOT,
        .r.rtm_scope = RT_SCOPE_UNIVERSE,
        .r.rtm_type = RTN_UNICAST,
    };

    struct in6_addr dst;
    if (inet_pton(AF_INET6, re->dst, &dst) <= 0) {
        log_msg(L_ERR, "[ROUTE] Invalid IPv6 address: %s", re->dst);
        return -1;
    }

    req.r.rtm_dst_len = re->dst_len;

    addattr_l(&req.n, sizeof(req), RTA_DST, &dst, sizeof(dst));

    if (strlen(re->gateway) > 0) {
        struct in6_addr gw;
        if (inet_pton(AF_INET6, re->gateway, &gw) <= 0) {
            log_msg(L_ERR, "[ROUTE] Invalid IPv6 gateway: %s", re->gateway);
            return -1;
        }
        addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &gw, sizeof(gw));
    }

    if (strlen(re->ifname) > 0) {
        unsigned int idx = ll_name_to_index(re->ifname);
        if (!idx) {
            log_msg(L_ERR, "[ROUTE] Cannot find device %s", re->ifname);
            return -1;
        }
        addattr32(&req.n, sizeof(req), RTA_OIF, idx);
    }

    addattr32(&req.n, sizeof(req), RTA_PRIORITY, re->metric);

    log_msg(L_INFO, "[ROUTE] Adding IPv6 route: ip -6 route %s/%u via %s dev %s",
            re->dst, re->dst_len, re->gateway, re->ifname);

    int ret = rtnl_talk(rth, &req.n, NULL);
    if (ret < 0) {
        log_msg(L_ERR, "[ROUTE] Add IPv6 route failed: %s", strerror(errno));
        return -1;
    }

    log_msg(L_INFO, "[ROUTE] IPv6 route added successfully");
    return 0;
}

int ipv4_route_add_all(route_list_t *head)
{
 
    struct rtnl_handle rth;

    memset(&rth, 0, sizeof(rth));
    if (rtnl_open(&rth) < 0)
    {
        log_msg(L_ERR, "[ROUTE] Open netlink failed");
        return -1;
    }

    route_entry_t *re;
    /* Add static route entries */
    TAILQ_FOREACH(re, head, next)
    {
        if (re->enable != 0)
        {
            ipv4_route_add_one(&rth, re);
			//ipv4_route_add(re);
        }
    }

    rtnl_close(&rth);

    return 0;
}

int ipv6_route_add_all(route_list_t *head)
{
 
    struct rtnl_handle rth;

    memset(&rth, 0, sizeof(rth));
    if (rtnl_open(&rth) < 0)
    {
        log_msg(L_ERR, "[ROUTE] Open netlink failed");
        return -1;
    }

    route_entry_t *re;
    /* Add static route entries */
    TAILQ_FOREACH(re, head, next)
    {
        if (re->enable != 0)
        {
            ipv6_route_add_one(&rth, re);
			//ipv6_route_add(re);
        }
    }

    rtnl_close(&rth);

    return 0;
}


/**
 * Removing routes with ip route del
 * ip route del 192.168.100.0/24 via gw dev xxx table vti0
 *
 * @param re  a pointer to route entry
 * @retval  0: success, -1: failed
 */
int ipv4_route_del(route_entry_t *re)
{
    struct {
        struct nlmsghdr	n;
        struct rtmsg	r;
        char			buf[4096];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST,
        .n.nlmsg_type = RTM_DELROUTE,
        .r.rtm_family = AF_INET,
        .r.rtm_table = RT_TABLE_MAIN,
        .r.rtm_scope = RT_SCOPE_NOWHERE,
    };

    struct rtnl_handle rth;
    uint32_t dst, mask;
    unsigned int idx = 0;

    memset(&rth, 0, sizeof(rth));
    if (rtnl_open(&rth) < 0)
    {
        log_msg(L_ERR, "[ROUTE] Open netlink failed");
        return -1;
    }

    req.r.rtm_src_len = 0;
    req.r.rtm_dst_len = re->dst_len;

    mask = get_ip_subnet_mask(re->dst_len);
    mask = htonl(mask);
    dst = inet_addr(re->dst);
    dst &= mask;
    addattr_l(&req.n, sizeof(req), RTA_DST, &dst, 4);
    if (strlen(re->gateway) > 0)
    {
        uint32_t gw;
        gw = inet_addr(re->gateway);
        addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &gw, 4);
    }

    if (re->table < RT_ID_MAX)
    {
        req.r.rtm_table = re->table;
    }
    else
    {
        req.r.rtm_table = RT_TABLE_UNSPEC;
        addattr32(&req.n, sizeof(req), RTA_OIF, re->table);
    }

    if (strlen(re->ifname) > 0)
    {
        idx = ll_name_to_index(re->ifname);
        if (!idx)
        {
            log_msg(L_ERR, "[ROUTE] Cannot find device %s", re->ifname);
            rtnl_close(&rth);
            return -1;
        }
        addattr32(&req.n, sizeof(req), RTA_OIF, idx);
    }

    if (re->metric > 0)
        addattr32(&req.n, sizeof(req), RTA_PRIORITY, re->metric);

    log_msg(L_DEBUG, "[ROUTE] ip route del %s/%u via %s dev %s table %d, ifindex %u\n",
            re->dst, re->dst_len, re->gateway, re->ifname, re->table, idx);

    /*printf("-v4del---[ROUTE] ip route del %s/%u via %s dev %s table %d, ifindex %u\n",
            re->dst, re->dst_len, re->gateway, re->ifname, re->table, idx);*/

    int ret = rtnl_talk(&rth, &req.n, NULL);
    //printf("-v4del-1---- ret=%d\n", ret);
    /* sending the message to the kernel. */
    //if (rtnl_talk(&rth, &req.n, NULL) < 0)
    if (ret < 0)
    {
        if (3 != errno) /* 3: "No such process" */
        {
            log_msg(L_ERR, "[ROUTE] Delete route to %s/%u via %s dev %s failed: %s\n",
                    re->dst, re->dst_len, re->gateway, re->ifname,
                    safe_strerror(errno));
            /*printf( "--v4del-[ROUTE] Delete route to %s/%u via %s dev %s failed: %s\n",
                    re->dst, re->dst_len, re->gateway, re->ifname,
                    safe_strerror(errno));*/

            rtnl_close(&rth);
            return ret;
        }
    }
    rtnl_close(&rth);

    return 0;
}


/**
 * Removing routes with ip -6 route del
 * ip -6 route del 2001:db8::1/64 via gw dev xxx table vti0
 * ip -6 route del 2001:db8::1/64 via fe80::1 dev eth1
 *
 * @param re  a pointer to route entry
 * @retval  0: success, -1: failed
 */
int ipv6_route_del(route_entry_t *re)
{
    /**
      1. 初始化Netlink消息
        初始化一个Netlink消息req，设置消息类型为RTM_DELROUTE，表示一个删除路由的请求
        IPv6地址  AF_INET6
    */
    struct {
        struct nlmsghdr n;
        struct rtmsg r;
        char buf[4096];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST,
        .n.nlmsg_type = RTM_DELROUTE,
        .r.rtm_family = AF_INET6,
        .r.rtm_table = RT_TABLE_MAIN,
        .r.rtm_scope = RT_SCOPE_NOWHERE,
    };

    struct rtnl_handle rth;
    memset(&rth, 0, sizeof(rth));
    if (rtnl_open(&rth) < 0)
    {
        log_msg(L_ERR, "[ROUTE] Open netlink failed");
        return -1;
    }

    /**2. 设置目的地址
       inet_pton函数将字符串形式的IPv6地址转换为二进制格式
       将其作为目的地址添加到Netlink消息中
    */
    struct in6_addr dst;
    unsigned int idx = 0;

    req.r.rtm_src_len = 0;
    req.r.rtm_dst_len = re->dst_len;

    if (inet_pton(AF_INET6, re->dst, &dst) <= 0) {
        log_msg(L_ERR, "[ROUTE] Invalid IPv6 address: %s", re->dst);
        return -1;
    }
    addattr_l(&req.n, sizeof(req), RTA_DST, &dst, sizeof(dst));

    /**3. 设置网关地址
        网关地址用于指定路由的下一跳
    */
    if (strlen(re->gateway) > 0) {
        struct in6_addr gw;
        if (inet_pton(AF_INET6, re->gateway, &gw) <= 0) {
            log_msg(L_ERR, "[ROUTE] Invalid IPv6 gateway: %s", re->gateway);
            return -1;
        }
        addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &gw, sizeof(gw));
    }

    
    if (re->table < RT_ID_MAX) {
        req.r.rtm_table = re->table;
    } else {
        req.r.rtm_table = RT_TABLE_UNSPEC;
        addattr32(&req.n, sizeof(req), RTA_TABLE, re->table);
    }

    /** 4. 设置输出接口
        指定输出接口（re->ifname）
        通过ll_name_to_index获取接口的索引，将其添加到Netlink消息中
    */
    if (strlen(re->ifname) > 0) {
        idx = ll_name_to_index(re->ifname);
        if (!idx) {
            log_msg(L_ERR, "[ROUTE] Cannot find device %s", re->ifname);
            return -1;
        }
        addattr32(&req.n, sizeof(req), RTA_OIF, idx);
    }

    if (re->metric > 0)
        addattr32(&req.n, sizeof(req), RTA_PRIORITY, re->metric);

    log_msg(L_DEBUG, "[ROUTE] ip -6 route del %s/%u via %s dev %s table %d, ifindex %u",
            re->dst, re->dst_len, re->gateway, re->ifname, re->table, idx);

    /*printf("[ROUTE] ip -6 route del %s/%u via %s dev %s table %d, ifindex %u\n",
            re->dst, re->dst_len, re->gateway, re->ifname, re->table, idx);*/

    /** 5. 发送Netlink消息 
        通过rtnl_talk发送Netlink消息给内核
        返回0，表示成功删除路由项
    */

    int ret = rtnl_talk(&rth, &req.n, NULL);
    //printf("-v6del-1---- ret=%d\n", ret);

    //if (rtnl_talk(&rth, &req.n, NULL) < 0) 
    if (ret < 0)
    {
        if (errno != ESRCH) { // ESRCH: No such process
            log_msg(L_ERR, "[ROUTE] Delete IPv6 route to %s/%u via %s dev %s failed: %s",
                    re->dst, re->dst_len, re->gateway, re->ifname,
                    strerror(errno));

             /*printf("[ROUTE] Delete IPv6 route to %s/%u via %s dev %s failed: %s",
                    re->dst, re->dst_len, re->gateway, re->ifname,strerror(errno));   */    
            rtnl_close(&rth);
            return -1;
        }
    }
    rtnl_close(&rth);

    return 0;
}

int ipv4_route_del_one(struct rtnl_handle* rth, route_entry_t *re)
{
	struct {
		 struct nlmsghdr n;
		 struct rtmsg	 r;
		 char			 buf[4096];
	 } req = {
		 .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
		 .n.nlmsg_flags = NLM_F_REQUEST,
		 .n.nlmsg_type = RTM_DELROUTE,
		 .r.rtm_family = AF_INET,
		 .r.rtm_table = RT_TABLE_MAIN,
		 .r.rtm_scope = RT_SCOPE_NOWHERE,
	 };
	

	 uint32_t dst, mask;
	 unsigned int idx = 0;
	
	 req.r.rtm_src_len = 0;
	 req.r.rtm_dst_len = re->dst_len;
	
	 mask = get_ip_subnet_mask(re->dst_len);
	 mask = htonl(mask);
	 dst = inet_addr(re->dst);
	 dst &= mask;
	 addattr_l(&req.n, sizeof(req), RTA_DST, &dst, 4);
	 if (strlen(re->gateway) > 0)
	 {
		 uint32_t gw;
		 gw = inet_addr(re->gateway);
		 addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &gw, 4);
	 }
	
	 if (re->table < RT_ID_MAX)
	 {
		 req.r.rtm_table = re->table;
	 }
	 else
	 {
		 req.r.rtm_table = RT_TABLE_UNSPEC;
		 addattr32(&req.n, sizeof(req), RTA_OIF, re->table);
	 }
	
	 if (strlen(re->ifname) > 0)
	 {
		 idx = ll_name_to_index(re->ifname);
		 if (!idx)
		 {
			 log_msg(L_ERR, "[ROUTE] Cannot find device %s", re->ifname);
			 return -1;
		 }
		 addattr32(&req.n, sizeof(req), RTA_OIF, idx);
	 }
	
	 if (re->metric > 0)
		 addattr32(&req.n, sizeof(req), RTA_PRIORITY, re->metric);
	
	 log_msg(L_DEBUG, "[ROUTE] ip route del %s/%u via %s dev %s, ifindex %u",
			 re->dst, re->dst_len, re->gateway, re->ifname, idx);
	
	 /* sending the message to the kernel. */
	 if (rtnl_talk(rth, &req.n, NULL) < 0)
	 {
		 if (3 != errno) /* 3: "No such process" */
		 {
			 log_msg(L_ERR, "[ROUTE] Delete route to %s/%u via %s dev %s failed: %s\n",
					 re->dst, re->dst_len, re->gateway, re->ifname,
					 safe_strerror(errno));
		 }
	 }
	
	 return 0;

}


/** 通过netlink删除路由
    rtnl_handle* rth指针用于Netlink通信
    route_entry_t *re  描述要删除的路由项 
*/
int ipv6_route_del_one(struct rtnl_handle* rth, route_entry_t *re)
{
    /**
      1. 初始化Netlink消息
        初始化一个Netlink消息req，设置消息类型为RTM_DELROUTE，表示一个删除路由的请求
        IPv6地址  AF_INET6
    */
    struct {
        struct nlmsghdr n;
        struct rtmsg r;
        char buf[4096];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST,
        .n.nlmsg_type = RTM_DELROUTE,
        .r.rtm_family = AF_INET6,
        .r.rtm_table = RT_TABLE_MAIN,
        .r.rtm_scope = RT_SCOPE_NOWHERE,
    };

    /**2. 设置目的地址
       inet_pton函数将字符串形式的IPv6地址转换为二进制格式
       将其作为目的地址添加到Netlink消息中
    */
    struct in6_addr dst;
    unsigned int idx = 0;

    req.r.rtm_src_len = 0;
    req.r.rtm_dst_len = re->dst_len;

    if (inet_pton(AF_INET6, re->dst, &dst) <= 0) {
        log_msg(L_ERR, "[ROUTE] Invalid IPv6 address: %s", re->dst);
        return -1;
    }
    
    addattr_l(&req.n, sizeof(req), RTA_DST, &dst, sizeof(dst));

    /**3. 设置网关地址
        网关地址用于指定路由的下一跳
    */
    if (strlen(re->gateway) > 0) {
        struct in6_addr gw;
        if (inet_pton(AF_INET6, re->gateway, &gw) <= 0) {
            log_msg(L_ERR, "[ROUTE] Invalid IPv6 gateway: %s", re->gateway);
            return -1;
        }
        addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &gw, sizeof(gw));
    }
    
    if (re->table < RT_ID_MAX) {
        req.r.rtm_table = re->table;
    } else {
        req.r.rtm_table = RT_TABLE_UNSPEC;
        addattr32(&req.n, sizeof(req), RTA_TABLE, re->table);
    }

    /** 4. 设置输出接口
        指定输出接口（re->ifname）
        通过ll_name_to_index获取接口的索引，将其添加到Netlink消息中
    */
    if (strlen(re->ifname) > 0) {
        idx = ll_name_to_index(re->ifname);
        if (!idx) {
            log_msg(L_ERR, "[ROUTE] Cannot find device %s", re->ifname);
            return -1;
        }
        addattr32(&req.n, sizeof(req), RTA_OIF, idx);
    }

    if (re->metric > 0)
        addattr32(&req.n, sizeof(req), RTA_PRIORITY, re->metric);

    log_msg(L_DEBUG, "[ROUTE] ip -6 route del %s/%u via %s dev %s, ifindex %u",
            re->dst, re->dst_len, re->gateway, re->ifname, idx);

    /** 5. 发送Netlink消息 
        通过rtnl_talk发送Netlink消息给内核
        返回0，表示成功删除路由项
    */
    if (rtnl_talk(rth, &req.n, NULL) < 0) {
        if (errno != ESRCH) { // ESRCH: No such process
            log_msg(L_ERR, "[ROUTE] Delete IPv6 route to %s/%u via %s dev %s failed: %s",
                    re->dst, re->dst_len, re->gateway, re->ifname,
                    strerror(errno));
            return -1;
        }
    }

    return 0;

}


int ipv4_route_del_all(route_list_t *head)
{
    route_entry_t *entry, *n;

    if (TAILQ_EMPTY(head))
        return -1;
	
    struct rtnl_handle rth;
    memset(&rth, 0, sizeof(rth));
    if (rtnl_open(&rth) < 0)
    {
        log_msg(L_ERR, "[ROUTE] Open netlink failed");
        return -1;
    }


    TAILQ_FOREACH_SAFE(entry, head, next, n)
    {
       // TAILQ_REMOVE(head, entry, next);
        ipv4_route_del_one(&rth, entry);
       // free(entry);
    }

	rtnl_close(&rth);
	
    return 0;
}

int ipv6_route_del_all(route_list_t *head)
{
    route_entry_t *entry, *n;

    if (TAILQ_EMPTY(head))
        return -1;
	
    struct rtnl_handle rth;
    memset(&rth, 0, sizeof(rth));
    if (rtnl_open(&rth) < 0)
    {
        log_msg(L_ERR, "[ROUTE] Open netlink failed");
        return -1;
    }


    TAILQ_FOREACH_SAFE(entry, head, next, n)
    {
       // TAILQ_REMOVE(head, entry, next);
        ipv6_route_del_one(&rth, entry);
       // free(entry);
    }

	rtnl_close(&rth);
	
    return 0;

}


void ip_route_list_destroy(route_list_t *head)
{
    route_entry_t *entry, *n;

    if (TAILQ_EMPTY(head))
        return;

    TAILQ_FOREACH_SAFE(entry, head, next, n)
    {
        TAILQ_REMOVE(head, entry, next);
        free(entry);
    }
}




