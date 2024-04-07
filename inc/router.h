#ifndef __ROUTER_H__
#define __ROUTER_H__

#include <stdint.h>
#include "queue.h"
#include "util_net.h"

#define MAX_IF_STR_LEN        32
#define MAX_IP_STR_LEN        32
#define ROUTE_NOTE_LEN        128

/* ip route entry configuration parameters */
typedef struct _route_entry
{
    uint32_t id;                       /* id */
    uint32_t table;                    /* routing table id */
    uint32_t action;                   /* action: add, edit, del */
    uint32_t enable;                   /* enabled/disabled */
    uint32_t if_id;                    /* interface id */
    char     ifname[MAX_IF_STR_LEN];   /* interface */
    //char src[MAX_IP_STR_LEN];        /* source address */
    char     dst[MAX_IP_STR_LEN];      /* destination address */
    char     netmask[MAX_IP_STR_LEN];  /* netmask */
    char     gateway[MAX_IP_STR_LEN];  /* nexthop */
    //uint8_t  src_len;                /* source subnet prefix length */
    uint8_t  dst_len;                  /* destination subnet prefix length */
    uint32_t metric;
    char     note[ROUTE_NOTE_LEN];
    TAILQ_ENTRY(_route_entry) next;
} route_entry_t;

typedef TAILQ_HEAD(_route_list, _route_entry) route_list_t;


int ipv4_route_add_all(route_list_t *head);
int ipv6_route_add_all(route_list_t *head);
int ipv4_route_del_all(route_list_t *head);
int ipv6_route_del_all(route_list_t *head);


/******************************************************************
*  @brief  : ipv4_route_add
*			 添加一条IPv4路由
*  @param  :
*	   IN  : route_entry_t *re
*             re.enable = 1 启用
*             re.ifname     网卡名称
*             re.dst        目标地址
*             re.netmask    子网掩码
*             re.dst_len    子网掩码长度
*             re.gateway    网关 (next hop)
*	   OUT : NONE
*  @return : OK    --   0
*			 ERROR --  -1 
*  @author : wangqi
*  @time   : 2024/03/20
****************************************************************/
int ipv4_route_add(route_entry_t *re);

/******************************************************************
*  @brief  : ipv6_route_add
*			 添加一条IPv6路由
*  @param  :
*	   IN  : route_entry_t *re
*             re.enable = 1 启用
*             re.ifname     网卡名称
*             re.dst        目标地址
*             re.netmask    子网掩码
*             re.dst_len    子网掩码长度
*             re.gateway    网关 (next hop)
*	   OUT : NONE
*  @return : OK    --   0
*			 ERROR --  -1 
*  @author : wangqi
*  @time   : 2024/03/20
****************************************************************/
int ipv6_route_add(route_entry_t *re);


/******************************************************************
*  @brief  : ipv4_route_del
*			 删除一条IPv4路由
*  @param  :
*	   IN  : route_entry_t *re
*             re.enable = 1 启用
*             re.ifname     网卡名称
*             re.dst        目标地址
*             re.netmask    子网掩码
*             re.dst_len    子网掩码长度
*             re.gateway    网关 (next hop)
*	   OUT : NONE
*  @return : OK    --   0
*			 ERROR --  -1 
*  @author : wangqi
*  @time   : 2024/03/20
****************************************************************/
int ipv4_route_del(route_entry_t *re);


/******************************************************************
*  @brief  : ipv6_route_del
*			 删除一条IPv6路由
*  @param  :
*	   IN  : route_entry_t *re
*             re.enable = 1 启用
*             re.ifname     网卡名称
*             re.dst        目标地址
*             re.netmask    子网掩码
*             re.dst_len    子网掩码长度
*             re.gateway    网关 (next hop)
*	   OUT : NONE
*  @return : OK    --   0
*			 ERROR --  -1 
*  @author : wangqi
*  @time   : 2024/03/20
****************************************************************/
int ipv6_route_del(route_entry_t *re);





//int ipv4_route_add_one(struct rtnl_handle* rth, route_entry_t *re);
//int ipv4_route_del_one(struct rtnl_handle* rth, route_entry_t *re);
//int ipv6_route_add_one(struct rtnl_handle* rth, route_entry_t *re);
//int ipv6_route_del_one(struct rtnl_handle* rth, route_entry_t *re);
void ip_route_list_destroy(route_list_t *head);


#endif  /* __ROUTER_H__ */

