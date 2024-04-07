#ifndef __WQ_ROUTE_H__
#define __WQ_ROUTE_H__


#define IFNAMSIZ 16


/******************************************************************
 *	@brief  : wq_route_add_ip4
 *			  添加一条IPv4路由 
 *            sudo ip route add 172.16.40.117/32 via 172.16.40.254 dev eth1 table 123
 *            ip route show table 123	      
 *	@param  :
 *		IN  : uip[4]                -- 目的ip，子网掩码固定32
 *            gip[4]                -- 网关ip(下一跳ip地址)
 *            ifname[16]            -- 网卡接口，最大16
 *            tabid                 -- 路由表名称 取值0-255
 *	    OUT : NONE
 *	@return : SUCC     --   0
 * 			  FAILED   --  -1 
 *  @author : wangqi
 *  @time   : 2024/03/27
 ****************************************************************/
int wq_route_add_ip4(unsigned char uip[4], unsigned char gip[4], unsigned char ifname[IFNAMSIZ], int tabid);


/******************************************************************
 *	@brief  : wq_route_add_ip6
 *			  添加一条IPv6路由 
 *            sudo ip -6 route add 2001:db8::777/128 via fe80::1 dev eth1  table 125
 *            ip -6 route show table 125	      
 *	@param  :
 *		IN  : uip[16]                -- 目的ip，子网掩码固定128
 *            gip[16]                -- 网关ip(下一跳ip地址)
 *            ifname[16]             -- 网卡接口，最大16
 *            tabid                  -- 路由表名称 取值0-255
 *	    OUT : NONE
 *	@return : SUCC     --   0
 * 			  FAILED   --  -1 
 *  @author : wangqi
 *  @time   : 2024/03/27
 ****************************************************************/
int wq_route_add_ip6(unsigned char uip[16], unsigned char gip[16], unsigned char ifname[IFNAMSIZ], int tabid);




/******************************************************************
 *	@brief  : wq_route_delete_ip4
 *			  删除一条IPv4路由 
 *            sudo ip route del 172.16.40.117/32 via 172.16.40.254 dev eth1 table 123	      
 *	@param  :
 *		IN  : uip[4]                -- 目的ip，子网掩码固定32
 *            gip[4]                -- 网关ip(下一跳ip地址)
 *            ifname[16]            -- 网卡接口，最大16
 *            tabid                 -- 路由表名称 取值0-255
 *	    OUT : NONE
 *	@return : SUCC     --   0
 * 			  FAILED   --  -1 
 *  @author : wangqi
 *  @time   : 2024/03/27
 ****************************************************************/
int wq_route_delete_ip4(unsigned char uip[4], unsigned char gip[4], unsigned char ifname[IFNAMSIZ], int tabid);


/******************************************************************
 *	@brief  : wq_route_delete_ip6
 *			  删除一条IPv6路由 
 *            sudo ip -6 route del 2001:db8::777/128 via fe80::1 dev eth1  table 127	      
 *	@param  :
 *		IN  : uip[16]                -- 目的ip，子网掩码固定128
 *            gip[16]                -- 网关ip(下一跳ip地址)
 *            ifname[16]             -- 网卡接口，最大16
 *            tabid                  -- 路由表名称 取值0-255
 *	    OUT : NONE
 *	@return : SUCC     --   0
 * 			  FAILED   --  -1 
 *  @author : wangqi
 *  @time   : 2024/03/27
 ****************************************************************/
int wq_route_delete_ip6(unsigned char uip[16], unsigned char gip[16], unsigned char ifname[IFNAMSIZ], int tabid);


#endif
