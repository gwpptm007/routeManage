#ifndef __ZROUTER_H__
#define __ZROUTER_H__

#include "i_public.h"
//#include "zrouter_version.h"

#define ZROUTER_VERSION      "1.0.0"

#define ZROUTER_PROG_PATH       "/home/sdp/zrouter"         /* ZROUTER应用程序路径 */
#define ZROUTER_LOG_DIR 		"/home/sdp/zrouter"         /* ZROUTER日志目录 */
#define ZROUTER_WORKING_DIR 	"/home/sdp/zrouter"         /* ZROUTER运行目录 */
#define ZROUTER_LOG_NAME 		"zrouter.log"               /* ZROUTER日志名称 */
#define ZROUTER_LOG_MODE 		"a+"                        /* ZROUTER日志文件打开方式 */
#define ZROUTER_LOG_LEVEL 	     L_INFO   	                /* ZROUTER日志级别 */


#define ZROUTER_CHECK_INTVL    60

/* better assert */
#define ASSERT(cond) do { \
    if (!(cond)) { \
        log_msg(L_ERR, "Assertion '" # cond "' failed!", __FILE__, __LINE__); \
        abort(); \
    } \
} while (0)


#define SYSTEM_STR_LEN 		128            	/* system 命令字符串长度 */
#define MAX_OPT_STR_LEN     128             /* 命令行字符最大长度 */



typedef struct _zrouter_context 
{
    bool quit;              /* 程序退出标志 */
    bool daemon;            /* 后台模式 */	
    bool add;               /* 添加 */	
    bool del;               /* 删除 */
	UINT32  num;             
	char   *destip;
    char   *gatewayip;
    char   *netmask;     
    char   *ifname;
	UINT8  log_level;

} zrouter_context_t;


#endif /* __ISCAN_H__ */
