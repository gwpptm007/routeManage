#ifndef _LOG_H__
#define _LOG_H__

#include <syslog.h>

#define L_FATAL 0
#define L_ERR   1
#define L_WARN  2
#define L_INFO  3
#define L_DEBUG 4
#define LOG_LEVEL_MAX  5

void _log_msg(int type, const char *file, int line, const char *format, ...);

#define log_msg(type, format, ...) \
    do { \
        _log_msg(type, __FILE__, __LINE__, format, ##__VA_ARGS__); \
    } while (0)

/*===========================================================================
函数名:  init_log
功能:  初始化日志
入参:  char *logfile_dir: 日志目录
       char *logfile_name: 日志文件名
       char *mode: 打开方式a+,a,w,r等
       int level: 日志级别L_FATAL - LOG_LEVEL_MAX
出参:
返回值: 0 初始化成功
		-1 初始化失败
作者:   
时间:  
说明: 小于等于level值会打印，大于不会打印
=============================================================================*/
int init_log(char *logfile_dir, char *logfile_name, char *mode, int level);

#endif

