#ifndef _I_PUBLIC_H
#define _I_PUBLIC_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <errno.h>
#include <pthread.h>
//#include <jansson.h>
#include <sys/prctl.h>

#include "log.h"

//--------------------------------------------------
#define  I_R_YES    1    //作为出参或返回值
#define  I_R_NO     2    //作为出参或返回值

#define  I_R_OK        0  //作为函数的返回值
#define  I_R_ERROR    -1  //作为函数的返回值

#define  I_SET_FLAG    1  //设置flag值
#define  I_RESET_FLAG  0  //复位flag值
//-------------------------------------------------


//-----------通用类型定义-------------------
#define  UINT8     unsigned char
#define  INT8      char
#define  UINT16    unsigned short int
#define  INT16     short int
#define  UINT32    unsigned int
#define  INT32     int
#define  UINT64    unsigned long long int
#define  INT64     long long int
//---------------------------------------------------

//获得结构体中的项在结构体中的偏移
#define I_OFFSET(struc, obj) (UINT64)&(((struc *)0)->obj)

#ifndef MAX
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x,y) (((x)<(y))?(x):(y))
#endif

//-------------------通用互斥锁定义------------
#define  T_CS              pthread_mutex_t        
#define  LOCK_INIT(x)      pthread_mutex_init(x, NULL)
#define  LOCK(x)           pthread_mutex_lock(x)
#define  UNLOCK(x)         pthread_mutex_unlock(x)
#define  LOCK_DEL(x)       pthread_mutex_destroy(x)
//--------------------------------------------------------


#define T_SP           pthread_spinlock_t
#define SLOCK_INIT(x)  pthread_spin_init(x, 0)
#define SLOCK(x)       pthread_spin_lock(x)
#define UNSLOCK(x)     pthread_spin_unlock(x)
#define SLOCK_DEL(x)   pthread_spin_destroy(x)
#define SLOCK_TRY(x)   pthread_spin_trylock(x)

#define T_RW           	pthread_rwlock_t 
#define RWLOCK_INIT(x)  pthread_rwlock_init(x, 0)
#define RLOCK(x)       	pthread_rwlock_rdlock(x)
#define WLOCK(x)        pthread_rwlock_wrlock(x)
#define UNRWLOCK(x)     pthread_rwlock_unlock(x)
#define RWLOCK_DEL(x)   pthread_rwlock_destroy(x)
#define RWLOCK_TRY(x)   pthread_spin_trylock(x)



//-------------通用条件变量定义-------------------
#define  T_CT			   pthread_cond_t
#define  COND_INIT(x)      pthread_cond_init(x, NULL)
#define  COND_WAIT(x, y)   pthread_cond_wait(x, y)
#define  COND_SINGAL(x)    pthread_cond_signal(x)
#define  COND_DEL(x)       pthread_cond_destroy(x)
#define  COND_TIMEWAIT(x, y, z)  pthread_cond_timedwait(x, y, z)
//------------------------------------------------------------


//----------------------------原子变量操作-----------------------------------
#if !defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_1) || !defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_2) \
    || !defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_4) || !defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_8)
# error "the gcc version has no atomic support!"
#else

#define ATOMIC_DECLARE(type, name)			type name ## _atomic_
#define ATOMIC_EXTERN(type, name)    		extern type name ## _atomic_
#define ATOMIC_INIT(name)           		(name ## _atomic_) = 0
#define ATOMIC_RESET(name)          		(name ## _atomic_) = 0
#define ATOMIC_DECL_AND_INIT(type, name)	type (name ## _atomic_) = 0
#define ATOMIC_ADD(name, value) 			__sync_add_and_fetch(&(name ## _atomic_), value) 
#define ATOMIC_SUB(name, value) 			__sync_sub_and_fetch(&(name ## _atomic_), value) 
#define ATOMIC_AND(name, value) 			__sync_fetch_and_and(&(name ## _atomic_), value)
#define ATOMIC_OR(name, value)				__sync_fetch_and_or(&(name ## _atomic_), value)
#define ATOMIC_XOR(name, value)				__sync_fetch_and_xor(&(name ## _atomic_), value)
#define ATOMIC_NAND(name, value)			__sync_fetch_and_nand(&(name ## _atomic_), value)
#define ATOMIC_CAS(name, cmpvalue, newvalue) __sync_bool_compare_and_swap(&(name ## _atomic_), cmpvalue, newvalue) 
#define ATOMIC_GET(name) 					(name ## _atomic_)
#define ATOMIC_SET(name, value) ({ \
    while (ATOMIC_CAS(name, ATOMIC_GET(name), value) == 0) \
        ; })

#endif
//-------------------------------------------------------------------------------------

#ifndef likely
#define likely(expr) __builtin_expect(!!(expr), 1)
#endif
#ifndef unlikely
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#endif

#define BIT_U8(n)   ((uint8_t)(1 << (n)))
#define BIT_U16(n)  ((uint16_t)(1 << (n)))
#define BIT_U32(n)  (1UL << (n))
#define BIT_U64(n)  (1ULL << (n))

#endif
