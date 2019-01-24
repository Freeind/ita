#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#ifdef MEMWATCH
#include "memwatch.h"
#endif



typedef struct map_int {
	const char *k;
	int v;
} map_int_t;

enum log_type {
	LOG_NONE,
	LOG_ERR,
	LOG_INFO,
	LOG_DEBUG,
};

#define log_err(fmt, ...)		_log(LOG_ERR, fmt, ## __VA_ARGS__)
#define log_info(fmt, ...)		_log(LOG_INFO, fmt, ## __VA_ARGS__)
#define log_debug(fmt, ...)		_log(LOG_DEBUG, fmt, ## __VA_ARGS__)

#define ALLOC_FAILED()	do{log_err("%s %d alloc failed\n", __FUNCTION__, __LINE__);exit(-1);} while(0)

#define _new(type)		new(sizeof(type))
#define _free(x)		do{if(x){free(x);x=NULL;}}while(0)

void *new(size_t size);
void _log(int priority, const char *fmt, ...);
size_t _strlcpy(char *dest, const char *src, size_t dest_size);
int map_int_get_v(const char *k, map_int_t *map);
const char *map_int_get_k(int v, map_int_t *map);

#endif /* COMMON_H */
