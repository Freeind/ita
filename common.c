#include "common.h"
#include <stdarg.h>
#include <time.h>

static const char *g_priority_str[] = {"NONE", "ERROR", "INFO", "DEBUG"};

void *new(size_t size)
{
	void *p = calloc(1, size);

	if (p == NULL) {
		ALLOC_FAILED();
	}

	return p;
}

void _log(int priority, const char *fmt, ...)
{
	va_list ap;
	struct timespec ts;
	struct tm tm;

	clock_gettime(CLOCK_REALTIME, &ts);
	localtime_r(&ts.tv_sec, &tm);

	fprintf(stderr, "%04d-%02d-%02d %02d:%02d:%02d.%03ld [%s] ",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000, g_priority_str[priority]);

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}


size_t _strlcpy(char *dest, const char *src, size_t dest_size)
{
	char *d = dest;
	const char *s = src;
	size_t n = dest_size;

	if (dest == NULL || src == NULL) {
		return 0;
	}

	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0)
		do {
			char c = *s++;

			*d++ = c;

			if (c == 0) {
				break;
			}
		} while (--n != 0);

	/* If not enough room in dest, add NUL and traverse rest of src */
	if (n == 0) {
		if (dest_size != 0) {
			*d = 0;
		}

		while (*s++);
	}

	return s - src - 1;  /* count does not include NUL */
}

int map_int_get_v(const char *k, map_int_t *map)
{
	int i = 0;

	for (; map[i].k != NULL; i++) {
		if (strcmp(map[i].k, k) == 0) {
			break;
		}
	}

	return map[i].v;
}

const char *map_int_get_k(int v, map_int_t *map)
{
	int i = 0;

	for (; map[i].k != NULL; i++) {
		if (map[i].v == v) {
			break;
		}
	}

	return map[i].k;
}

