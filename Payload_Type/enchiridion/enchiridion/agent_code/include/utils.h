#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdio.h>

#define BUFSIZE 8192
#define ERR_MSG_SIZE 128

void uint_to_str(unsigned int n, char *buf);
// Strip trailing whitespace (\r \n \t space) in-place; returns new length.
size_t str_rtrim(char *s, size_t len);

#ifdef DEBUG
#define DBGPRINT(fmt, ...) fprintf(stderr, "[DBG] %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define DBGPRINT(fmt, ...) ((void)0)
#endif
#endif // !UTILS_H
