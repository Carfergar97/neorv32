#ifndef __LOG_H__
#define __LOG_H__
#include <stdio.h>
#ifdef DEBUG_LOG
#define LOG(fmt, ...) printf("[%s->%s:%d]: "fmt". \n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define FIPS_REF(Alg, Line, Comment) printf("[%s->%s:%d]: FIPS205: Algorithm: %d, Line:%d. %s \n",__FILE__, __FUNCTION__, __LINE__, Alg, Line, Comment)
#endif // DEBUG_LOG
#ifndef DEBUG_LOG
#define LOG(fmt, ...) asm("nop")
#define FIPS_REF(Alg, Line, Comment) asm("nop")
#endif // !DEBUG_LOG
#endif // !__LOG_H__
