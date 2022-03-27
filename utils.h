#ifndef UTILS_H
#define UTILS_H

#define DEBUG 1

#if defined(DEBUG) && DEBUG > 0
 #define DEBUG_PRINT(fmt, args...) fprintf(stderr, "\033[38;5;214mDEBUG: %s:%d:%s():\033[0m " fmt, \
    __FILE__, __LINE__, __func__, ##args)
#else
 #define DEBUG_PRINT(fmt, args...) /* Don't do anything in release builds */
#endif

#endif // !UTILS_H