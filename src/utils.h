#ifndef UTILS_H
#define UTILS_H

#define DEBUG 0

#if defined(DEBUG) && DEBUG > 0
#define DEBUG_PRINT(fmt, args...) fprintf(stderr, "\033[38;5;214mDEBUG: %s:%d:%s():\033[0m " fmt, \
                                          __FILE__, __LINE__, __func__, ##args)
#else
#define DEBUG_PRINT(fmt, args...) /* Don't do anything in release builds */
#endif

typedef enum RESPONSE_TYPE
{
    SUCCESS,    // results in '[n]. [IP] ... [time]\n'
    TIMEOUT,    // results in '???'
    NO_RESPONSE // results in '*'
} RESPONSE_TYPE;

struct response_t
{
    char ip_addresses[100];
    RESPONSE_TYPE type;
    int avg_time_ms;
};

#endif // !UTILS_H