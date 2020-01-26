#pragma once

#include <stdio.h>
#include <pthread.h>

#define ALOWIT_ENABLE_LOGGING

typedef struct alowit_logging_instance {
    pthread_mutex_t write_mtx;
    FILE * fd;
} ALOWIT_LOG_INSTANCE;

typedef enum alowit_log_level { 
    ALOWIT_INFO, ALOWIT_WARNING, ALOWIT_ERROR, ALOWIT_ERROR_FATAL 
    } ALOWIT_LL;

typedef enum alowit_log_type { 
    ALOWIT_UNKNOWN, ALOWIT_MAIN
    } ALOWIT_LT;

int alowit_log_instance_init_from_fd(ALOWIT_LOG_INSTANCE **instancePtr, FILE * fd);
void alowit_log_instance_destroy(ALOWIT_LOG_INSTANCE * instance);

#ifdef ALOWIT_ENABLE_LOGGING
void alowit_log_internal(ALOWIT_LOG_INSTANCE * instance, unsigned int line, char *cFile, ALOWIT_LL logLevel, ALOWIT_LT logType, char *formatString, ...);
#define alowit_log alowit_log_internal
#else
#define alowit_log(a, b, c, d, e, f, g)
//empty macro
#endif

