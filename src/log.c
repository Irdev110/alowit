#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <pthread.h>
#include "log.h"


/// Initializes a logging instance from a file descriptor.
/** MAKE SURE YOU CHECK retval. retval == 0 on success, and instance ptr is filled  */
int alowit_log_instance_init_from_fd(ALOWIT_LOG_INSTANCE **instancePtr, FILE * fd)
{
    *instancePtr = malloc(sizeof(ALOWIT_LOG_INSTANCE));
    ALOWIT_LOG_INSTANCE *instance = *instancePtr;
    if(!instance)
        return 1;
    //Initialize all struct values..
    instance->fd = fd;
    if(!pthread_mutex_init(&(instance->write_mtx), NULL))
        return 0;
    
    //Oops.. If we got here, there was an error initializing the write mutex
    free(instance);
    return 1;
}

///Destroys a logging instance by freeing the struct and log write mutex.
void alowit_log_instance_destroy(ALOWIT_LOG_INSTANCE * instance)
{
    if(instance)
    {
        pthread_mutex_destroy(&instance->write_mtx);
        free(instance);
    }
}

/// Writes data to a alowit logging instance.
/** No return value, but make  */
void alowit_log_internal(ALOWIT_LOG_INSTANCE * instance, unsigned int line, char *cFile, ALOWIT_LL logLevel, ALOWIT_LT logType, char *formatString, ...)
{
    if(instance && !pthread_mutex_lock(&instance->write_mtx)) //Successful on retval==0
    {
        cFile = cFile ? cFile : "null"; // If cFile is null then set it to a printable string
        FILE *fd = instance->fd;
        if(fprintf(fd, "(%s):%d:%d:%d:", cFile, line, logLevel, logType) > 0) //TODO: Should we make it print the logType as a string?
        {
            va_list args;
            va_start(args, formatString);
            vfprintf(fd, formatString, args);
            va_end(args);
            fprintf(fd, "\n");
        }
        pthread_mutex_unlock(&instance->write_mtx);
    }
}
