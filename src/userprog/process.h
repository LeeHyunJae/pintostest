#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

void process_init(void);
int process_file_open (char *filename);
struct file *process_file_find (int fd);
void process_file_close (int fd);

#endif /* userprog/process.h */
