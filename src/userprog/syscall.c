#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"    /* for PHYS_BASE */
#include "threads/synch.h"    /* for lock */
#include "userprog/pagedir.h" /* for pagedir_get_page */
#include "userprog/process.h" /* process_execute, process_wait */
#include "devices/shutdown.h" /* for shutdown_power_off */
#include "devices/input.h"    /* for input_getc */
#include "filesys/file.h"     /* for file_... */
#include "filesys/filesys.h"  /* for filesys_... */

/*
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/user/syscall.h"
*/


static struct lock lock_filesys;
static void syscall_handler (struct intr_frame *);
#define IS_VALID(p) ((p) != NULL && \
	(void *)(p) < PHYS_BASE && \
	pagedir_get_page(thread_current()->pagedir, (p)) != NULL)


void
syscall_init (void) 
{
  lock_init (&lock_filesys);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static int
syscall_exit (int status)
{
	thread_current()->exit_code = status;
	thread_exit (); /* will call process_wait() and terminate thread */
}

static unsigned
syscall_tell (int fd) 
{
	struct file *f = process_file_find (fd);
	if (f == NULL)
		return (unsigned)-1;
	return (unsigned)file_tell(f);
}

static bool
syscall_remove (const char *file) 
{
	return filesys_remove(file);
}

static int
syscall_filesize (int fd) 
{
	struct file *f = process_file_find (fd);
	if (f == NULL)
		return -1;
	return (int)file_length(f);
}

static bool
syscall_create (const char *file, unsigned initial_size)
{
	return filesys_create(file, initial_size);
}

static void
syscall_seek (int fd, unsigned position) 
{
	struct file *f = process_file_find (fd);
	if (f == NULL)
		return;
	file_seek(f, (off_t)position);
}

static int
syscall_read (int fd, char *buffer, unsigned size)
{
	struct file *f;	

	// if the FD is 0, read STDIN
	if (fd == 0) {
		unsigned i;
		for (i = 0; i < size; i++)
			buffer[i] = (char)input_getc();
		return (int)i;
	}

	f = process_file_find (fd);
	if (f == NULL)
		return -1;
	return file_read(f, buffer, size);
}

static int
syscall_write (int fd, const char *buffer, unsigned size) 
{
	struct file *f;

	/* if the FD is 1, write to STDOUT */
	if (fd == 1) {
		const int max_out = 256;
		int remained = size;

		while (remained > max_out) {
			putbuf(buffer, max_out);
			buffer += max_out;
			remained -= max_out;
		}
		putbuf(buffer, remained);
		
		// actuall size of bytes written is (size - i)
		return (int)size;
	}

	/* normal case */
	f = process_file_find (fd);
	if (f == NULL)
		return -1;
	return file_write(f, buffer, size);
}

static void
syscall_handler (struct intr_frame *f) 
{
	int nsyscall, argc, i;
	int *esp = (int *)f->esp; /* get argument pointer */
	int *arg_int[3];
	void **arg_ptr[3];

	/* verify the argument pointer */
	if (!IS_VALID(esp))
		goto error_end;

	/* system call number */
	nsyscall = *(esp++);

	/* number of arguments */
	switch (nsyscall) {
	case SYS_HALT: 
		argc = 0;
		break;
	case SYS_EXIT:
	case SYS_EXEC:
	case SYS_WAIT:
	case SYS_TELL:
	case SYS_CLOSE:	
	case SYS_REMOVE:
	case SYS_OPEN:
	case SYS_FILESIZE:
		argc = 1;
		break;
	case SYS_CREATE:
	case SYS_SEEK:
		argc = 2;
		break;
	case SYS_READ:
	case SYS_WRITE:
		argc = 3;
		break;
	default:
		goto error_end;
	}

	/* verify the argument pointer */
	for (i = 0; i < argc; i++)
		if (IS_VALID(esp + i)) {
			arg_int[i] = esp + i;
			arg_ptr[i] = (void**)(esp + i);
		} else {
			break;
		}
	if (i < argc)
		goto error_end;

	/* system call */
	switch (nsyscall) {
	case SYS_HALT:
		shutdown_power_off();
		break; 
	case SYS_EXIT:
		syscall_exit(*arg_int[0]);
		break;
	case SYS_EXEC:
		if (!IS_VALID(*arg_ptr[0]))
			goto error_end;
		lock_acquire (&lock_filesys);
		f->eax = process_execute(*arg_ptr[0]);
		lock_release (&lock_filesys);
		break;
	case SYS_WAIT:
		f->eax = process_wait(*arg_int[0]);
		break;
	case SYS_TELL:
		lock_acquire (&lock_filesys);
		f->eax = syscall_tell(*arg_int[0]);
		lock_release (&lock_filesys);
		break;
	case SYS_CLOSE:	
		lock_acquire (&lock_filesys);
		process_file_close(*arg_int[0]);
		lock_release (&lock_filesys);
		break;
	case SYS_REMOVE:
		if (!IS_VALID(*arg_ptr[0]))
			goto error_end;
		lock_acquire (&lock_filesys);
		f->eax = syscall_remove(*arg_ptr[0]);
		lock_release (&lock_filesys);
		break;
	case SYS_OPEN:
		if (!IS_VALID(*arg_ptr[0]))
			goto error_end;
		lock_acquire (&lock_filesys);
		f->eax = process_file_open(*arg_ptr[0]);
		lock_release (&lock_filesys);
		break;
	case SYS_FILESIZE:
		lock_acquire (&lock_filesys);
		f->eax = syscall_filesize(*arg_int[0]);
		lock_release (&lock_filesys);
		break;
	case SYS_CREATE:
		if (!IS_VALID(*arg_ptr[0]))
			goto error_end;
		lock_acquire (&lock_filesys);
		f->eax = syscall_create(*arg_ptr[0], *arg_int[1]);
		lock_release (&lock_filesys);
		break;
	case SYS_SEEK:
		lock_acquire (&lock_filesys);
		syscall_seek(*arg_int[0], *arg_int[1]);
		lock_release (&lock_filesys);
		break;
	case SYS_READ:
		if (!IS_VALID(*arg_ptr[1]))
			goto error_end;
		lock_acquire (&lock_filesys);
		f->eax = syscall_read(*arg_int[0], *arg_ptr[1], *arg_int[2]);
		lock_release (&lock_filesys);
		break;
	case SYS_WRITE:
		if (!IS_VALID(*arg_ptr[1]))
			goto error_end;
		lock_acquire (&lock_filesys);
		f->eax = syscall_write(*arg_int[0], *arg_ptr[1], *arg_int[2]);
		lock_release (&lock_filesys);
		break;
	default:
		printf ("Unknown syscall : %d\n", nsyscall);
		goto error_end;
	}
	return;

error_end:
	thread_exit ();
}
