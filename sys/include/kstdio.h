#pragma once

#include <kstdarg.h>

void kprintf(const char *, ...);

/* To "stdout" */
int kputchar(int);
void kputs(const char *);


#ifdef SLB_THESIS 
#ifdef MULTICORE_PRINTING

void tkprintf(const char *, ...);
void printer_cpu_init(void);
void printer_cpu_service(unsigned int vec, void *varg);

#define PRINTER_CPU 4
#define PRINTING_IPI 0xb0
#define STDOUT_MSG_LEN 2048

#endif
#endif
