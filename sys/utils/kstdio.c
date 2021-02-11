/* kstdio.c -- Kernel versions of useful C stdio functions.
 *
 * Copyright (c) 2011 Stephen Taylor (parts of printf)
 * Copyright (c) 2011 Morgon Kanter (everything else)
 */
#include <kstdarg.h>
#include <kstdio.h>
#include <stdint.h>
#include <fatfs.h>
#include <constants.h>
#include <pio.h>

#ifdef VGA_OUT_SYSTEM
#include <sbin/vgad.h>
#endif

#if defined(SLB_THESIS) && defined(KERNEL) && defined(MULTICORE_PRINTING)
#include <apic.h>
#include <smp.h>
#endif

#ifndef USER			/* ensure only used in system */

#define STDOUT NULL

#define TABSTOP 8



#if defined(SLB_THESIS) && defined(KERNEL) && defined(MULTICORE_PRINTING)
char stdout_msg_arr[8][STDOUT_MSG_LEN];
volatile int stdout_msg_idx[8]; 
int printer_cpu_up = 0;
static int tputc(int c, FIL *fp);
static void tdo_print(const char *fmt, va_list argp, FIL *stream);
#endif

static int putc(int c, FIL *fp);
static void do_print(const char *fmt, va_list argp, FIL *stream);
static void fputs(const char *s, FIL *fp);

int kputchar(int c) {
  return putc(c,STDOUT);
}

void kputs(const char *s) {
  fputs(s,STDOUT);
  return;
}

#ifdef SERIAL_OUT_SYSTEM
#define PORT 0x3f8   /* COM1 */
int is_transmit_empty() {
   return inb(PORT + 5) & 0x20;
}

void write_serial(char a) {
   while (is_transmit_empty() == 0);
    outb(PORT,a);
}
#endif

/* Parts of the following functions were adapted from Minix stdio code.
 * See LICENSE.Minix in the top-level Bear directory for the licensing
 * information for those sections.
 */
void kprintf(const char *fmt, ...) {
  va_list argp;
  
#if defined(SLB_THESIS) && defined(KERNEL) && defined(MULTICORE_PRINTING)
  if ( printer_cpu_up && (this_cpu() != PRINTER_CPU) ) {

    /* wait for the printer to consume the previous msg */
    while ( stdout_msg_idx[this_cpu()] == -1 )
      ;

    /* zero out the buffer and index where I'll write the message. */
    kmemset(stdout_msg_arr[this_cpu()], 0, STDOUT_MSG_LEN);
    stdout_msg_idx[this_cpu()] = 0;
  }
#endif  

  va_start(argp, fmt);
  
  do_print(fmt, argp, STDOUT);

  va_end(argp);

#if defined(SLB_THESIS) && defined(KERNEL) && defined(MULTICORE_PRINTING)
  /* if this is the printing core, we're done. */
  if ( !printer_cpu_up || (this_cpu() == PRINTER_CPU) ) 
    return;

  /* mark my index as -1 so that the printer knows to print me. */
  stdout_msg_idx[this_cpu()] = -1;

  /* for other cores, we need to tell the printing core about our message. */
  send_ipi(PRINTER_CPU, PRINTING_IPI);
  while(lapic_read(APIC_ICRL) & APIC_DELIVS);
#endif

  return;
}


#if defined(SLB_THESIS) && defined(KERNEL) && defined(MULTICORE_PRINTING)

void printer_cpu_init(void) {

  printer_cpu_up = 1;

  return;
}

void printer_cpu_service(unsigned int vec, void *varg) {

  int src_cpu;

  /* print all pending messages */
  while ( 1 ) {

    /* find a cpu with a pending msg */
    for ( src_cpu = 0; src_cpu < 8; src_cpu++)
      if ( stdout_msg_idx[src_cpu] < 0 ) 
	break;
    
    /* print the statement if we found a source */
    if ( src_cpu != 8 )  {
      kprintf("Core %d: %s", src_cpu, stdout_msg_arr[src_cpu]);
      stdout_msg_idx[src_cpu] = 0;
    }
    else 
      break;
  }
  
  /* acknowledge IPI */
  lapic_eoi();

  return;
}

#endif

static int putc(int c, FIL *fp) {
  
  if (fp == STDOUT) {
    if((c) == '\n'){
#ifdef SERIAL_OUT_SYSTEM

#if defined(SLB_THESIS) && defined(KERNEL) && defined(MULTICORE_PRINTING)
      if ( printer_cpu_up && (this_cpu() != PRINTER_CPU) ) 
	stdout_msg_arr[this_cpu()][stdout_msg_idx[this_cpu()]++] = (char)c;
      else
#endif
      write_serial(0xA);
#endif	/* SERIAL_OUT_SYSTEM */
#ifndef REMOTE
#ifdef VGA_OUT_SYSTEM
      vga_newline();
#endif	/* VGA_OUT_SYSTEM */
#endif	/* REMOTE */
    }
    else if((c) == '\t') {
#ifdef SERIAL_OUT_SYSTEM

#if defined(SLB_THESIS) && defined(KERNEL) && defined(MULTICORE_PRINTING)
      if ( printer_cpu_up && (this_cpu() != PRINTER_CPU) ) 
	stdout_msg_arr[this_cpu()][stdout_msg_idx[this_cpu()]++] = (char)c;
      else
#endif
      write_serial(0x9);
#endif	/* SERIAL_OUT_SYSTEM */
#ifndef REMOTE
#ifdef VGA_OUT_SYSTEM
      vga_tabline();
#endif	/* VGA_OUT_SYSTEM */
#endif	/* REMOTE */
    }
    else {
#ifdef SERIAL_OUT_SYSTEM

#if defined(SLB_THESIS) && defined(KERNEL) && defined(MULTICORE_PRINTING)
      if ( printer_cpu_up && (this_cpu() != PRINTER_CPU) ) 
	stdout_msg_arr[this_cpu()][stdout_msg_idx[this_cpu()]++] = (char)c;
      else
#endif
	write_serial((char)c);

#endif	/* SERIAL_OUT_SYSTEM */
#ifndef REMOTE
#ifdef VGA_OUT_SYSTEM
      vga_drawc((char)c, STD_VGA_COLOR);
      vga_advance(1);
#endif	/* VGA_OUT_SYSTEM */
#endif	/* REMOTE */
    }
  }
  return c;
}

static void fputs(const char *s, FIL *fp) {
  char *p = (char *)s;
  int c;
  
  while((c = *p++) != '\0')
    putc(c,fp);

  putc('\n',fp);
  
  return;
}

static void do_print(const char *fmt, va_list argp, FIL *stream) {
  int c;                                        /* Next character in fmt */
  int d;
  uint64_t u;                                   /* Hold number argument */
  int base;                                     /* Base of number arg */
  int negative;                                 /* Print minus sign */
  static char x2c[] = "0123456789ABCDEF";       /* Number converstion table */
  char ascii[8*sizeof(long)/3 + 2];             /* String for ASCII number */
  char *s;                                      /* String to be printed */
  int min_len;
  int position;

  position=0;			/* position on line */
  while((c = *fmt++) != 0) {
    if(c == '%') {
      negative = 0;                         /* (Re)initialize */
      s = NULL;                             /* (Re)initialize */
      switch(c = *fmt++) {
	/* Known keys are %d, %u, %x, %s */
      case 'd':
	d = va_arg(argp, int32_t);
	if(d < 0) {
	  negative = 1;
	  u = -d;
	} else {
	  u = d;
	}
	base = 10;
	min_len = 0;
	break;
      case 'u':
	u = va_arg(argp, uint64_t);
	base = 10;
	min_len = 0;
	break;
      case 'x':
	u = va_arg(argp, uint64_t);
	base = 0x10;
	min_len = 2; /* ST: was 0 ?? */
	break;
      case 'X':
	u = va_arg(argp, uint64_t);
	base = 0x10;
	min_len = 2;
	break;
      case 's':
	s = va_arg(argp, char *);
	if(s == NULL)
	  s = "(null)";
	break;
      default:
	s = "%?";
	s[1] = c;
      }
      /* Assume a number if no string is set. Convert to ASCII. */
      if(s == NULL) {
	s = ascii + sizeof(ascii) - 1;
	*s = 0;
	do {
	  *--s = x2c[(u % base)];       /* work backwards */
	  min_len--;
	} while(((u /= base) > 0) || (min_len > 0));
      }
      /* This is where the actual output for format "%key" is done. */
      if(negative) {
	putc('-', stream);
	position++;
      }
      while(*s != '\0') {
	putc(*s++, stream);
	position++;
      }
    } 
    else {			/* not formatting an arg */
      if(c=='\t') {
	if((position%TABSTOP)==0) { /* on a tabstop move off it */
	  putc(' ',stream);
	  position++;
	}
	while((position%TABSTOP)!=0) { /* keep going till next */
	  putc(' ',stream);
	  position++;
	}
      }
      else {      /* Print and continue. */
	putc(c, stream);
	position++;
      }
    }
  }
}

#ifdef SLB_THESIS 
#ifdef MULTICORE_PRINTING
void tkprintf(const char *fmt, ...) {
  va_list argp;

  va_start(argp, fmt);
  
  tdo_print(fmt, argp, STDOUT);

  va_end(argp);

  return;
}


static void tdo_print(const char *fmt, va_list argp, FIL *stream) {
  int c;                                        /* Next character in fmt */
  int d;
  uint64_t u;                                   /* Hold number argument */
  int base;                                     /* Base of number arg */
  int negative;                                 /* Print minus sign */
  static char x2c[] = "0123456789ABCDEF";       /* Number converstion table */
  char ascii[8*sizeof(long)/3 + 2];             /* String for ASCII number */
  char *s;                                      /* String to be printed */
  int min_len;
  int position;

  position=0;			/* position on line */
  while((c = *fmt++) != 0) {
    if(c == '%') {
      negative = 0;                         /* (Re)initialize */
      s = NULL;                             /* (Re)initialize */
      switch(c = *fmt++) {
	/* Known keys are %d, %u, %x, %s */
      case 'd':
	d = va_arg(argp, int32_t);
	if(d < 0) {
	  negative = 1;
	  u = -d;
	} else {
	  u = d;
	}
	base = 10;
	min_len = 0;
	break;
      case 'u':
	u = va_arg(argp, uint64_t);
	base = 10;
	min_len = 0;
	break;
      case 'x':
	u = va_arg(argp, uint64_t);
	base = 0x10;
	min_len = 2; /* ST: was 0 ?? */
	break;
      case 'X':
	u = va_arg(argp, uint64_t);
	base = 0x10;
	min_len = 2;
	break;
      case 's':
	s = va_arg(argp, char *);
	if(s == NULL)
	  s = "(null)";
	break;
      default:
	s = "%?";
	s[1] = c;
      }
      /* Assume a number if no string is set. Convert to ASCII. */
      if(s == NULL) {
	s = ascii + sizeof(ascii) - 1;
	*s = 0;
	do {
	  *--s = x2c[(u % base)];       /* work backwards */
	  min_len--;
	} while(((u /= base) > 0) || (min_len > 0));
      }
      /* This is where the actual output for format "%key" is done. */
      if(negative) {
	tputc('-', stream);
	position++;
      }
      while(*s != '\0') {
	tputc(*s++, stream);
	position++;
      }
    } 
    else {			/* not formatting an arg */
      if(c=='\t') {
	if((position%TABSTOP)==0) { /* on a tabstop move off it */
	  tputc(' ',stream);
	  position++;
	}
	while((position%TABSTOP)!=0) { /* keep going till next */
	  tputc(' ',stream);
	  position++;
	}
      }
      else {      /* Print and continue. */
	tputc(c, stream);
	position++;
      }
    }
  }
}


static int tputc(int c, FIL *fp) {
  
  if (fp == STDOUT) {
    if((c) == '\n'){
#ifdef SERIAL_OUT_SYSTEM

      write_serial(0xA);
#endif	/* SERIAL_OUT_SYSTEM */
#ifndef REMOTE
#ifdef VGA_OUT_SYSTEM
      vga_newline();
#endif	/* VGA_OUT_SYSTEM */
#endif	/* REMOTE */
    }
    else if((c) == '\t') {
#ifdef SERIAL_OUT_SYSTEM

      write_serial(0x9);
#endif	/* SERIAL_OUT_SYSTEM */
#ifndef REMOTE
#ifdef VGA_OUT_SYSTEM
      vga_tabline();
#endif	/* VGA_OUT_SYSTEM */
#endif	/* REMOTE */
    }
    else {
#ifdef SERIAL_OUT_SYSTEM

	write_serial((char)c);

#endif	/* SERIAL_OUT_SYSTEM */
#ifndef REMOTE
#ifdef VGA_OUT_SYSTEM
      vga_drawc((char)c, STD_VGA_COLOR);
      vga_advance(1);
#endif	/* VGA_OUT_SYSTEM */
#endif	/* REMOTE */
    }
  }
  return c;
}

#endif
#endif

#endif /* ifndef USER */
