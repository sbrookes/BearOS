#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <syscall.h>
#include <msg.h>
#include <time.h>

int main(int argc, char *argv[]) {
#ifdef SLB_THESIS

  int i, val;
  i = val = 0;

  /* t13 lives msg. */
  send_ipi(2, 0xf0);

  while ( 1 ) {
    if ( (val++ == 500000) ) {
      kprintstr("t13 hello world!!!!!\n");
      printf("t13 hello world %d\n", (i++*4));
    }
  }

  kprintstr("back from hello worlding\n");

  while(1);

  /* never reached */

#else
  void *malloc_var;

  malloc_var = (void*)malloc(4);

  printf("Address of stack var   : %p\n", &argc);
  printf("Address of printf      : %p\n", printf);
  printf("Address of main        : %p\n", main);
  printf("Address of msgsend     : %p\n", msgsend);
  printf("Address of malloc_var  : %p\n", malloc_var);
#endif
  return EXIT_SUCCESS;
}
