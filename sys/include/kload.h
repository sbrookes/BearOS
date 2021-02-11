
#include <stdint.h>

#ifdef SLB_THESIS
int load_elf_proc_remote(char *procnm);
int load_ring0_idle_procs(void);
#endif

int load_elf_proc(void);
void kload_daemon(char *dname,int dpid, int ioflags);
