#ifdef SLB_THESIS

#ifndef __asmp_h_
#define __asmp_h_

#define KERNEL_CORE 2
#define TEMP_PINNED_PROC_CORE 4

void kernel_syscall_handler(unsigned int vec, void *varg);

void vmem_bridge(Proc_t *proc);


#define USR_SC_RBUF_ADDR ((uint64_t)idx2vaddr(10,0,0,2))
#define USR_PES_ADDR ((uint64_t) idx2vaddr(10,0,0,1))
#define USR_MCONTEXT_ADDR ((uint64_t)idx2vaddr(10,0,0,0))

#endif

#endif
