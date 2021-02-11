#include <kstdio.h>
#include <kstring.h>
#include <constants.h>
#include <kload.h>
#include <proc.h>
#include <memory.h>
#include <file_abstraction.h>
#include <ffconf.h>
#include <procman.h>
#include <ksched.h>
#include <elf_loader.h>
#include <apic.h>
#include <kmalloc_sites.h>

#ifdef ENABLE_SMP
#include <smp.h>
#endif

#ifdef SLB_THESIS
#include <apic.h>
#include <asmp.h>
#include <asm_subroutines.h>

extern void idle(void);          /* asm func to make CPU idle */
static int usr_kernel_interface_init(Proc_t *proc);
static int sc_rbuf_init(Proc_t *proc);
static int load_ring0_intr(Proc_t *proc);

#endif

void kload_daemon(char *dname,int dpid, int ioflags) {
  Proc_t *dp;

  kprintf("[KERNEL] %s\n", dname);
  dp = new_proc(USR_TEXT_START, ioflags ? PL_3 : PL_0, dpid,NULL);

  setprocname(dp, dname);
  dp->is_in_mem = 0;

  ksched_add(dp);		/* add it to the scheduling queue */
  
  return;
}

#ifdef SLB_THESIS
int load_elf_proc_imp(Proc_t *proc);
#endif

int load_elf_proc(void) {
#ifdef SLB_THESIS
  return load_elf_proc_imp(NULL);
}

int load_elf_proc_remote(char *procnm) {
  
  Proc_t *proc;

  proc = new_ring0_proc((uint64_t)0x1, PL_0, PROC_NONE, ksched_get_last());
  setprocname(proc, procnm);
  proc->is_in_mem = 0;  

  return load_elf_proc_imp(proc);
}

int load_elf_proc_imp(Proc_t *proc) {
#endif

  /* top of load_elf_proc IFF !SLB_THESIS */
  /* top of load_elf_proc_imp IFF SLB_THESIS*/

#ifndef SLB_THESIS
  Proc_t *proc; /* Currently running process */
#endif
  struct Elf64_Phdr *phdr;
#ifndef DIVERSITY
  uint64_t entry_point;
  struct Elf_Sym* sym;
#endif
  int rc;
  int i;

  uint64_t env_ptr, argv_ptr_array;

#ifdef DIVERSITY
  SHA256_CTX ctx;
  unsigned char hash[32];
#endif

#ifdef SLB_THESIS
  if ( !proc ) 
#endif
    proc = ksched_get_last();

  /* Open file */
  if(!(proc->is_in_mem)) {
    /* go to the RAM disk */
    proc->file = alloc_elf_ctx(file_read, file_seek, file_error_check);
    proc->file->file_ctx = file_open(proc->procnm);
    if((rc = file_error_check(proc->file->file_ctx))) {
      kprintf("[Kernel] Error opening file %s; error code %d.\n", 
	      proc->procnm, rc);
      return -1;
    }
  } else {
    /* The file has been placed into memory, provide the appropriate
     * memory I/O functions
     */
    proc->file = alloc_elf_ctx(mem_read, mem_seek, mem_error_check);
    proc->file->file_ctx = mem_open();
  }


  /* Read header; find the executable part we need to load.
   * FIXME: In the future, we may have more than one executable segment,
   * which will make the code fall down. (For example, if we ever get
   * library support). For now, we just use the first.
   */
  rc = elf_load_metadata(proc->file);

  if(rc) {
    kprintf("[kernel] Error opening file header for %s.", proc->procnm);
    return -1;
  }

  phdr = proc->file->program_headers;
  if(phdr == NULL) {
    kprintf("[kernel] Error reading file header for %s.", proc->procnm);
    return -1;
  }
  
  /* Load the code. */
  if(!(proc->is_in_mem))
    file_seek(proc->file->file_ctx, 0);
  else
    mem_seek(proc->file->file_ctx, 0);

  proc->mc.rsp = (reg_t)(phdr->p_vaddr - sizeof(uint64_t));
  proc->mc.rbp = proc->mc.rsp;

  /*set the process entry point to the value from elf */
  proc->mc.rip = proc->file->file_header.e_entry;

#ifndef DIVERSITY

  /** loop through the elf symbol table to find the sbrk_end value that is
      set in the usr.bin linker script. */
  for(i = 0, sym = proc->file->symtab; 
      i < proc->file->num_syms; 
      i++, sym++) {
    /* Make sure it's a valid diversity symbol (must be contained 
       in a valid section / have a valid section header). */

    if ( !kstrncmp((char*)ELF_SYMNAME(*sym, proc->file->strtab), 
		   "sbrk_end", kstrlen("sbrk_end") )){

      /* add the heap to the proc's memory region queue */
      add_memory_region(proc, HEAP_REGION, PG_USER | PG_RW | PG_NX, 
			sym->st_value, sym->st_value);
    }
#ifdef SLB_THESIS
    else if ( !kstrncmp((char*)ELF_SYMNAME(*sym, proc->file->strtab), 
		   "lapicaddr", kstrlen("lapicaddr") )){
      proc->usr_lapicaddr_addr = (uint64_t*)sym->st_value;
    }
    else if ( !kstrncmp((char*)ELF_SYMNAME(*sym, proc->file->strtab), 
		   "kernel_core_apicid", kstrlen("kernel_core_apicid") )){
      proc->usr_kcorenum_addr = (uint64_t*)sym->st_value;
    }
    else if ( !kstrncmp((char*)ELF_SYMNAME(*sym, proc->file->strtab), 
		   "_proc_loaded_in_ring0", kstrlen("_proc_loaded_in_ring0") )){
      proc->usr_ring0_flag = (int*)sym->st_value;
    }
    else if ( !kstrncmp((char*)ELF_SYMNAME(*sym, proc->file->strtab), 
			"_sc_rbuf_size", kstrlen("_sc_rbuf_size") )){
      proc->sc_rbuf_size = (uint64_t)sym->st_value;
    }
    else if ( !kstrncmp((char*)ELF_SYMNAME(*sym, proc->file->strtab), 
		   "_sc_rbuf_tail", kstrlen("_sc_rbuf_tail") )){
      proc->usr_sc_rbuf_tail = (uint64_t*)sym->st_value;
    }
    else if ( !kstrncmp((char*)ELF_SYMNAME(*sym, proc->file->strtab), 
		   "_sc_rbuf_head", kstrlen("_sc_rbuf_head") )){
      proc->usr_sc_rbuf_head = (uint64_t*)sym->st_value;
    }
    else if ( !kstrncmp((char*)ELF_SYMNAME(*sym, proc->file->strtab), 
		   "_sc_rbuf", kstrlen("_sc_rbuf") )){
      proc->usr_sc_rbuf = (Message_t**)sym->st_value;
    }
#endif
  }

  entry_point = elf_load_file(proc, proc->file);

  if(entry_point == MEM_FAIL) {
    kprintf("[kernel] Error loading elf file %s.\n",proc->procnm);
    /* FIXME: Clean up? */
    return -1;
  }
#ifdef SLB_THESIS
  if ( proc->ring0 )
    /** allocate the stack for the user process */
    vmem_alloc_remote(proc, (uint64_t*)((uint64_t)phdr->p_vaddr - 
			   (USR_STACK_PAGES*PAGE_SIZE)),
	       USR_STACK_PAGES*PAGE_SIZE, PG_NX | PG_RW | PG_USER);

    else
#endif
  /** allocate the stack for the user process */
  vmem_alloc((uint64_t*)((uint64_t)phdr->p_vaddr - 
			 (USR_STACK_PAGES*PAGE_SIZE)),
             USR_STACK_PAGES*PAGE_SIZE, PG_NX | PG_RW | PG_USER);

  add_memory_region(proc, STACK_REGION, PG_USER | PG_RW | PG_NX, 
		    (uint64_t)phdr->p_vaddr - (USR_STACK_PAGES*PAGE_SIZE),
		    phdr->p_vaddr);

#else

  kmemset(hash, 0, 32);
  sha256_init(&ctx);
  /* Special thing we need to do before the start of diversification: 
   * we have to create a diversity unit that represents the stack. 
   * Otherwise, the stack won't get relocated to the new memory space and 
   * the stack pointer won't get updated. Also, it won't be randomized 
   * if we don't do this. 
   */
  struct diversity_unit *stackunit = alloc_diversity_unit(NULL);
  stackunit->addr = (uint64_t)phdr->p_vaddr - (USR_STACK_PAGES*PAGE_SIZE);
  stackunit->memsz = USR_STACK_PAGES * PAGE_SIZE;
  stackunit->hdr = kmalloc_track(KLOAD_SITE, sizeof(struct Elf_Shdr));
  stackunit->hdr->sh_addralign = 16;
  list_add_tail(&proc->file->diversity_units, &stackunit->list);
  proc->file->num_diversity_units++;

  struct diversity_unit *heapunit = alloc_diversity_unit(NULL);
  heapunit->addr = (uint64_t)0x4F000000000;
  heapunit->memsz = 0x30000000;
  heapunit->hdr = kmalloc_track(KLOAD_SITE, sizeof(struct Elf_Shdr));
  heapunit->hdr->sh_addralign = PAGE_SIZE;
  list_add_tail(&proc->file->diversity_units, &heapunit->list);
  proc->file->num_diversity_units++;

  diversify(proc, &ctx);
  sha256_final(&ctx, hash);
  print_hash(proc->procnm, hash);
  kprintf(" @ %x\n",proc->mc.rip);
  kfree_track(KLOAD_SITE, stackunit->hdr);
  kfree_track(KLOAD_SITE, heapunit->hdr);
#endif

  /* Clean up. */
  if(!(proc->is_in_mem))
    file_close(proc->file->file_ctx);
  else {
    kfree_track(KLOAD_SITE,(((void*)(*(uint64_t*)BINARY_LOCATION))));
    mem_close(proc->file->file_ctx);
  }

  /* free up the elf meta data */
  free_elf_ctx(proc->file);

  proc->mc.rsp -= PAGE_SIZE;
  proc->mc.rcx = proc->mc.rsp;

#ifdef SLB_THESIS
  if ( proc->ring0 )
    env_ptr = (uint64_t)remote2vaddr(proc, proc->mc.rcx);
  else
#endif
  env_ptr = proc->mc.rcx;

  if ( proc->env ) {
    kmemcpy((void*)env_ptr, (void*)proc->env, PAGE_SIZE);

    /*fixing offsets from array in kmalloc space to a user space addrss*/
    for ( i = 0; i < proc->envc; i++ ) {
      ((uint64_t*)env_ptr)[i] -= proc->env;
      ((uint64_t*)env_ptr)[i] += (uint64_t)proc->mc.rcx;
    }
  }
  else
    kmemset((void*)env_ptr, 0, PAGE_SIZE);

  proc->mc.rdx = proc->envc;

  /* set the end to zero */
  proc->mc.rsp -= sizeof(char*);
#ifdef SLB_THESIS
  if ( proc->ring0 )
    *remote2vaddr(proc, proc->mc.rsp) = 0x0;
  else
#endif
  *(uint64_t*)proc->mc.rsp = 0x0;

  /* set up the argv array */
  /* leave space for null terminator */
  proc->mc.rsp -= sizeof(char*)*(proc->argc + 1); 
  proc->mc.rsi = proc->mc.rsp;

#ifdef SLB_THESIS
  if ( proc->ring0 )
    argv_ptr_array = (uint64_t)remote2vaddr(proc, proc->mc.rsi);
  else
#endif
  argv_ptr_array = proc->mc.rsi;

  for ( i = 0; i < proc->argc; i++ ) {
    /* Copy the string on the stack */
    proc->mc.rsp -= kstrlen(proc->argv[i]) + 1;
#ifdef SLB_THESIS
    if ( proc->ring0 )
      kstrncpy((char*)remote2vaddr(proc, proc->mc.rsp), proc->argv[i], 
	     kstrlen(proc->argv[i]) + 1);
    else
#endif
    kstrncpy((char*)(proc->mc.rsp), proc->argv[i], 
	     kstrlen(proc->argv[i]) + 1);
    *(uint64_t*)((uint64_t)argv_ptr_array + (i*sizeof(char*))) = 
      proc->mc.rsp;
  }

  proc->mc.rdi = proc->argc;                  /* Put argc in RDI */

  proc->mc.rsp -= sizeof(char*);
#ifdef SLB_THESIS
  if ( proc->ring0 )
    *remote2vaddr(proc, proc->mc.rsp) = 0x0;
  else
#endif
  *(uint64_t*)proc->mc.rsp = 0x0;
  proc->mc.rbp = proc->mc.rsp;     /* new base is after the argv stuff */

#ifdef SLB_THESIS
  
  /* need to map interrupt handling stuff into the process. */
  if ( !proc->ring0 ) 
    return 0;

  rc = usr_kernel_interface_init(proc);
  if ( rc ) 
    kpanic("failed to initialize rbuf during remote proc loading\n");

  rc = load_ring0_intr(proc);
  if ( rc ) 
    kpanic("failed to initialize interrupts during remote proc loading\n");

  /* TODO: put the proc into the scheduling queue */
  ksched_add_remote(proc);

#endif
  
  return 0;
}

#ifdef SLB_THESIS

Proc_t *ring0_idle_proc(void) {

  int rc;
  Proc_t *proc;
  uint64_t idle_fn;
  uint64_t schedule_fn;

  proc = new_ring0_proc(0x1, PL_0, IDLE_PROC, NULL);
  setprocname(proc, "IDLE");
  proc->is_in_mem = 0;

  /* TODO: make sure these magic numbers are correct, the functions might have 
     changed. Also, try to get rid of magic numbers. */

  /* map the kernel->ring0 scheduling fn... */
  schedule_fn = vmem_alloc_remote(proc, (uint64_t*)kernel_to_ring0_proc, 0x33b-0x2e0, 0x0);
  kmemcpy((void*)(schedule_fn + ((uint64_t)kernel_to_ring0_proc & 0xfff)), kernel_to_ring0_proc, 0x33b-0x2e0);

  /* set up interrupts for the process */
  rc = load_ring0_intr(proc);
  if ( rc ) 
    return 0x0;

  /* update proc state info */
  proc->mc.rsp = proc->usr_intr_stk;

  /* update stored proc structure */
  *(struct mcontext*)remote2vaddr(proc, proc->usr_mc_addr) = proc->mc;
  
  return proc;
}

int load_ring0_idle_procs(void) {
  
  int i;

  for ( i = 0; i < smp_num_cpus; i++ )
    ring0_idleps[i] = ring0_idle_proc();

  for ( i = 0; i < smp_num_cpus; i++ )
    if ( !ring0_idleps[i] )
      return -1;

  return 0;
}

static int load_ring0_intr(Proc_t *proc) {

  struct elf_ctx *ui_file;
  struct gdt_desc gdtp;
  struct idtptr idtp;

  uint64_t entry_point;
  struct Elf_Sym* sym;
  struct Elf64_Phdr *phdr;

  int rc, i;

  /* TODO TODO : Make sure that all of this code and data is marked without 
     write permission. */

  ui_file = alloc_elf_ctx(file_read, file_seek, file_error_check);
  ui_file->file_ctx = file_open("usr_intr");
  if((rc = file_error_check(ui_file->file_ctx))) {
    kprintf("[Kernel] Error opening file %s; error code %d.\n", 
	    "usr_intr", rc);
    return -1;
  }
  
  rc = elf_load_metadata(ui_file);
  if(rc) {
    kprintf("[kernel] Error opening file header for usr_intr\n");
    return -1;
  }

  phdr = ui_file->program_headers;
  if(phdr == NULL) {
    kprintf("[kernel] Error reading file header for %s.", proc->procnm);
    return -1;
  }

  file_seek(ui_file->file_ctx, 0);

  for(i = 0, sym = ui_file->symtab; 
      i < ui_file->num_syms; 
      i++, sym++) {
    /* Make sure it's a valid diversity symbol (must be contained 
       in a valid section / have a valid section header). */
    if ( !kstrncmp((char*)ELF_SYMNAME(*sym, ui_file->strtab), 
		   "usr_vec0", kstrlen("usr_vec0") )){
      proc->usr_intr_vec0 = (uint64_t)sym->st_value;
    }
    else if ( !kstrncmp((char*)ELF_SYMNAME(*sym, ui_file->strtab), 
			"_gdtp", kstrlen("_gdtp") )){
      proc->usr_gdtp = (uint64_t)sym->st_value;
    }
    else if ( !kstrncmp((char*)ELF_SYMNAME(*sym, ui_file->strtab), 
			"_idtp", kstrlen("_idtp") )){
      proc->usr_idtp = (uint64_t)sym->st_value;
    }
    else if ( !kstrncmp((char*)ELF_SYMNAME(*sym, ui_file->strtab), 
		   "usr_handler_len", kstrlen("usr_handler_len") )){
      proc->usr_handler_len = (uint64_t)sym->st_value;
    }
    else if ( !kstrncmp((char*)ELF_SYMNAME(*sym, ui_file->strtab), 
		   "_intr_handler_array", kstrlen("_intr_handler_array") )){
      proc->usr_intr_handler_array = (void(**)(uint64_t))sym->st_value;
    }
    else if ( !kstrncmp((char*)ELF_SYMNAME(*sym, ui_file->strtab), 
		   "lapicaddr", kstrlen("lapicaddr") )){
      proc->usr_intr_lapic_addr = (uint64_t) sym->st_value;
    }
    else if ( !kstrncmp((char*)ELF_SYMNAME(*sym, ui_file->strtab), 
		   "kernel_core_apicid", kstrlen("kernel_core_apicid") )){
      proc->usr_kcorenum_addr = (uint64_t*)sym->st_value;
    }
    else if ( !kstrncmp((char*)ELF_SYMNAME(*sym, ui_file->strtab), 
		   "_intr_generic_handler", kstrlen("_intr_generic_handler") )){
      proc->usr_intr_generic_handler = (uint64_t) sym->st_value;
    }
    else if ( !kstrncmp((char*)ELF_SYMNAME(*sym, ui_file->strtab), 
		   "_mcontext", kstrlen("_mcontext") )){
      proc->usr_mc_addr = (struct mcontext *) sym->st_value;
    }
    else if ( !kstrncmp((char*)ELF_SYMNAME(*sym, ui_file->strtab), 
		   "_next_proc_cr3", kstrlen("_next_proc_cr3") )){
      proc->usr_next_proc_cr3 = (uint64_t) sym->st_value;
    }
    else if ( !kstrncmp((char*)ELF_SYMNAME(*sym, ui_file->strtab), 
		   "_ring0_proc_yield", kstrlen("_ring0_proc_yield") )){
      proc->usr_schedule_fn = (uint64_t) sym->st_value;
    }
    else if ( !kstrncmp((char*)ELF_SYMNAME(*sym, ui_file->strtab), 
		   "_ring0_proc_checkin", kstrlen("_ring0_proc_checkin") )){
      proc->usr_checkin_fn = (uint64_t) sym->st_value;
    }

  }   
 
  entry_point = elf_load_file(proc, ui_file);
  
  if(entry_point == MEM_FAIL) {
    kprintf("[kernel] Error loading elf file %s.\n",proc->procnm);
    /* FIXME: Clean up? */
    return -1;
  }

  /* now initialize the shared memory interfaces between the proc/kernel */

  /* place the machine context for the proc */
  *(struct mcontext*)vmem_alloc_remote(proc, (uint64_t*)USR_MCONTEXT_ADDR, PAGE_SIZE, PG_NX | PG_RW) = proc->mc;
  /* tell the proc where it is */
  *(uint64_t*)remote2vaddr(proc, proc->usr_mc_addr) = USR_MCONTEXT_ADDR;
  /* now the kernel will use this var in terms of the proc */
  proc->usr_mc_addr = (struct mcontext *)USR_MCONTEXT_ADDR;

  /* make a mapping to the APIC */
  attach_page_remote(proc, lapicaddr, lapicaddr, KMEM_IO_FLAGS | PG_GLOBAL);

  /* stupid lapic repeat global variable hack */
  *remote2vaddr(proc, proc->usr_intr_lapic_addr) = lapicaddr;
  *remote2vaddr(proc, proc->usr_kcorenum_addr) = KERNEL_CORE;

  /* get the vector length out of the global var */
  proc->usr_handler_len = (uint64_t)*(uint16_t*)remote2vaddr(proc, proc->usr_handler_len);

  /* init the tss, gdt and idt */
  intr_init_remote(proc);
  
  /* put idtp and gdtp into proc */
  idtp.limit = (256 * sizeof(idtentry_t)) - 1;
  idtp.base = (uint64_t)proc->usr_idt_addr;
  *(struct idtptr*)remote2vaddr(proc, proc->usr_idtp) = idtp;
  
  gdtp.base = proc->gdt_base;
  gdtp.limit = proc->gdt_limit;
  *(struct gdt_desc*)remote2vaddr(proc, proc->usr_gdtp) = gdtp;

  return 0;
}

static int usr_kernel_interface_init(Proc_t *proc) {

  uint64_t *pes;

  if ( !proc->usr_lapicaddr_addr ||
       !proc->usr_kcorenum_addr  ||
       !proc->usr_ring0_flag) 
    return -1;

  /* give the user other info it needs */
  *remote2vaddr(proc, proc->usr_lapicaddr_addr) = lapicaddr;
  *remote2vaddr(proc, proc->usr_kcorenum_addr) = KERNEL_CORE;
  *remote2vaddr(proc, proc->usr_ring0_flag) = 1;

  /* make some PES space */
  pes = (uint64_t*)vmem_alloc_remote(proc, (uint64_t*)USR_PES_ADDR, PAGE_SIZE, PG_NX | PG_RW);
  kmemcpy((void*)pes, proc->kmc.sse, PAGE_SIZE);
  proc->mc.sse = (char*)USR_PES_ADDR;

  /* init ring buffer for messages */
  if ( sc_rbuf_init(proc) )
    return -2;

  return 0;
}

static int sc_rbuf_init(Proc_t *proc) {

  if ( !proc->usr_sc_rbuf      || 
       !proc->sc_rbuf_size     || 
       !proc->usr_sc_rbuf_head ||
       !proc->usr_sc_rbuf_tail  )
    return -1;

  /* place the ring buffer */
  *remote2vaddr(proc, proc->usr_sc_rbuf) = USR_SC_RBUF_ADDR;
  proc->k_sc_rbuf = (Message_t*)vmem_alloc_remote(proc, (uint64_t*)USR_SC_RBUF_ADDR, PAGE_SIZE, PG_NX);
  
  *remote2vaddr(proc, proc->sc_rbuf_size) = PAGE_SIZE/sizeof(Message_t);
  proc->sc_rbuf_size = PAGE_SIZE/sizeof(Message_t);
  
  proc->k_sc_rbuf_tail = remote2vaddr(proc, proc->usr_sc_rbuf_tail);    
  *proc->k_sc_rbuf_tail = 0;
  
  proc->k_sc_rbuf_head = remote2vaddr(proc, proc->usr_sc_rbuf_head);    
  *proc->k_sc_rbuf_head = 0;

  return 0;
}
#endif
