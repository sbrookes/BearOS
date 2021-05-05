/*
 * kernel.c
 *
 * Description: The kernel is dedicated to handling interrupts and
 * passing messages.  Every interrupt gets turned into a message,
 * which is sent to one of the PL=1 driver tasks, which then takes
 * appropriate action once it's received.  There are also a number of
 * system calls that the kernel services directly.  These system calls
 * are used by the PL=1 driver tasks to facilitate communication with
 * the hardware.
 */
#include <pio.h>
#include <kstdio.h>
#include <kstring.h>
#include <kvmem.h>
#include <kqueue.h>
#include <constants.h>
#include <disklabel.h>
#include <interrupts.h>
#include <kmalloc.h>
#include <memory.h>
#include <ramio.h>
#include <procman.h>
#include <asm_subroutines.h>
#include <ktime.h>
#include <syscall.h>
#include <ksyscall.h>
#include <kernel.h>
#include <ktimer.h>
#include <pci.h>
#include <elf_loader.h>
#include <elf.h>
#include <file_abstraction.h>
#include <kvmem.h>
#include <kwait.h>
#include <kmsg.h>
#include <msg_types.h>
#include <proc.h>
#include <ksched.h>
#include <kvcall.h>
#include <pes.h>
#include <fatfs.h>
#include <ff_const.h>
#include <elf.h>
#include <ke1000.h>
#include <tsc.h>
#include <sbin/kbd.h>
#include <random.h>
#include <vk.h>
#include <network.h>

#include <kload.h>

//smp related includes
#include <smp.h>
#include <apic.h>
#include <semaphore.h>
#include <acpi.h>

#ifdef SLB_THESIS
#include <asmp.h>
#endif

#ifdef DRIVER_REFRESH
#include <refresh.h>
#endif

#ifdef DIVERSITY
#include <diversity.h>
#endif

#ifdef HYPV_SHIM
#include <vmx.h>
#include <vmx_utils.h>
#endif

/* PRIVATE DECLARATIONS */

#ifdef SLB_THESIS
uint64_t val_phys_addr;
uint64_t *val_virt_addr;

#ifdef MULTICORE_PRINTING
void printing_core_kernel_proc(volatile uint64_t arg);
#endif
#endif

/* Entry Point */
void kentry() __attribute__ ((section ("startpoint"))); /* Entry point */

/* Private Functions */
static void kinit();		     /* Init core kernel */
static void add_all_intr_handlers(); /* Init interrupt handlers */
static int  systick_search_hooks(void *ep, const void *kp);
static void systick_run_hooks(void *hp);

#ifdef HYPV_SHIM
static Proc_t *shim_p;
static void install_shim();
static int is_nic(void *ep, const void *keyp);
#endif

#ifdef ENABLE_SMP
static void ap_core_init();
#endif

static void print_debug(char * name){
#ifdef DEBUG
  kprintf("[Kernel] %s \n", name);
#endif
}

/* Private Variables */
void *systick_hooks;
#ifdef DIVERSITY
static void print_hash(char *file, unsigned char hash[]);
#endif

/*	New fix for Dell Bios issues involving spurious intterupt generation.
 *	this is a flip flop. on the Dell 9010s amd 9020s the bios is configured
 *	in a way that causes a spurious interrupt to be fired on boot for the
 *	I/O APIC. Additionally, on the 9020s the bios causes each key press to
 *	result in 4 interrupts instead of 2, which generates double output 
 *      to the
 *	the screen. Of course VMWARE has none of these issues thus complicating
 *	the solution across now three architectures (RMD)
 */
#ifndef VMWARE
int flip __attribute__ ((section (".bss")));
#endif

#ifdef ENABLE_SMP
int bsp_ready_kernel __attribute__ ((section (".bss"))); /* BSP booted */
#endif

#ifdef KPLT
extern uint64_t kplt;
#endif

/* PUBLIC FUNCTIONS */
/*
 * kentry(): The main entry point of the kernel.  Initializes virutal
 * memory, then gets the kernel stack out of the lower memspace.
 */
void kentry() {

  uint64_t frame_array_address, heap_start;
  
  /* Kernel initialization should not be interrupted */
  asm volatile("cli");

  kprintf("[Kernel] Starting\n");

#if ENABLE_SMP
  if(bsp_ready_kernel == 1) {
    asm volatile("movq %0,%%rsp  \n\t"
		 "movq %%rsp,%%rbp   \n\t"
		 "movq %1,%%rax      \n\t"
		 "jmp *%%rax"
		 ::"p"(system_stack_base),
		  "p"(ap_core_init));
  }
#ifdef DEBUG_SMP
  else
    kprintf("[SMP] Boot Stap Core Started\n");
#endif

  bsp_ready_kernel = 1;
#endif

  scan_rsdp();

  /*Enable global pages for the kernel */
#ifndef KPLT
  write_cr4((read_cr4() | (1<<7)));
#else
  write_cr4((read_cr4() & ~(1<<7)));
#endif
  /*
   * We need to get ourselves all the way into the higher half.
   * Hypervisor took care of most of it; just a few things left to do.
   */
 
  /* frame_array_address is in rcx; heap_start in rdx */
  asm volatile("movq %%r10, %0" : "=r"(frame_array_address));
  asm volatile("movq %%r11, %0" : "=r"(heap_start));

  asm volatile("movq %%r12, %0" : "=r"(system_stack_base));

#ifdef KPLT
  asm volatile("movq %%r13, %0" : "=r"(kplt));
#endif

  kvmem_init( frame_array_address, heap_start );

  if(!kheapcheck(0,"kernel entry"))
    kpanic("Error: Invalid heap after memory setup.");

  /* Test the VK module */
  vmem_alloc( idx2vaddr(333,0,0,0), PAGE_SIZE, 
	      PG_RW | PG_NX | PG_GLOBAL );

  vk_heap = idx2vaddr(333, 0,0,0);

  vkinit(vk_heap, VK_HEAP_NUM_PAGES, PAGE_SIZE);

#ifdef VK_DEBUG
  vkshowmap(vk_heap);
#endif

#ifdef DEMO 
  kputs("\nKernel diversity check:");
  kprintf("    address of kentry        : 0x%x\n", kentry);
  kprintf("    address of load_elf_proc : 0x%x\n", load_elf_proc);
  kprintf("    address of stack var     : 0x%x\n", &frame_array_address);
  kprintf("    address of kprintf       : 0x%x\n", kprintf);
  kprintf("    address of kputs         : 0x%x\n", kputs);
  kprintf("    address of diversify     : 0x%x\n", diversify);
  kprintf("    address of lapic_eoi     : 0x%x\n", lapic_eoi);
  kprintf("    address of kernel heap   : 0x%x\n", frame_array_address);
#endif

  /* initialize the kernel! */
  kinit();
  kpanic("kinit tried to return");
}


Proc_t* gp;

#ifdef ENABLE_SMP
static void ap_core_init() {
  asm volatile("movq %0,%%rsp" : :"r"(temp_stack));
#ifdef DEBUG_SMP
  kprintf("[SMP] core %d initializing\n",this_cpu());
#endif
  pes_init();
  init_new_gdt();
  lapic_init();
  ap_lidt();		 /* loads idt and then loads new tss into gdt*/
#ifdef DEBUG_SMP
  kprintf("[SMP] application core init done\n");
#endif
  set_running();
  kprintf("#");

  acquire_lock(sem_kernel);
  ksched_yield();

#ifdef SLB_THESIS

  /* we have to send core 2 into userspace first with that ksched_yield() 
     because before entering and then leaving userspace, it doesnt have its 
     own kernel stack. */

#ifdef MULTICORE_PRINTING
  /* send printing core to print */
  if ( this_cpu() == PRINTER_CPU ) 
    printing_core_kernel_proc(0);
#endif

  /* send core 2 into its inf loop */
  if ( this_cpu() == KERNEL_CORE ) {
    asm volatile ("sti");

    load_elf_proc_remote("t12");
    load_elf_proc_remote("t13");

    
    
#if 0
    int i1, i2, i3, i4, i5;
 
    kprintf("paging struct for remote proc\n");
    for ( i1 = 0; i1 < 512; i1++ ) {
      if ( ! *(uint64_t*)remote_PML4TE2vaddr(test_ring0_proc, i1) ) 
	continue;

      kprintf("  %d -> 0x%x\n", i1, *(uint64_t*)remote_PML4TE2vaddr(test_ring0_proc, i1));

      for ( i2 = 0; i2 < 512; i2++ ) {
	if ( !*(uint64_t*)remote_PDPTE2vaddr(test_ring0_proc, i1, i2) )
	  continue;

	kprintf("    %d -> 0x%x\n", i2, *(uint64_t*)remote_PDPTE2vaddr(test_ring0_proc, i1, i2));

	for ( i3 = 0; i3 < 512; i3++ ) {
	  if ( !*(uint64_t*)remote_PDE2vaddr(test_ring0_proc, i1, i2, i3) )
	    continue;

	  kprintf("      %d -> 0x%x\n", i3, *(uint64_t*)remote_PDE2vaddr(test_ring0_proc, i1, i2, i3));
	  
	  for ( i4 = 0; i4 < 512; i4++ ) {
	    if ( !*(uint64_t*)remote_PTE2vaddr(test_ring0_proc, i1, i2, i3, i4) )
	      continue;

	    kprintf("        %d -> 0x%x\n", i4, *(uint64_t*)remote_PTE2vaddr(test_ring0_proc, i1, i2, i3, i4));
	    continue;
	    for ( i5 = 0; i5 < 512; i5++ )
	      if ( i1 == 7 ) 
		continue;
	      else 
		kprintf("          0x%x: 0x%x\n", i5*8, *((uint64_t*)remote_idx2vaddr(test_ring0_proc, i1, i2, i3, i4) + i5) );
	  }
	}
      }
    }
#endif

    if ( load_ring0_idle_procs() )
      kpanic("failed to load ring0 idle procs\n");

    /* todo: special scheduling for the idleprocs... in other words, reconcile 
       these with the "checkin" scheduling mechanism */
    Proc_t *first_proc = ring0_idleps[TEMP_PINNED_PROC_CORE];
    Proc_t *next_proc = ksched_get_remote();

    *(uint64_t*)remote2vaddr(first_proc, first_proc->usr_next_proc_cr3) = (uint64_t)next_proc->cr3_target;
    ring0_proc_ptr_array[TEMP_PINNED_PROC_CORE] = first_proc;
    ring0_nproc_ptr_array[TEMP_PINNED_PROC_CORE] = next_proc;
    
    release_lock(sem_kernel);
    
    while ( 1 );
  }
  else if ( this_cpu() == TEMP_PINNED_PROC_CORE ) {

    release_lock(sem_kernel);

    while ( !ring0_proc_ptr_array[TEMP_PINNED_PROC_CORE] ) ;
    
    /* TODO: no longer need to pass mc_addr to this fn */
    kernel_to_ring0_proc(
		     ring0_proc_ptr_array[TEMP_PINNED_PROC_CORE]->cr3_target, 
		     ring0_proc_ptr_array[TEMP_PINNED_PROC_CORE]->usr_gdtp, 
		     ring0_proc_ptr_array[TEMP_PINNED_PROC_CORE]->usr_idtp);
    
    kpanic("jump to ring0 proc failed!\n");
  }

#endif

  kernel_exit();

  gp = ksched_schedule();

  restore_kernel_proc(gp);
}
#endif

/*
 * kinit(): Carries out core kernel initialization.
 */
static void kinit() {

  /*Arbitrary unused interrupt set. Will be updated by ke1000.c*/
  network_interrupt_mask = 50; 
  struct tm boot_time;

#ifdef KMALLOC_TRACKING
  kmalloc_clear_sites();
#endif

#ifdef VMEM_TRACKING
  vmem_clear_sites();
#endif

#ifdef ENABLE_SMP
  /* get a semaphore */
  sem_kernel = create_semaphore( 0 );
  acquire_lock(sem_kernel);
#endif /* ENABLE_SMP */

  Scan_ACPI();

  /* The GDT holds pointers to the code,data,stack,+other segments.
   * These never change.  However, it also contains a pointer to the
   * TSS.  Each kernel must have a unique TSS, and hence each must
   * have a unique gdt.  Note - the TSS gets changed in
   * init_interrupts not here.
   */
  print_debug("GDT initialization");
  init_new_gdt();

  /* Initialize all data structures and all hardware necessary to
   * trigger and handle interrupts.  Includes IDT, IST, PIC, and PIT.
   * Note - does not actually register any interrupt handler routines.
   */
  print_debug("Interrupt Handler initialization");
  intr_init();

  /* Register all our IRQ/Syscall handlers. */
  /* FIXME: Add a handler for FP exceptions */
  /* FIXME: check for SSE support; set flags */
  add_all_intr_handlers();

  print_debug("APIC initialization");
  /*use this address if we're virtualizing in the hypervisor
   *eventually we have to vmcall for it from hypv */

  if( attach_page(lapicaddr,lapicaddr, KMEM_IO_FLAGS | PG_GLOBAL) )
    kpanic("[SMP] failed to add page location of APIC");
  lapic_init();

  print_debug("IO_APIC initialization");
  if( attach_page(ioapicaddr,ioapicaddr, KMEM_IO_FLAGS | PG_GLOBAL) )
    kpanic("[SMP] IOAPIC failed to add page location of IOAPIC");
  ioapic_init();

  /*** KERNEL MODULES ***/

  /*
   * Initialize the PCI module; this scans the PCI bus for devices.
   * Must be done before devices that use PCI (i.e. disk and NIC).
   */
  print_debug("PCI initialization");
  pci_init();

  /* Init process creation module Must be done before creating processes */
  print_debug("Proc initialization ");
  procman_init();

  /* Init the pes module so we can correctly save processor state */
  print_debug("PES initialization");
  pes_init();
  
  /* Init kwait module. Must be done before procman_init. */
  print_debug("Kwait initialization");
  kwait_init();

  /* Get the filesystem ready for use. */
  print_debug("FS initialization ");
  file_init();

  /* Initialize watchdog timer module. Must be done before networking */
  print_debug("Timer initialization ");
  ktimer_init();

  /* Initialize message-passing. Must be done before user creating procs */
  print_debug("Message Passing initialization ");
  kmsg_init();

  /* Init scheduler module. */
  print_debug("Scheduler initialization ");
  ksched_init();

  /*
   * Seed the random number generator.  Use the current tsc value; it's the
   * closest thing we're gonna get to a random seed!
   */
  print_debug("Random Number initialization ");
  srandom(readtsc());
  /* Initialize the refresh module. */
#ifdef DRIVER_REFRESH
  print_debug("Refresh initialization ");
  refresh_init();
#endif /* DRIVER_REFRESH */

#ifdef ENABLE_SMP
  smp_boot_aps();
#endif

  /*** SYSTEM PROCESSES ***/
#ifndef REMOTE
  kload_daemon("vgad",VGAD, PL_0 /* IO_FLAGS_ENABLED */);	/* VGAD = -5 */
  kload_daemon("kbd",KBD, PL_0 /* IO_FLAGS_ENABLED */);	/* KBD = -6 */
  ioapicenable(1, 0); /*enables the keyboard interrupt*/
#endif /* not REMOTE */
#ifndef STANDALONE
  kload_daemon("netd",NETD, PL_3 /* IO_FLAGS_DISABLED */);	/* NETD = -7 */

  /* Start the network, if any network interfaces are present.
   * This code relies on interrupts, klog,kmsg, timers, and the existence
   * of the netd and sysd processes; DON'T MOVE THIS UP IN KINIT.
   */
  print_debug("Network Drivers initialization");
  network_init();		/* E1000D = -8 */
#ifdef BEARNFS
  kload_daemon("nfsd",NFSD, PL_3 /* IO_FLAGS_DISABLED */);	/* NFSD = -9 */
  kload_daemon("statd",STATD, PL_3 /* IO_FLAGS_DISABLED */);	/* STATD = -10 */
#endif /* BEARNFS */
#endif /* STANDALONE */

  print_debug("SYSD initialization");
  kload_daemon("sysd",SYSD, PL_3 /* IO_FLAGS_DISABLED */);	/* INITD = -11 -- tracked */
  //  kload_daemon("rmpd"); 		/* rmpd.h: RMPD = -11 */

  print_debug("PIPED Initialization\n");
  kload_daemon("piped",PIPED, PL_3 /* IO_FLAGS_DISABLED */);	/* PIPED = -12 */

  /* 
   * Load the hypervisor shim that enables execute-only
   * memory for the kernel.
   */
#ifdef HYPV_SHIM
  uint64_t stack;
  asm volatile( "movq %rsp, %rax" );
  asm volatile( "movq %%rax, %0" : "=r"(stack));

  /* Load a new kernel process, the shim_p */
  shim_p = new_kernel_proc((uint64_t)install_shim, -80085);
  ksched_add(shim_p);
#else
#ifdef XONLY_BEAR_HYPV
  kvmcall(9, NULL, NULL);
#endif
#endif	/* HYPV_SHIM */

  print_debug("Wall Clock initialization");
  init_time();
  localtime(system_time, &boot_time);

  kprintf("[Kernel] Initialization Complete");
  kprintf(" (%d:%d:%d)\n", boot_time.tm_hour-1, boot_time.tm_min, 
	  boot_time.tm_sec);

  ksched_yield();

  /** On start up ksched init will create the idle proc. the ksched yield above
      is being called by this idle proc. if idle proc is ever scheduled again 
      it will resume execution here*/
  kernel_exit();
}

/*
 * kpanic(char *): Prints error string and then halts the system.
 */
void kpanic(char *error_str) {
  /* No more interrupts. */
  asm volatile("cli");

  /* Print then halt */
  kputs("\n[Kernel] PANIC!");
  if (error_str)
    kputs(error_str);
  panic();
}

/******************************************************************************
 *********************** FILESYSTEM STUFF *************************************
 *****************************************************************************/

/*
 * is_process -- returns TRUE if processp is has pid pidp
 */
int is_process(void *processp,const void *pidp) {

  return ((Proc_t*)processp)->pid == *(int*)pidp;
}

/*
 * Do any necessary kernel cleanup here before returning to userspace. 
 * This includes invoking the scheduler to figure out what process to run
 * next. Return next proc in %rax to the assembly function that called 
 * (as of writing this comment, this function is called exclusively from 
 * assembly-land.
 */
Proc_t *kernel_exit() {
  Proc_t *p;

  lapic_eoi();

  p = ksched_get_last();

  /* Restore the virtual memory space for the process. */
  restore_user_proc(p);     /* Does not return */

  kpanic("Kernel has gone critical.");
  return p;
}

/******************************************************************************
 *************************** INTERRUPT HANDLING *******************************
 *****************************************************************************/

/******************************************************************************
 *
 * Function: systick_handler(int pid)
 *
 * Description:
 *  This function is called whenever the PIT (programmable interval timer)
 *  fires.  It updates the watchdog timer then invokes the scheduler.
 *
 *****************************************************************************/
void systick_handler(unsigned int vec, void *varg) {
  Proc_t *p;

#ifdef SLB_THESIS
  /* don't do anything for cores running kernel loops */
  if ( (this_cpu() == KERNEL_CORE)
#ifdef MULTICORE_PRINTING
       || (this_cpu() == PRINTER_CPU) 
#endif
       )
    return;

#endif

  p = ksched_get_last();

  if(p && (p->pid != IDLE_PROC) && (p->pid != -666) && (p->pid != -80085))
    ksched_add(p);

  ktimer_tick();

  /* Run hooks. */
  qapply(systick_hooks, systick_run_hooks);
  //p = ksched_schedule();
  ksched_yield();
  p = ksched_get_last();
}

/*******************************************************************************
 *
 * Function: systick_hook_add(systick_hook)
 *
 * Description:
 *  Adds a hook that is called every time the systick fires. The hook must
 *  be void and take no arguments.
 *
 ******************************************************************************/
void systick_hook_add(systick_hook hook) {
  qput(systick_hooks, hook);
}

/*******************************************************************************
 *
 * Function: systick_hook_remove(systick_hook)
 *
 * Description:
 * Removes a previously-added systick hook from the systick hook list.
 *
 ******************************************************************************/
void systick_hook_remove(systick_hook hook) {
  qremove(systick_hooks, systick_search_hooks, hook);
}

/* All that follows are the private systick functions for manipulating the
 * hook queue. */

static int systick_search_hooks(void *ep, const void *kp) {
  systick_hook element = (systick_hook)ep;
  systick_hook key = (systick_hook)kp;
  return element == key;
}

static void systick_run_hooks(void *hp) {
  systick_hook hook = (systick_hook)hp;
  hook();
}

/*******************************************************************************
 *
 * Function: interrupt(unsigned int vec, void *varg)
 *
 * Description:
 *  This function is called whenever an interrupt occurs on a device with a
 *  userland driver.  This function will translate the interrupt into a message
 *  and send it to that proc.  In order to expedite interrupt handling, this
 *  function will also mess with process scheduling, in an attempt to get the
 *  driver process to run sooner.
 *
 * Arguments:
 *    vec -- the interrupt number
 *    varg -- the user process assigned to this interrupt
 *
 ******************************************************************************/
void interrupt(unsigned int vec, void *varg) {
  pid_t pid;
  Message_t msg;
  Hwint_msg_t hwmsg;
  Proc_t *dst_p;
  int code, val;
  pid = (pid_t)(intptr_t)varg;

  dst_p = pid_to_addr(pid);
  if (dst_p == NULL) {
    kprintf("ERROR: Interrupt registered to %d but process %d does not exist\n", pid, pid);
    return;
  }

  /*Architecture Support for Keyboard driver (RMD)*/
#ifndef VMWARE
  if(vec == 0x21 ){
    code = inb(0x60);       /* get the scan code for the key struck */
#if 0
    // per https://forum.osdev.org/viewtopic.php?f=1&t=40001 ... not needed
    val = inb(0x64);         /* strobe the keyboard to ack the char  */
    outb(0x64, val | 0x80);  /* strobe the bit high                  */
    outb(0x64, val);           /* now strobe it low                    */
#endif
#ifdef DELL_9020_KBD_FIX
    flip^=0x1;
    if(flip == 1)
      kernel_exit();
#else
    if(flip == 0){
      flip++;
      kernel_exit();
    }
#endif /*DELL_9020_KBD_FIX */
  }
#endif /*VMWARE*/

  msg.src = HARDWARE;		/* src process -2 in usr/include/syspid.h */
  msg.dst = dst_p->pid;		/* dst is who its going to */
  msg.len = sizeof(Hwint_msg_t);
  msg.status = NULL;
  msg.buf = &hwmsg;
  hwmsg.type = HARD_INT;	/* msg type 0 in /usr/include syscall.h */

  /*
   * HACK: Mask out the card interrupts until they're handled by the
   * userspace
   * drivers.  The card has a horrible habit of spamming this interrupt, and
   * without doing this the kernel will spend all its time in this very
   * function.
   */
  if(vec == network_interrupt_mask)
    ioapicdisable(vec-32, 0); /*disable the network interrupt*/

  kmsg_send(&msg);
}

#ifdef SLB_THESIS 
void asmp_kernel_syscall(Message_t *mp, Proc_t *cp) {

  Systask_msg_t *msg;
  Msg_status_t status;
  int msgtype;
  int fn = mp->direction;

  if ( mp == NULL ) { /* access message */
    kprintf("Empty system call\n");
    return;
  }
  if(fn!=MSEND && fn!=MRECV) { 	/* invalid message */
    kprintf("Invalid ASMP system call\n");
    return;
  }

  if(fn==MRECV)  /* recv(frompid,msg) */
    kmsg_recv(cp, mp, mp->src);
  else {			/* fn == MSEND */
    if(mp->dst == SYS) {	/* system call? */
      msg = mp->buf;		/* get message data  */
      status.src = cp->pid; /* set up return values for msgrecv from syscall */

      status.bytes_rcvd = mp->len;
      status.msgsize_orig = mp->len;
      /*
       * NOTE: compiler generates jump table -- do not optimize
       */
      msgtype = *(int*)(mp->buf);	/* get message type */
      switch(msgtype) {	        	/* which system call? */
      case SC_FORK:
	systask_do_fork(msg,&status);
	break;
      case SC_EXEC:
	systask_do_exec(msg,&status);
	break;
      case SC_GETPID:
	systask_do_getpid(msg,&status);
	break;
      case SC_WAITPID:
	systask_do_waitpid(msg,&status);
	break;
      case SC_EXIT:
	systask_do_exit(msg,&status);
	break;
      case SC_KILL:
	systask_do_kill(msg,&status);
	break;
      case SC_USLEEP:
	systask_do_usleep(msg,&status);
	break;
      case SC_VGAMEM:
	systask_do_map_vga_mem(msg,&status);
	break;
      case SC_REBOOT:
	systask_do_reboot(msg,&status);
	break;
      case SC_UNMASK:
	systask_do_unmask_irq(msg,&status);
	break;
      case SC_EOI:
	systask_do_eoi(msg,&status);
	break;
      case SC_GETTIME:
	systask_do_gettime(msg,&status);
	break;
      case SC_UMALLOC:
	systask_do_umalloc(msg,&status);
	break;
      case SC_PCI_SET:
	systask_do_pci_set_config(msg,&status);
	break;
      case SC_POLL:
	systask_do_poll(msg,&status);
	break;
      case SC_CORE:
	systask_do_get_core(msg,&status);
	break;
      case SC_PS:
	systask_do_ps(msg,&status);
	break;
      case SC_GETSTDIO:
	systask_do_getstdio(msg,&status);
	break;
      case SC_REDIRECT:
	systask_do_redirect(msg,&status);
	break;
      case SC_SIGACT:
	systask_do_sigaction(msg,&status);
	break;
      case SC_SIGRET:
	systask_do_sigreturn(msg,&status);
	break;
      case SC_ALARM:
	systask_do_alarm(msg, &status);
	break;
#ifdef KERNEL_DEBUG
      case SC_PRINTINT:
	systask_do_kprintint(msg,&status);
	break;
      case SC_PRINTSTR:
	systask_do_kprintstr(msg,&status);
	break;
#endif
      case SC_MAP_MMIO:
	systask_do_map_mmio(msg, &status);
	break;
      case SC_MAP_DMA:
	systask_do_map_dma(msg, &status);
	break;
      case SC_MSI_EN:
	systask_do_msi(msg, &status);
	break;
      default:
	kprintf("%d: Invalid system call - %d\n",cp->pid,msgtype);
	break;
      }
    }
    else {		       /* send to a process */
      mp->src = cp->pid;       /* record sending process in message */
      kmsg_send(mp);	       /* Perform the send */
    }
  }

  return;
}
#endif

void kernel_syscall(unsigned int vec, void *varg) {
  Proc_t *cp;
  Message_t *mp;
  int *msgtype;
  Systask_msg_t *msg;
  Msg_status_t status;
  int fn;

  cp = ksched_get_last();	/* find the current process */

  if((mp = (Message_t*)cp->mc.rsi)==NULL) { /* access message */
    kprintf("%d: Empty system call\n",cp->pid);
    return;
  }
  fn = mp->direction;		/* should be send or recv */
  if(fn!=MSEND && fn!=MRECV) { 	/* invalid message */
    kprintf("%d: Invalid system call - %d\n",cp->pid,fn);
    return;
  }

  if(fn==MRECV)  /* recv(frompid,msg) */
    kmsg_recv(cp, mp, mp->src);
  else {			/* fn == MSEND */
    if(mp->dst == SYS) {	/* system call? */
      msg = mp->buf;		/* get message data  */
      status.src = cp->pid; /* set up return values for msgrecv from syscall */

      status.bytes_rcvd = mp->len;
      status.msgsize_orig = mp->len;
      /*
       * NOTE: compiler generates jump table -- do not optimize
       */
      msgtype = (int*)(mp->buf);	/* get message type */
      switch(*msgtype) {		/* which system call? */
      case SC_FORK:
	systask_do_fork(msg,&status);
	break;
      case SC_EXEC:
	systask_do_exec(msg,&status);
	break;
      case SC_GETPID:
	systask_do_getpid(msg,&status);
	break;
      case SC_WAITPID:
	systask_do_waitpid(msg,&status);
	break;
      case SC_EXIT:
	systask_do_exit(msg,&status);
	break;
      case SC_KILL:
	systask_do_kill(msg,&status);
	break;
      case SC_USLEEP:
	systask_do_usleep(msg,&status);
	break;
      case SC_VGAMEM:
	systask_do_map_vga_mem(msg,&status);
	break;
      case SC_REBOOT:
	systask_do_reboot(msg,&status);
	break;
      case SC_UNMASK:
	systask_do_unmask_irq(msg,&status);
	break;
      case SC_EOI:
	systask_do_eoi(msg,&status);
	break;
      case SC_GETTIME:
	systask_do_gettime(msg,&status);
	break;
      case SC_UMALLOC:
	systask_do_umalloc(msg,&status);
	break;
      case SC_PCI_SET:
	systask_do_pci_set_config(msg,&status);
	break;
      case SC_POLL:
	systask_do_poll(msg,&status);
	break;
      case SC_CORE:
	systask_do_get_core(msg,&status);
	break;
      case SC_PS:
	systask_do_ps(msg,&status);
	break;
      case SC_GETSTDIO:
	systask_do_getstdio(msg,&status);
	break;
      case SC_REDIRECT:
	systask_do_redirect(msg,&status);
	break;
      case SC_SIGACT:
	systask_do_sigaction(msg,&status);
	break;
      case SC_SIGRET:
	systask_do_sigreturn(msg,&status);
	break;
      case SC_ALARM:
	systask_do_alarm(msg, &status);
	break;
#ifdef KERNEL_DEBUG
      case SC_PRINTINT:
	systask_do_kprintint(msg,&status);
	break;
      case SC_PRINTSTR:
	systask_do_kprintstr(msg,&status);
	break;
#endif
      case SC_MAP_MMIO:
	systask_do_map_mmio(msg, &status);
	break;
      case SC_MAP_DMA:
	systask_do_map_dma(msg, &status);
	break;
	    case SC_MSI_EN:
	systask_do_msi(msg, &status);
	break;
      default:
	kprintf("%d: Invalid system call - %d\n",cp->pid,fn);
	break;
      }
    }
    else {		       /* send to a process */
      mp->src = cp->pid;       /* record sending process in message */
      kmsg_send(mp);	       /* Perform the send */
    }
  }
  return;
}

/* Interrupt handlers */
extern void poke_vmm();
static void add_all_intr_handlers() {

#ifndef VMWARE
  flip = 0;
#endif

  /* Initialize hook queue before the systick handler is turned on. */
  systick_hooks = qopen();

  /* Now turn on the interrupts. Args are always passed as void* */
  intr_add_handler(0x20, &systick_handler, NULL); /* APIC timer */
#ifndef REMOTE
  intr_add_handler(0x21, &interrupt, (void*)KBD); /* kbd hardware */
#endif
  intr_add_handler(0x80, &kernel_syscall, NULL);  /* system call */

#ifdef SLB_THESIS
  intr_add_handler(0xa5, &kernel_syscall_handler, NULL);
  intr_add_handler(0xa4, &kernel_syscall_handler, NULL);
  intr_add_handler(0xFF, &kernel_syscall_handler, NULL);
  intr_add_handler(0xb1, &kernel_syscall_handler, NULL);
  intr_add_handler(0xF0, &kernel_syscall_handler, NULL);
  intr_add_handler(0xc0, &kernel_syscall_handler, NULL);
  intr_add_handler(0xc1, &kernel_syscall_handler, NULL);

#if defined(MULTICORE_PRINTING)
  /* set printing interrupt handler */
  intr_add_handler(PRINTING_IPI, &printer_cpu_service, NULL);
#endif

#endif

  /* Forensics */
  intr_update_idtentry(0x7D, INTR64_ON, (uint64_t)poke_vmm); /* vmcall */
  /*
   * Set 0x81 to the syscall handler. This alternate syscall vector is
   * used by fork and exec; this makes it easy for the hypervisor to
   * see when they occur.  Technically, someone could get around this
   * by not using the library syscall, but this mechanism doesn't need
   * to be perfectly robust (it's what the hypv DOES with that info
   * that is the research part; NOT how it gets it).
   */
  intr_add_handler(0x81, &kernel_syscall, NULL); /* forensics */
}
#ifdef DIVERSITY

#define HASHPRTLEN 4
static void print_hash(char *name, unsigned char hash[]) {
  int idx;

  kprintf("[%s\tHash: ", name);
  for(idx=0; idx<32 ; idx++) {
    if(idx<HASHPRTLEN || idx>=(32-HASHPRTLEN))
      kprintf("%x", hash[idx]);
    if(idx==HASHPRTLEN) 
      kprintf(" ... ");
  }
  kprintf("]");

  return;
}
#endif

/**
 * kstart()
 * This function is called by new_proc() after the process has been loaded
 * Akin to crt0 in userland, this function gets the process started.
 */
void kstart(void) {

#ifdef KPLT
  int i;
  uint64_t fn_addr;

  kprintf("addr of \"kputs\" = 0x%x\n", kputs);
  for ( i = 2; i < 10; i++ )
    fn_addr |= (uint64_t)(*(uint8_t*)(kputs + i)) << (i - 2)*8;
  kprintf("implementation of kputs = 0x%x\n", fn_addr);

  kprintf("addr of \"load_elf_proc\" = 0x%x\n", load_elf_proc);
  for ( i = 2; i < 10; i++ )
    fn_addr |= (uint64_t)(*(uint8_t*)(load_elf_proc + i)) << (i - 2)*8;
  kprintf("implementation of load_elf_proc = 0x%x\n", fn_addr);
#endif  
  /* load_elf_proc */
  load_elf_proc();

  /* kexit() */
  kernel_exit();
}

#ifdef HYPV_SHIM

void death_handler(void) {
  uint64_t exit_reason, status;
  uint64_t vmcs_ptr;
  uint64_t gcr3;
  uint64_t grip;
  uint64_t qualification;
  uint64_t address;

  vmptrst(&vmcs_ptr);

  kprintf("vmptr = 0x%x\n", vmcs_ptr);

  vmread(VM_EXIT_REASON, &exit_reason);

  if(exit_reason & (1 << 31)){
    kputs("vm entry failure");
    exit_reason &= ~(1 << 31);
  }

  kprintf("exit reason = %d\n", exit_reason);

  vmread(VM_INSTRUCTION_ERROR, &status);
  kprintf("error field = %d\n", status);
  
  vmread(GUEST_CR3, &gcr3);
  kprintf("offending cr3 0x%x\n", gcr3);

  vmread(GUEST_RIP, &grip);
  kprintf("guest rip that died 0x%x\n", grip);

  vmread(EXIT_QUALIFICATION, &qualification);

  if(qualification & 0x1)
    kprintf("violation was EPT read\n");
  if(qualification & 0x2)
    kprintf("violation was EPT write\n");
  if(qualification & 0x4)
    kprintf("violation was EPT instruction fetch\n");
  if(qualification & 0x80)
    vmread(GUEST_LINEAR_ADDRESS, &address);

  kprintf("Linear Address access violation at %X\n", address);

  vmread(GUEST_PHYSICAL_ADDRESS, &address);

  kprintf("Physical Address access violation at %x\n", address);

  kprintf("The shim will kill you now.\n");

  asm volatile("hlt");
}

uint64_t SPECIAL_K_HACK;

#define CHECK_SHIM_FUNCTION(func, funcstr)				\
  if ( !kstrncmp((char*)ELF_SYMNAME(*sym, proc->file->strtab),          \
		 funcstr, kstrlen(funcstr)) )		       		\
    for ( addr = (uint64_t)func - ((uint64_t)func % PAGE_SIZE);		\
	  addr < (uint64_t)func + sym->st_size; addr += PAGE_SIZE )	\
      shim_pages[shim_pages_idx++] = virt2phys((void*)addr);

#define SHIM_ALLOC(addr)     	                  \
  addr = SPECIAL_K_HACK;			  \
  SPECIAL_K_HACK += PAGE_SIZE;                    \
  vmem_alloc((uint64_t*)addr, PAGE_SIZE, PG_RW);  \
  shim_pages[shim_pages_idx++] = virt2phys((void*)addr); 

Proc_t *ksched_get_next();

static void install_shim() {

  int rc, i;
  int pml4t_idx;
  int pdpt_idx;
  int pd_idx;
  int pt_idx;
  int ept_frames;
  struct page_map_level_4_table *pml4t;
  struct page_directory_pointer_table *pdpt;
  struct page_directory *pd;
  struct page_table *pt;

  uint64_t addr;
  uint64_t *shim_pages;
  uint64_t shim_pages_idx;
  uint64_t *nocache_frames;
  uint64_t nocache_frames_idx;
  uint64_t *kern_pages;
  uint64_t kern_pages_idx;
  uint64_t memory_present;
  struct memmap *chunk = (struct memmap *)MEMORY_MAP;
  uint16_t *numchunks = (uint16_t *)MEMORY_MAP_ENTRIES;
#ifdef DIVERSITY 
  struct Elf_Sym* sym;
  Proc_t *proc = ksched_get_last();
#endif
  uint64_t vmxon_region, vmxon_region_phys, vmcs_ptr, vmcs_ptr_phys, msr;
  uint64_t vmcsid, status;
  struct gdt_desc gdt;
  struct idtptr idt;
  Proc_t next_proc = *ksched_schedule();
  uint64_t grsp;

  Pci_dev_t *dev;
  uint64_t mmio_pos;
  uint64_t mmio_end;
  uint64_t flash_pos;
  uint64_t flash_end;

  shim_pages = (uint64_t*)vkmalloc(vk_heap, 12); 
  vmem_alloc(shim_pages, PAGE_SIZE*12, PG_RW | PG_NX);
  kmemset(shim_pages, 0, PAGE_SIZE * 12);
  shim_pages_idx = 0x0;

  kern_pages = (uint64_t*)vkmalloc(vk_heap, 6); 
  vmem_alloc(kern_pages, PAGE_SIZE*6, PG_RW | PG_NX);
  kmemset(kern_pages, 0, PAGE_SIZE * 6);
  kern_pages_idx = 0x0;  

  nocache_frames = (uint64_t*)vkmalloc(vk_heap, 6); 
  vmem_alloc(nocache_frames, PAGE_SIZE*6, PG_RW | PG_NX);
  kmemset(nocache_frames, 0, PAGE_SIZE * 6);
  nocache_frames_idx = 0x0;  

#ifdef DIVERSITY
  /* if we are using diversity, shim functions are loaded onto their own 
     physical frames of memory. Therefore, we can actually keep the kernel 
     from accessing their functionality. We will be maintaining a record 
     throughout of frames that the shim is using that the EPT will block the 
     kernel from entirely. We need malloc in order to keep track of the 
     frames, so we can't set up the shim's own allocator yet. Therefore, it 
     will use VK alloc first. */

  /* I need to find where the shim code was loaded */
  proc->file = alloc_elf_ctx(file_read, file_seek, file_error_check);
  proc->file->file_ctx = file_open("binaryte");

  rc = elf_load_metadata(proc->file);
  
  /* loop through in order to find anything associated with the shim */
  for(i = 0, sym = proc->file->symtab; i < proc->file->num_syms; i++, sym++) {
    
    /* here, we check look for any function that is _only_ for the shim */
    CHECK_SHIM_FUNCTION(install_shim, "install_shim");
    CHECK_SHIM_FUNCTION(death_handler, "death_handler");
  }

  /* clean up */
  file_close(proc->file->file_ctx);
  free_elf_ctx(proc->file);

#ifdef DEBUG_SHIM
  kputs("[Shim] done finding shim functions");
#endif

#endif

  /* certain frames must not be chacheable. */
  /* ioapic and apic */
  nocache_frames[nocache_frames_idx++] = 0xFEE00000;
  nocache_frames[nocache_frames_idx++] = 0xFEC00000;

  for(i = PHYS_VGA_MEM; i < 0x100000; i += 0x1000)
    nocache_frames[nocache_frames_idx++] = i;

  /* MMIO and flash for the nic */
  /* find the nic */
  dev = pci_search(&is_nic, NULL);

  mmio_pos = dev->pci_dev_bars[0].bar_base;
  mmio_end = mmio_pos + dev->pci_dev_bars[0].bar_size;
  
  flash_pos = dev->pci_dev_bars[1].bar_base;
  flash_end = flash_pos + dev->pci_dev_bars[1].bar_size;
  
#ifdef DEBUG_SHIM
  kprintf("[Hypv] Network card mmio_pos = %x\n", mmio_pos);
  kprintf("[Hypv] Network card mmio_end = %x\n", mmio_end);
  kprintf("[Hypv] Network card flash_pos = %x\n", flash_pos);
  kprintf("[Hypv] Network card flash_end = %x\n", flash_end);
#endif

  for( ; mmio_pos < mmio_end; mmio_pos += PAGE_SIZE)
    nocache_frames[nocache_frames_idx++] = mmio_pos;
    
    
  for( ; flash_pos < flash_end; flash_pos += PAGE_SIZE)
    nocache_frames[nocache_frames_idx++] = flash_pos;

   /* The shim will not use kmalloc. It will protect all of its memory from 
      the kernel. It cannot do this in the heap. So, the shim removes its 
      vitual mappings to the heap. Any attempt to kmalloc from the shim's 
      context should now cause a fault. */
  vmem_free_temp((uint64_t*)get_heap_start(), KHEAP_SIZE);
  
  flush_tlb(TLB_ALL);

  SPECIAL_K_HACK = get_heap_start();

#ifdef DEBUG_SHIM
  kputs("[Shim] freed heap mappings");
#endif

  SHIM_ALLOC(vmxon_region);
  vmxon_region_phys = virt2phys((void*)vmxon_region);

  SHIM_ALLOC(vmcs_ptr);
  vmcs_ptr_phys = virt2phys((void*)vmcs_ptr);

  /* profile the kernel to find all of its pages. */  
  for ( pml4t_idx = 0; pml4t_idx < 511; pml4t_idx++ ) {
    
    if ( !((union pt_entry*)PML4TE2vaddr(pml4t_idx))->present ) 
      continue;
    
    for ( pdpt_idx = 0; pdpt_idx < 512; pdpt_idx++ ) {
      
      if ( !((union pt_entry*)PDPTE2vaddr(pml4t_idx, pdpt_idx))->present ) 
	continue;
      
      for ( pd_idx = 0; pd_idx < 512; pd_idx++ ) {

	if ( !((union pt_entry*)PDE2vaddr(pml4t_idx, pdpt_idx, pd_idx))->present )
	  continue;
	
	for ( pt_idx = 0; pt_idx < 512; pt_idx++ ) {
	  
	  if ( !((union pt_entry*)PTE2vaddr(pml4t_idx, pdpt_idx, pd_idx, pt_idx))->present )
	    continue;
	  
	  if ( ((union page*)PTE2vaddr(pml4t_idx, pdpt_idx, pd_idx, pt_idx))->global && !((union page*)PTE2vaddr(pml4t_idx, pdpt_idx, pd_idx, pt_idx))->rw ) {
	    kern_pages[kern_pages_idx++] = TABLE2ADDR(((union page*)PTE2vaddr(pml4t_idx, pdpt_idx, pd_idx, pt_idx))->addr);
	  }
	}
      }
    }
  }

#ifdef DEBUG_SHIM
  kputs("[Shim] done finding kernel memory");
#endif

  /* find the paging structures for the shim */
  shim_pages[shim_pages_idx++] = read_cr3();
  for ( pml4t_idx = 0; pml4t_idx < 512; pml4t_idx++ ) {

    /* if no pdpt */
    if ( !((union pt_entry*)PML4TE2vaddr(pml4t_idx))->present )
      continue;
    
    /* else, extract phys address */
    shim_pages[shim_pages_idx++] = TABLE2ADDR(((union pt_entry*)PML4TE2vaddr(pml4t_idx))->addr);

    /* find all PDs linkd from here. */
    for ( pdpt_idx = 0; pdpt_idx < 512; pdpt_idx++ ) {
      
      /* if no pd */
      if ( !((union pt_entry*)PDPTE2vaddr(pml4t_idx, pdpt_idx))->present )
	continue;

      /* else, extract phys address */
      shim_pages[shim_pages_idx++] = TABLE2ADDR(((union pt_entry*)PDPTE2vaddr(pml4t_idx, pdpt_idx))->addr);

      /* find all PTs linked from here */
      for ( pd_idx = 0; pd_idx < 512; pd_idx++ ) {
	
	/* if no PT */
	if ( !((union pt_entry*)PDE2vaddr(pml4t_idx, pdpt_idx, pd_idx))->present )
	  continue;
	
	/* extract phys addr */
	shim_pages[shim_pages_idx++] = TABLE2ADDR(((union pt_entry*)PDE2vaddr(pml4t_idx, pdpt_idx, pd_idx))->addr);

	/* dont need to search frames. This is just for paging structures */
      }
    }
  }


  /* TODO TODO TODO */
  /* find shim stack pages and add them to shim_pages */


#ifdef DEBUG_SHIM
  kputs("[Shim] done finding shim paging structures");
#endif

  memory_present = chunk[(*numchunks)-1].base + chunk[(*numchunks)-1].length;

#ifdef DEBUG_SHIM
  kprintf("[Shim] found 0x%x for memory present\n", memory_present);
#endif

  /* precalcualte the number of frames I will need for the EPT. For each frame 
     that will be needed, find it and store it into the shim_pages array so 
     that they can be protected when we build the EPT. */
  ept_frames = shim_pages_idx;
  pml4t_idx = pdpt_idx = pd_idx = 0;
  pt_idx = 511;
  for ( pml4t_idx = 0; 
	(uint64_t)idx2vaddr(pml4t_idx, pdpt_idx, pd_idx, pt_idx) <= memory_present && pml4t_idx < 512;
	pml4t_idx++ ) {

    /* find pdpt */
    shim_pages[shim_pages_idx++] = get_free_frame();

    for ( pdpt_idx = 0; 
	  (uint64_t)idx2vaddr(pml4t_idx, pdpt_idx, pd_idx, pt_idx) <= memory_present && pdpt_idx < 512;
	  pdpt_idx++ ) {
      
      /* find pd */
      shim_pages[shim_pages_idx++] = get_free_frame();
      
      for ( pd_idx = 0; 
	    (uint64_t)idx2vaddr(pml4t_idx, pdpt_idx, pd_idx, pt_idx) <= memory_present && pd_idx < 512;
	    pd_idx++ ) {
	
	/* find pt */
	shim_pages[shim_pages_idx++] = get_free_frame();
      }
    }
  }

#ifdef DEBUG_SHIM
  kputs("[Shim] done preallocating shim EPT frames");
#endif

  /* build an EPT. Use frames from the ept_frames section of the shim_pages 
     array for the EPT tables. As I go through, identity map except anything 
     in the kern_pages array will be marked x-only and anything in the 
     shim_pages array will not be allowed at all. */
  pml4t_idx = pdpt_idx = pd_idx = pt_idx = 0;
  pml4t = (struct page_map_level_4_table*)SPECIAL_K_HACK;
  SPECIAL_K_HACK += PAGE_SIZE;
  attach_page((uint64_t)pml4t, shim_pages[ept_frames++], PG_RW);
  kmemset(pml4t, 0, PAGE_SIZE);

  for ( pml4t_idx = 0; 
	(uint64_t)idx2vaddr(pml4t_idx, pdpt_idx, pd_idx, pt_idx) <= memory_present && pml4t_idx < 512;
	pml4t_idx++ ) {
    
    /* get a new PDPT */
    pdpt = (struct page_directory_pointer_table*)SPECIAL_K_HACK;
    SPECIAL_K_HACK += PAGE_SIZE;
    attach_page((uint64_t)pdpt, shim_pages[ept_frames], PG_RW);
    kmemset(pdpt, 0, PAGE_SIZE);
    
    ((uint64_t*)pml4t)[pml4t_idx] = (shim_pages[ept_frames++] & ~0xfff) | 0x7;

    for ( pdpt_idx = 0; 
	  (uint64_t)idx2vaddr(pml4t_idx, pdpt_idx, pd_idx, pt_idx) <= memory_present && pdpt_idx < 512;
	  pdpt_idx++ ) {
      
      /* get a new PD */
      pd = (struct page_directory*)SPECIAL_K_HACK;
      SPECIAL_K_HACK += PAGE_SIZE;
      attach_page((uint64_t)pd, shim_pages[ept_frames], PG_RW);
      kmemset(pd, 0, PAGE_SIZE);

      /* initialize the pdpt entry */
      ((uint64_t*)pdpt)[pdpt_idx] = (shim_pages[ept_frames++] & ~0xfff) | 0x7;

      for ( pd_idx = 0; 
	    (uint64_t)idx2vaddr(pml4t_idx, pdpt_idx, pd_idx, pt_idx) <= memory_present && pd_idx < 512;
	    pd_idx++ ) {

	/* get a new PT */
	pt = (struct page_table*)SPECIAL_K_HACK;
	SPECIAL_K_HACK += PAGE_SIZE;
	attach_page((uint64_t)pt, shim_pages[ept_frames], PG_RW);
	kmemset(pt, 0, PAGE_SIZE);
	
	/* initialize the pd entry */
	((uint64_t*)pd)[pd_idx] = (shim_pages[ept_frames++] & ~0xfff) | 0x7;

	for ( pt_idx = 0; 
	      (uint64_t)idx2vaddr(pml4t_idx, pdpt_idx, pd_idx, pt_idx) <= memory_present && pt_idx < 512;
	      pt_idx++ ) {

	  /* initialize the pt entry */
	  ((uint64_t*)pt)[pt_idx] = (uint64_t)idx2vaddr(pml4t_idx, pdpt_idx, pd_idx, pt_idx) | 0x37;

	  /* strip out chaching if kernel page */
	  for ( i = 0; i < nocache_frames_idx; i++ ) {
	    if ( (uint64_t)idx2vaddr(pml4t_idx, pdpt_idx, pd_idx, pt_idx) == nocache_frames[i] ) {
	      ((uint64_t*)pt)[pt_idx] &= ~(uint64_t)0x30;
	      break;
	    }
	  }

	  /* strip out read/write permissions if kernel page */
	  for ( i = 0; i < kern_pages_idx; i++ ) {
	    if ( (uint64_t)idx2vaddr(pml4t_idx, pdpt_idx, pd_idx, pt_idx) == kern_pages[i] ) {
	      ((uint64_t*)pt)[pt_idx] &= ~(uint64_t)0x3;
	      ((uint64_t*)pt)[pt_idx] |= 0x4;
	      break;
	    }
	  }


	  /* strip out all permissions if shim page */
	  for ( i = 0; i < shim_pages_idx; i++ ) {
	    if ( (uint64_t)idx2vaddr(pml4t_idx, pdpt_idx, pd_idx, pt_idx) == shim_pages[i] ) {
	      ((uint64_t*)pt)[pt_idx] &= ~(uint64_t)0x7;
	      break;
	    }
	  }

	}
      }
    }
  }

 
#ifdef DEBUG_SHIM
  kputs("[Shim] done with building EPT");
#endif

  asm volatile("sgdt %w0" : : "m"(gdt) : "memory");
  asm volatile("sidt %0" : "=m"(idt));
 
  vmx_support_test();
  
  asm volatile("movq %%cr4,%%rax    \n\t"
               "bts $13,%%rax       \n\t"
	       "bts $7,%%rax       \n\t"
               "movq %%rax,%%cr4    \n\t"
               ::: "%rax");

  vmx_register_test();
  
  vmcsid = read_msr(IA32_VMX_BASIC);
  revid(vmcsid, vmxon_region);

#ifdef DEBUG_SHIM
  kprintf("[Shim] vmxon 0x%x\n", *(uint64_t*)vmxon_region);
#endif
  
  //vmxon
  status = vmxon(vmxon_region_phys);

#ifdef DEBUG_SHIM
  kprintf("status of vmxon = %d\n", status);
#endif

  //vmclear
  revid(vmcsid, vmcs_ptr);
  status = vmclear(vmcs_ptr_phys);

#ifdef DEBUG_SHIM
  kprintf("vmcsptr = 0x%x\n", *(uint64_t*)vmcs_ptr);
  kprintf("status of vmclear = %d\n", status);
#endif

  //vmptrload
  status = vmptrld(vmcs_ptr_phys);

  //init the vmcs
#ifdef DEBUG_SHIM
  kprintf("status vmptrld = %d\n", status);
#endif

#ifdef DEBUG_SHIM
  kprintf("vmptr_phys = 0x%x\n", vmcs_ptr_phys);
#endif

  vmwrite(VIRTUAL_PROCESSOR_ID, 1);
  vmwrite(PIN_BASED_VM_EXEC_CONTROL, (uint32_t)read_msr(IA32_VMX_PINBASED_CTLS) | (1 << PIN_NMI_EXITING));

  vmwrite(CPU_BASED_VM_EXEC_CONTROL,  ((uint32_t)read_msr(IA32_VMX_TRUE_PROCBASED_CTLS) 
				       | (1 << PROC_PRI_SECONDARY_CTRLS_ON) 
				       | (1 << PROC_PRI_USE_MSR_BITMAP)));

  vmwrite(SECONDARY_VM_EXEC_CONTROL, ((uint32_t)read_msr(IA32_VMX_PROCBASED_CTLS2) |
				      (1 << PROC_SEC_ENABLE_EPT) |
				      (1 << PROC_SEC_ENABLE_RDTSCP) |
				      (1 << PROC_SEC_ENABLE_VPID)));
  
  
#ifdef DEBUG_SHIM
  //  kprintf("physical ept pointer = 0x%x\n", virt2phys(pml4t));
#endif

  vmwrite(EPT_POINTER, (virt2phys(pml4t) | 6 | (3 << 3)));
  vmwrite(EPT_POINTER_HIGH, (virt2phys(pml4t) >> 32));
  
  //  vmwrite(EXCEPTION_BITMAP, ~(uint32_t)0);
  vmwrite(CR0_GUEST_HOST_MASK, 0);
  vmwrite(CR4_GUEST_HOST_MASK, 0);

  asm volatile("movq %%rsp, %0" : "=m"(grsp));

#ifdef DEBUG_SHIM
  kprintf("shim cr0 0x%x cr3 0x%x cr4 0x%x\n", read_cr0(), read_cr3(), read_cr4());
#endif
 /* -------- Host Processor State -------- */
  /* These shouldn't ever change from what we get after entering long mode. */
  vmwrite(HOST_CS_SELECTOR,          0x8);
  vmwrite(HOST_DS_SELECTOR,          0x10);
  vmwrite(HOST_SS_SELECTOR,          0x10);
  vmwrite(HOST_ES_SELECTOR,          0x10);
  vmwrite(HOST_FS_SELECTOR,          0x10);
  vmwrite(HOST_GS_SELECTOR,          0x10);
  vmwrite(HOST_TR_SELECTOR,          0x28);
  vmwrite(HOST_CR0,                  read_cr0());
  vmwrite(HOST_CR3,                  read_cr3());
  vmwrite(HOST_CR4,                  read_cr4() | (1 << 13) | (1 << 7));
  vmwrite(HOST_GDTR_BASE,            gdt.base);
  vmwrite(HOST_IDTR_BASE,            idt.base);
  vmwrite(HOST_RIP,                  (uint64_t)death_handler);
  vmwrite(HOST_RSP,                  system_stack_base);
  /* -------- Guest processor state. -------- */
  /* For now, these should be the same as the host. */

  vmwrite(GUEST_CS_SELECTOR, 0x8);
  vmwrite(GUEST_DS_SELECTOR, 0x10);
  vmwrite(GUEST_SS_SELECTOR, 0x10);
  vmwrite(GUEST_ES_SELECTOR, 0x10);
  vmwrite(GUEST_FS_SELECTOR, 0x10);
  vmwrite(GUEST_GS_SELECTOR, 0x10);
  vmwrite(GUEST_TR_SELECTOR,         0x28);
  vmwrite(GUEST_CS_BASE,             0);
  vmwrite(GUEST_DS_BASE,             0);
  vmwrite(GUEST_SS_BASE,             0);
  vmwrite(GUEST_ES_BASE,             0);
  vmwrite(GUEST_FS_BASE,             0);
  vmwrite(GUEST_GS_BASE,             0);
  vmwrite(GUEST_CS_LIMIT,            0xFFFFFFFF);
  vmwrite(GUEST_DS_LIMIT,            0xFFFFFFFF);
  vmwrite(GUEST_SS_LIMIT,            0xFFFFFFFF);
  vmwrite(GUEST_ES_LIMIT,            0xFFFFFFFF);
  vmwrite(GUEST_FS_LIMIT,            0xFFFFFFFF);
  vmwrite(GUEST_GS_LIMIT,            0xFFFFFFFF);
  vmwrite(GUEST_CS_AR_BYTES,         0b1010000010011011);
  vmwrite(GUEST_DS_AR_BYTES,         0b1100000010010011);
  vmwrite(GUEST_SS_AR_BYTES,         0b1100000010010011);
  vmwrite(GUEST_ES_AR_BYTES,         0b1100000010010011);
  vmwrite(GUEST_FS_AR_BYTES,         0b1100000010010011);
  vmwrite(GUEST_GS_AR_BYTES,         0b1100000010010011);
  

  vmwrite(GUEST_LDTR_SELECTOR,       0);
  vmwrite(GUEST_LDTR_BASE,           0);
  vmwrite(GUEST_LDTR_LIMIT,          0);
  vmwrite(GUEST_LDTR_AR_BYTES,       0x0082);
  
  vmwrite(GUEST_GDTR_BASE,           gdt.base);
  vmwrite(GUEST_GDTR_LIMIT,          gdt.limit);
  vmwrite(GUEST_IDTR_BASE,           idt.base);
  vmwrite(GUEST_IDTR_LIMIT,          idt.limit);
  
  
  vmwrite(GUEST_TR_BASE,             gdt.base + TSS_ENTRY_OFFSET - 0xA0);
  vmwrite(GUEST_TR_LIMIT,            0x0067);
  vmwrite(GUEST_TR_AR_BYTES,         0x108b);

#ifdef DEBUG_SHIM
  kprintf("next proc cr3 0x%x\n",next_proc.cr3_target);
  kprintf("rip 0x%x rsp 0x%x\n", next_proc.kmc.rip, next_proc.kmc.rsp);
#endif
  /* This gives the entry point to the guest! */
  vmwrite(GUEST_RIP,                 next_proc.kmc.rip);
  vmwrite(GUEST_RSP,                 next_proc.kmc.rsp);//system_stack_base);
  /* Control registers, for now, identical to host. */
  vmwrite(GUEST_CR0,                 read_cr0());// | (1 << 5) | (1 << 3));
  vmwrite(GUEST_CR3,                 (uint64_t)next_proc.cr3_target);
  vmwrite(GUEST_CR4,                 read_cr4());/* | read_msr(IA32_VMX_CR4_FIXED0)
						    & read_msr(IA32_VMX_CR4_FIXED1));*/
  /* RFLAGS sanity check. */
  vmwrite(GUEST_RFLAGS,              next_proc.kmc.eflags & ~(1 << 9));
  /* -------- VM entry/exit controls -------- */
  vmwrite(VM_ENTRY_CONTROLS,         ((uint32_t)read_msr(IA32_VMX_TRUE_ENTRY_CTLS) | (1 << 9)));
  vmwrite(VM_EXIT_CONTROLS,          ((uint32_t)read_msr(IA32_VMX_TRUE_EXIT_CTLS) | (1 << 9) | (1 | 15)));
  /* -------- Miscellania -------- */
  vmwrite(VMCS_LINK_POINTER,         ~0UL);

  /* cleanup */
  vmem_free(shim_pages, 12*PAGE_SIZE);
  vkdirty(vk_heap, shim_pages, 12*PAGE_SIZE);

  vmem_free(kern_pages, 6*PAGE_SIZE);
  vkdirty(vk_heap, kern_pages, 6*PAGE_SIZE);

  vmem_free(nocache_frames, 6*PAGE_SIZE);
  vkdirty(vk_heap, nocache_frames, 6*PAGE_SIZE);

#ifdef DEBUG_SHIM
  kputs("[Shim] launching vproc");
#endif
#if 0
  asm volatile("movq %0, %%rax \n\t"
	       "fxrstor %rax \n\t"
	       "movq %1, %%rax \n\t"
	       "movq %2, %%rbx \n\t"
	       "movq %3, %%rcx \n\t"
	       "movq %4, %%rdx \n\t"
	       "movq %5, %%rsi \n\t"
	       "movq %6, %%rdi \n\t"
	       "movq %7, %%r8 \n\t"
	       "movq %8, %%r9 \n\t"
	       "movq %9, %%r10 \n\t"
	       "movq %10, %%r11 \n\t"
	       "movq %11, %%r12 \n\t"
	       "movq %12, %%r13 \n\t"
	       "movq %13, %%r14 \n\t"
	       "movq %14, %%r15 \n\t"
	       "movq %15, %%rbp \n\t")

#endif

  asm volatile("movq %0, %%rbp" : "=m" (next_proc.kmc.rbp));

  //    restore_kernel_from_shim(&next_proc);
  asm volatile("vmlaunch");

#ifdef DEBUG_SHIM
  kputs("vmlaunch failed\n");
#endif

  vmread(VM_INSTRUCTION_ERROR, &status);

#ifdef DEBUG_SHIM
  kprintf("what field information did we screw up %d\n", status);
#endif

  death_handler();


  return;
}

static int is_nic(void *ep, const void *keyp) { 

  Pci_dev_t *dev;
  dev = (Pci_dev_t *)ep;

  if(dev->bus == 0)
    return 0;

  if( dev->vendor == PCI_VENDOR_INTEL &&
    ( dev->dev_id == 0x100E || dev->dev_id ==0x107C || dev->dev_id ==0x10D3 || 
      dev->dev_id == 0x100F || dev->dev_id == 	0x153A)){
    return 1;
  }
  return 0;
}

#endif


#ifdef SLB_THESIS
#ifdef MULTICORE_PRINTING
void printing_core_kernel_proc(volatile uint64_t arg) {

  if ( this_cpu() != PRINTER_CPU ) {
    kprintf("WTF WHY IS CPU %d here?!\n", this_cpu());
    asm volatile("hlt");
  }

  /* make sure interrupts are enabled on this core. */

  kprintf("******* About to enable multicore printing! *********\n");

  /* initialize multicore printing */
  printer_cpu_init();

  kprintf("done.\n");

  /* release the lock so that other cores can get into the kernel */
  release_lock(sem_kernel);

  /* busy wait... */
  /* TODO: In theory, this core could actually just keep doing other work with 
     no problem... */
  while (1) {
    asm volatile("sti");

    /* busy wait a while */
    for ( arg = 0xfffffff; arg; arg-- ) ;
  }

  /* never reached */
  kprintf("printing core is leaving its loop fn for some reason\n");  
  return;
}
#endif
#endif
