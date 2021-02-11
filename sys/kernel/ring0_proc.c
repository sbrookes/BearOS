#ifdef SLB_THESIS

#include <smp.h>
#include <asmp.h>
#include <ktime.h>
#include <ksched.h>
#include <kernel.h>
#include <kmalloc.h>
#include <procman.h>
#include <msg_types.h>
#include <interrupts.h>

/* TOPUTINTHESIS - 
   differnetiating btwn msgsend and msgrecv is kind of a bitch... the existing 
     system does it by storing a value in a register before triggering a 
     common interrupt. I cannot pass info from core-to-core in registers.
     Options
     -> use different interrupts (being used in the current prototype)
       - I use up interrupts, and since the IPI mechanism might throw them 
       away, I may need to use the interrupt space to diversify my interrupts.
       + don't need to fuck with userspace too much.
     -> embed it in the message struct 
       - message structs are fucked and hackish... I suspect that they already 
       make assumptions about the order of data... I got screwed with this 
       when implementing tagged messaging. 
       + pretty elegant
     -> provide a memory interface for passing this information specifically.
       - a bit cumbersome... 
       + don't fuck with msg structs.

   ----> luckily it is only msg->buf that we make assumptions about. Message_t 
   is flexible enough that I can just add a "direction" member to the struct 
   and put msend/mrecv there. 

   To be included in thesis as an example of how its harder to pass data in 
   this scheme. This had an easy solution, but the previous simple solution of 
   'just check the register' fails.
 */

void kernel_syscall_handler(unsigned int vec, void *varg) {

  Proc_t *proc, *nproc, *oproc;
  Message_t *mp; 
  void *buf;
  int dir;
  int success;
  int tail;

  acquire_lock(sem_kernel);

  /* TODO: eventually I think I want this to be async. In other words, the 
       syscall handler just places the message on a stack, and the kernel's 
       main code is an inf loop that does the things that this fn currently 
       does using the message */

  /* TODO: get core */
  proc = ring0_proc_ptr_array[TEMP_PINNED_PROC_CORE];

  if ( vec == 0xFF ) {
    kprintf("HOORAY THE USER INTERRUPTS ARE WORKING\n");

    lapic_eoi();
    
    release_lock(sem_kernel);
  
    return;
  }
  else if ( vec == 0xf0 ) {
    kprintf("t13 lives!\n");

    lapic_eoi();
    
    release_lock(sem_kernel);
  
    return;    
  }
  else if ( vec == 0xb1 ) {
    oproc = ring0_proc_ptr_array[TEMP_PINNED_PROC_CORE];
    proc  = ring0_nproc_ptr_array[TEMP_PINNED_PROC_CORE];
    
    //    kprintf("--> %s checking in\n", proc->procnm);

    /* put proc that just left into idle queue */
    if ( oproc->pid != IDLE_PROC )
      ksched_add_remote(oproc);

    /* replace our record for the current proc */
    ring0_proc_ptr_array[TEMP_PINNED_PROC_CORE] = proc;
    
    /* set up the next scheduling change: */
    nproc = ksched_get_remote();
    //    kprintf("nproc will be %s\n", nproc->procnm);
    ring0_nproc_ptr_array[TEMP_PINNED_PROC_CORE] = nproc;
    *(uint64_t*)remote2vaddr(proc, proc->usr_next_proc_cr3) = (uint64_t)nproc->cr3_target;

    lapic_eoi();
    
    release_lock(sem_kernel);
  
    return;    
  }
  else if ( vec == 0xc0 ) {
    kprintf("Page fault in the process\n");

    lapic_eoi();
    
    release_lock(sem_kernel);
  
    return;    
  }
  else if ( vec == 0xc1 ) {
    kprintf("GPF in the process\n");

    lapic_eoi();
    
    release_lock(sem_kernel);
  
    return;    
  }

  /* find where I'm reading */
  tail = (*proc->k_sc_rbuf_tail + 1) % proc->sc_rbuf_size;

  /* get copy of message */
  mp = kmalloc(sizeof(Message_t));
  *mp = proc->k_sc_rbuf[tail];

  /* there are 2 pointers within the message structure... the buffer and the 
     status. We have conflicting interests with how to deal with these ptrs:
     
     MSEND: want the user's send routine to be (basically) asynchronous. 
       therefore, we want to make a copy of the buffer so that the user doesnt 
       need to preserve it.
     MRECV: need to write back to the both the status and the buffer. 
       Therefore, we don't want to copy it because we'd lose the address we 
       need to use to put data where the process expects it.

     TODO: IS TOCTOU an issue for the mrecv case?

     so, we'll make a copy for MSEND, and give kernel vaddrs for user data in 
       mrecv.
  */
  dir = mp->direction;
  if ( dir == MSEND ) {
    buf = kmalloc(mp->len);
    kmemcpy(buf, remote2vaddr(proc, mp->buf), mp->len);
    mp->buf = buf;
  }
  else if ( dir == MRECV) {
    mp->buf = remote2vaddr(proc, mp->buf);
    mp->status = (Msg_status_t*)remote2vaddr(proc, mp->status);

    /* TODO: remove this when there is only 1 kernel context */
    proc->mpbuf_phys = virt2phys(mp->buf) | ((uint64_t)mp->buf & 0xfff);
    proc->mpstatus_phys = (Msg_status_t*)(virt2phys(mp->status) | ((uint64_t)mp->status & 0xfff));
    proc->scrbuf_phys = virt2phys(proc->k_sc_rbuf) | ((uint64_t)proc->k_sc_rbuf & 0xfff);
    proc->scrbuf_tail_phys = virt2phys(proc->k_sc_rbuf_tail) | ((uint64_t)proc->k_sc_rbuf_tail & 0xfff);
  }

  /* send message to syscall dispatcher */
  asmp_kernel_syscall(mp, proc);

  /* release "fake" user proc to continue running */
  if ( dir == MSEND ) { /* asmp_msgsend */

    /* tell the proc about the new tail */
    *proc->k_sc_rbuf_tail = tail;
    
    /* do a thing to let the user proc resume. See notes in asmp_msgsend: this 
       should not be necessary in the final product. TODO */
    proc->k_sc_rbuf[tail].dst = 0;
  }
  else if ( (dir == MRECV) ) { /* asmp_msgrecv */   

    /* 
       ksched_yield no longer makes sense. In order to replace the 
       ksched_yield used to implement the blocking functionality of kmsg_recv, 
       we want the kernel to simply attach the msg and unblock the proc when 
       the message the proc is waiting for is sent. Unfortunately, if the 
       kernel context of another (non-ring0) proc is the one that tries to do 
       the attaching, it needs to go through a bunch of hoops to map the 
       correct addresses into its own space. 
    */
    if ( !proc->blocked ) {
      
      /* tell the proc about the new tail */
      *proc->k_sc_rbuf_tail = tail;
      
      /* do a thing to allow the proc to resume. Due to the current loop/hack 
	 in asmp_msgrecv, this is how we do that. Later, we might send it an 
	 IPI to get the core to execute a kernel-controlled handler. TODO */
      proc->k_sc_rbuf[tail].src = 0;
    }
  }
  
  /* free the message pointer */
  if ( dir == MSEND ) 
    kfree(mp->buf);
  kfree(mp);

  lapic_eoi();

  release_lock(sem_kernel);

  return;
}

/* TODO: Make more robust... give n slots globally at boot time and find/track 
   those here... */
/* TODO: put this in a more sensible place */
void vmem_bridge(Proc_t *proc) {
  
  int i;

  if ( proc->vmem_bridge_idx > 0 ) 
    return;
  
  /* for now, just find an open PML4T and give it to the proc. */
  for ( i = 0; i < 512; i++ )
    if ( !((union pt_entry*)PML4TE2vaddr(i))->present )
      break;
  
  /* check if we found a free one */
  if ( i == 512 ) {
    kprintf("NOT ENOUGH SPACE IN THE PML4T!!\n");
    panic();
  }

  setup_table(proc->cr3_target, PML4TE2vaddr(i), PG_RW | PG_NX);

  proc->vmem_bridge_idx = i;

  return;
}

void intr_init_remote(Proc_t *proc) {

  struct gdt_desc new_gdt;
  struct gdt_desc current_gdt;

  idtentry_t *kidtp;
  uint64_t handler_addr;
  int vec, i;

  tss_t *tss_addr, *ktss_addr;
  Tssdesc_t *te;

  /* TODO: dynamic addr, not just idx2vaddr */
  uint64_t usr_gdt_addr = (uint64_t)idx2vaddr(22,0,0,0);
  uint64_t usr_idt_addr = (uint64_t)idx2vaddr(24,0,0,0);
  uint64_t usr_intr_stk = (uint64_t)idx2vaddr(26,0,0,0);

  proc->usr_idt_addr = usr_idt_addr;

  /* GDT is basically total bullshit in 64 bit mode... except for the TSS 
     entry. so, we'll just use the dummy one that we are currently using in 
     this context and replicate it  in the user's address space and update the 
     TSS entry. */
  
  /* get gdt */
  asm volatile("sgdt %w0" : : "m"(current_gdt) : "memory");

  /* allocate space in user's proc */
  new_gdt.base = vmem_alloc_remote(proc, (uint64_t*)usr_gdt_addr, current_gdt.limit+1, PG_RW);
  
  /* write new gdt */
  kmemcpy((void*)new_gdt.base, (void*)current_gdt.base, current_gdt.limit + 1);
  new_gdt.limit = current_gdt.limit;
  
  /* give a stack for interrupt processing */
  vmem_alloc_remote(proc, (uint64_t*)usr_intr_stk, PAGE_SIZE*4, PG_RW | PG_NX);
  usr_intr_stk += (PAGE_SIZE*4)-sizeof(uint64_t);
  proc->usr_intr_stk = usr_intr_stk;

  /* build a tss */
  tss_addr = (tss_t*)(usr_gdt_addr + current_gdt.limit + 1);
  ktss_addr = (tss_t*)remote2vaddr(proc, tss_addr);
  kmemset(ktss_addr, 0, TSS_SIZE);

  /* Write TSS so that all interrupts will run on stk */
  ktss_addr = (tss_t *)((uint64_t)(ktss_addr) + 4);
  for(i=0;i<12;i++) {
    if ((i == 3) || (i == 11)) {
      (ktss_addr+i)->rsp_low  = 0x0;
      (ktss_addr+i)->rsp_high = 0x0;
    } else {
      (ktss_addr+i)->rsp_low  = (uint32_t)(usr_intr_stk & 0xFFFFFFFF);
      (ktss_addr+i)->rsp_high = (uint32_t)((usr_intr_stk >> 32) & 0xFFFFFFFF);
    }
  }
  // Index 12: Bits 0-15 reserved; 16-31 = offset to IO permission bitmap
  // IO perm. map is outside of the segment, meaning all perms granted
  (ktss_addr+12)->rsp_low = 0x68 << 16;

  /* update TSS entry in GDT */
  /* overwrite the entry to point to the new blank tss */
  te = (Tssdesc_t*)(new_gdt.base + TSS_ENTRY_OFFSET);
  te->c2 = (uint8_t)(((uint64_t)tss_addr) & 0xFF);
  te->c3 = (uint8_t)((((uint64_t)tss_addr) >> 8) & 0xFF);
  te->c4 = (uint8_t)((((uint64_t)tss_addr) >> 16) & 0xFF);
  te->c7 = (uint8_t)((((uint64_t)tss_addr) >> 24) & 0xFF);
  te->upper_addr = (uint32_t)((((uint64_t)tss_addr) >> 32) & 0xFFFFFFFF);
  te->zeros = 0x0;

  /* Update type, just in case something has made it
     "busy" instead of "available" */
  te->c5 = (uint8_t)0x89;

  /* copy the newly constructed gdt description reg into proc struct */
  new_gdt.base = usr_gdt_addr;
  proc->gdt_base = new_gdt.base;
  proc->gdt_limit = new_gdt.limit;

  /* build an idt for the proc. */
  kidtp = (idtentry_t*)vmem_alloc_remote(proc, (uint64_t*)usr_idt_addr, sizeof(idtentry_t)*256, PG_RW);
  kmemset(kidtp, 0, sizeof(idtentry_t)*256);

  /* populate all the idt entries */
  handler_addr = proc->usr_intr_vec0;      
  for ( vec = 0; vec < 256; vec++, handler_addr += proc->usr_handler_len ) {
    (kidtp+vec)->type = INTR64_ON;
    (kidtp+vec)->selector = 0x08;
    (kidtp+vec)->ist = 0x1;
    (kidtp+vec)->base_low = (uint16_t)(handler_addr & 0xffff);
    (kidtp+vec)->base_mid = (uint16_t)((handler_addr >> 16) & 0xffff);
    (kidtp+vec)->base_high = (uint32_t)((handler_addr >> 32) & ~(uint32_t)0);
  }

  /* populate the handler array */
  proc->usr_intr_handler_array = (void(**)(uint64_t))remote2vaddr(proc, proc->usr_intr_handler_array);
  for ( vec = 0; vec < 256; vec++ ) {
    if ( vec == 0xb1 ) 
      proc->usr_intr_handler_array[vec] = (void(*)(uint64_t))proc->usr_checkin_fn;
    else if ( vec == 0x20 ) {
      proc->usr_intr_handler_array[vec] = (void(*)(uint64_t))proc->usr_schedule_fn;     
    }
    else
      proc->usr_intr_handler_array[vec] = (void(*)(uint64_t))proc->usr_intr_generic_handler;
  }

  return;
}

#endif
