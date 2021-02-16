/*
 * msg.c -- the message passing interface
 */

#include <swint.h>
#include <msg.h>
#ifdef SLB_THESIS
//#include <stdlib.h>
#include <ring0.h>
#endif

#ifdef SLB_THESIS
void lapic_write(uint32_t offset, uint32_t data){
  *(uint32_t *)(lapicaddr+offset) = data;
  return;
}

void send_ipi(uint8_t apicid, uint32_t int_vector){

  lapic_write(APIC_ICRH, apicid<<24);
  lapic_write(APIC_ICRL, APIC_ASSERT | int_vector);

  return;
}
#endif

/* TODO revise this */
#ifndef NULL
#define NULL ((void *)0)
#endif

static unsigned int tag_ctr;

unsigned int get_msg_tag(void) {

  if ( !tag_ctr )
    tag_ctr++;

  return tag_ctr++;
}

#ifdef SLB_THESIS
Message_t *produce_rbuf_msg(Message_t *msg) {

  uint64_t next_head;
  Message_t *ret;

  /* increment the head */
  next_head = (_sc_rbuf_head + 1) % _sc_rbuf_size;

  /* make sure there's room for the new msg */
  while ( _sc_rbuf_tail == next_head ) ;

  /* store message pointer */
  _sc_rbuf[next_head] = *msg;
  
  ret = &_sc_rbuf[next_head];

  /* increment the head */
  _sc_rbuf_head = next_head;
  
  return ret;
}
#endif

/* Send a message to another process */
int msgsend(int dst, void *buf, int buflen) {

  Message_t m;
  Message_t *rbuf_mp;

  m.direction = MSEND;
  m.dst = dst;
  m.len = buflen;
  m.buf = buf;
  m.status = NULL;

#ifdef SLB_THESIS
  if ( _proc_loaded_in_ring0 ) {

    rbuf_mp = produce_rbuf_msg(&m);
    
    send_ipi(kernel_core_apicid, 0xa5);

    /* TODO */
    /* this loop checks whether the kernel is done working on the message... 
       this exists to immitate the behavior of the smp syscall mechanism -
       the user proc does not run until the kernel is done working on the 
       msgsend. We may not need to do this waiting. When things are stable, 
       we should remove it. 
       
       in fact, removing this will mean that msg sending is truly asynchronous!
       
       Right now, if an IPI x sends, then IPI y while kernel is still handling 
       IPI x, IPI y will interrupt execution of IPI x IFF y > x.
       -> this is likely to be a problem in some cases.
       -> how to fix? cli? some apic setting? 
       -> will it matter if the interrupt handler is just queuing a message 
       rather than doing work? I think yes, it will still matter.
     
       in other words, removing this currently works only if the 
       msend ipi > than the mrecv IPI.

       TO FIX THIS: I'll want a ring buffer in usrspace so that the user can 
       make sure that the kernel is not too overwhelmed with messages. User 
       writes to ring buffer, kernel reads from it. I think with one consumer 
       and one producer, no synchronization neeeded.
       
    */
    while ( rbuf_mp->dst );

    return 0;
  }
#endif

  /* not ring0 proc */
  return swint(MSEND,&m);
}

#ifdef FORENSICS 
/* Send a message to another process (Forensics verison) */
int msgsend_1(int dst, void *buf, int buflen) {
	Message_t m;
	m.dst = dst;
	m.len = buflen;
	m.buf = buf;
	m.status = NULL;
	return swint_1(MSEND,&m);
}
#endif

/* Receive a message from another process */
int msgrecv(int src, void *buf, int buflen, Msg_status_t *status) {

  Message_t m;
  Message_t *rbuf_mp;

  m.direction = MRECV;
  m.src    = src;
  m.len    = buflen;
  m.buf    = buf;
  m.status = status;

#ifdef SLB_THESIS
  if ( _proc_loaded_in_ring0 ) {

    rbuf_mp = produce_rbuf_msg(&m);

    send_ipi(kernel_core_apicid, 0xa4);

    /* TODO */
    /* this exists partially to replicate functionality from the smp syscall 
         mechanism... see notes below. */
    while ( rbuf_mp->src );

  /*  After it does its msgrecv, the proc expects to be running with data 
        provided to it by the kernel. Its possible that we could simply loop 
	on the data we expect, waiting for the kernel to run it. However, in 
	the general case, the kernel might need to change the proc's RIP or 
	other stuff (ie signal handling). In this case, this mechanism is not 
	sufficient. Instead, we would want the application to HLT instead of 
	loop, then a kernel-controlled IPI handler in the process would do the 
	necessary state change... 

	ANOTHER OPTION --> basically do a ksched_yield, but for procs. Put a 
	commonly-located switching routine in every user proc...

	QUESTION: is there a security risk in the proc running even after it 
	does the msgrecv, whne it should have blocked?

      TODO TODO TODO
  */

    return 0;
  }
#endif 

  /* else (not ring0 proc */
  return swint(MRECV,&m);
}
