/*
 * kmsg.c -- the message system is built on two hash tables:
 * waitingq -- all processes suspended waiting for messages, hashed on 
 *    RECIEVER pid
 * msgq -- all messages held for receiving processes, hashed on recievers pid,
 *    and searched using both the reciever and sender pid.
 *
 */
#include <khash.h>
#include <constants.h>
#include <kstdio.h>
#include <stdint.h>
#include <kstring.h>
#include <kmalloc.h>
#include <kmsg.h>
#include <kqueue.h>
#include <khash.h>
#include <proc.h>
#include <ksched.h>
#include <kernel.h>
#include <procman.h>

/* 20131212 JMD: Added so system calls can be managed directly from within kmsg handling */
#include <ksyscall.h>
#include <syscall.h>

/* PRIVATE DECLARATIONS */

static void *msgq;  /* hash table of messages waiting for a process */
static void *waitingq; /* hash table of processes waiting for a message */

static int is_msg(void *msgp,const void *vmhp);
static int is_msg_tag(void *msgp,const void *vmhp);
static int is_waiting_for(void *msgp,const void *vmhp);
static int is_waiting_for_tag(void *msgp,const void *vmhp);
static void kmsg_printproc(void *resp,void *ep);

#define HASHTABLESIZE 10
/* PUBLIC FUNCTIONS */


/*
 * kmsg_init() -- create hash tables and init everything necessary for 
 *   msg-passing
 */
int kmsg_init() {
  msgq = hopen(HASHTABLESIZE);
  waitingq = hopen(HASHTABLESIZE);
  return 0;
}

/*
 * kmsg_purge -- clear a process out and restart any process waiting on it.
 *  Returns 1 if pid was removed; returns 0 otherwise.
 */
int kmsg_purge(Proc_t *p) {  
  /* Restart processes waiting on this proc 
   *  FIXME: Can't do this :(
   *  Clear out the proc 
   */
  p = (Proc_t*)hremove(waitingq, is_process, (const char*)(&(p->pid)), sizeof(int));
  return (p != NULL);
}

void print_msgq(void * msg){

  kprintf("msg->buf 0x%x msg->len 0x%x dest %d src %d\n",((Message_t*)msg)->buf,((Message_t*)msg)->len,
                                                            ((Message_t*)msg)->dst,((Message_t*)msg)->src);
  return;
}

void print_waitq(void * p){

  kprintf("waitingq pid %d\n", ((Proc_t*)p)->pid);
  return;
}

/*
 * kmsg_send -- called by handle_syscall() and hardware interrupt handlers.
 */
void kmsg_send(Message_t *mp) {
  Message_t *newmsgp;
  MsgHeader mh;
  /*	Msg_status_t status; */
  Proc_t *p;
  int type;

  int(*search_fn)(void *,const void *);  
  
  search_fn = is_waiting_for;
  
  /* look to see if receiving process is waiting for the message */
  mh.destpid = mp->dst;
  mh.srcpid = mp->src;
   
   /* allocate kernel space for msg */
  newmsgp=(Message_t*)kmalloc_track(KMSG_SITE,sizeof(Message_t));
  newmsgp->buf = kmalloc_track(KMSG_SITE,mp->len);
  if ((newmsgp == NULL) || (newmsgp->buf == NULL))
    kprintf("ERROR: Couldn't kmalloc Message_t\n");
  
  /* Copy msg into kernel */
  newmsgp->src = mp->src;
  newmsgp->dst = mp->dst;
  newmsgp->len = mp->len;
  kmemcpy(newmsgp->buf, mp->buf, mp->len);
  
  /* put it in the message system under the senders pid */
  hput(msgq, (void*)newmsgp, (const char*)(&(mp->dst)), sizeof(mp->dst));
   
  /* mp is a pointer to the message we want to send */
  type = ((int*)(mp->buf))[0];
  if ( (type == SC_KILL || type == SC_SIGACT || 
	type == SC_GETSTDIO || type == SC_WAITPID) && mh.srcpid == SYS) {
    mh.tag = ((unsigned int*)(mp->buf))[1];
    search_fn = is_waiting_for_tag;
  }

  /* look in hash table under the destination pid, but search using both src and dest */
  if((p=(Proc_t*)hremove(waitingq, search_fn, (const char*)(&mh), sizeof(int)))!=NULL) {
    if (mp->dst != p->pid) {
      kpanic("HORRIBLE ERROR in kmsg_send");
    }

#ifdef SLB_THESIS
    if ( !p->ring0 ) {
#endif
      p->recvp = NULL;         /* Set this to NULL (impt for fork)        */
      p->recvfrom = PROC_NONE; /* Set to Non-existent pid (impt for fork) */

      /* wake up the process */
      if ( !(p->status & SIG_STOPPED) )
	ksched_unblock(p);
      else {
	update_proc_status(p,0,SIG_STOPPED);
	update_proc_status(p,0,0); /* mark as reported */
      }
#ifdef SLB_THESIS
    }
    else {
      p->blocked = 0;
      p->recvp = newmsgp;

      //      kprintf("message for blocked ring0 proc\n");

      /* TODO : need to build new mappings bc the kernel context executing 
	        this is almost certainly not the one on the proper kernel 
		core. this should be simplified once we have just 1 kernel 
		core. */
      uint64_t mpbuf_virt = vkmalloc(vk_heap, 1);
      Msg_status_t *mpstatus_virt = (Msg_status_t*)vkmalloc(vk_heap, 1);
      uint64_t scrbuf_virt = vkmalloc(vk_heap, 1);
      uint64_t scrbuf_tail_virt = vkmalloc(vk_heap, 1);
      
      //      kprintf("attaching pages\n");
      
      attach_page_dup(mpbuf_virt, p->mpbuf_phys & ~0xfff, PG_RW);
      attach_page_dup(mpstatus_virt, (uint64_t)p->mpstatus_phys & ~0xfff, PG_RW);
      attach_page_dup(scrbuf_virt, p->scrbuf_phys & ~0xfff, PG_RW);
      attach_page_dup(scrbuf_tail_virt, p->scrbuf_tail_phys & ~0xfff, PG_RW);

      //      kprintf("recovering offsets \n");

      mpbuf_virt |= (p->mpbuf_phys & 0xfff);
      mpstatus_virt = (Msg_status_t*)((uint64_t)mpstatus_virt | ((uint64_t)p->mpstatus_phys & 0xfff));
      scrbuf_virt |= (p->scrbuf_phys & 0xfff);
      scrbuf_tail_virt |= (p->scrbuf_tail_phys & 0xfff);

      //      kprintf("  mpbuf_virt = 0x%x\n", mpbuf_virt);
      //      kprintf("  mpstatus_virt = 0x%x\n", mpstatus_virt);
      //      kprintf("  scrbuf_virt = 0x%x\n", scrbuf_virt);
      //      kprintf("  scrbuf_tail_virt = 0x%x\n", scrbuf_tail_virt);

      /* find where I'm reading */
      int tail = (*(uint64_t*)scrbuf_tail_virt + 1) % p->sc_rbuf_size;

      //      kprintf("got tail = %d\n", tail);

      /* attach the message */
      /* deliver it by attaching to process */
      kmemcpy((void*)mpbuf_virt, p->recvp->buf, p->recvp->len);   /* Copy buf */

      //      kprintf("attached message\n");

      mpstatus_virt->src = p->recvp->src;                /* Update status */
      mpstatus_virt->bytes_rcvd = p->recvp->len;
      mpstatus_virt->msgsize_orig = p->recvp->len;

      /* free kernel message */
      kfree_track(KMSG_SITE,p->recvp->buf);
      kfree_track(KMSG_SITE,p->recvp);

      p->recvp = NULL;         /* Set this to NULL (impt for fork)        */
      p->recvfrom = PROC_NONE; /* Set to Non-existent pid (impt for fork) */

      /* tell the proc about the new tail */
      *(uint64_t*)scrbuf_tail_virt = tail;

      /* do a thing to allow the proc to resume. Due to the current loop/hack 
	 in asmp_msgrecv, this is how we do that. Later, we might send it an 
	 IPI to get the core to execute a kernel-controlled handler. TODO */
      ((Message_t*)scrbuf_virt)[tail].src = 0;

      vkdirty(vk_heap, (vkpage_t*)(mpbuf_virt & ~0xfff), PAGE_SIZE);
      vkdirty(vk_heap, (vkpage_t*)((uint64_t)mpstatus_virt & ~0xfff), PAGE_SIZE);
      vkdirty(vk_heap, (vkpage_t*)(scrbuf_virt & ~0xfff), PAGE_SIZE);
      vkdirty(vk_heap, (vkpage_t*)(scrbuf_tail_virt & ~0xfff), PAGE_SIZE);
      vkfreedirty(vk_heap);
      
      //      kprintf("done in kmsg send\n");
    }
#endif

  }
  return;
}

int kmsg_recv(Proc_t *p, Message_t *mp, int from) {
  Message_t *newmsgp;
  MsgHeader mh;
  int rc, type;
  unsigned int tag;

  int(*search_fn)(void *,const void *);

  search_fn = is_msg;

  /* look to see if sender sent a message  */
  mh.destpid=p->pid;
  mh.srcpid=from;
  
  /* mp is a pointer to the message we want to send */
  type = ((int*)(mp->buf))[0];
  if ( (type == SC_KILL || type == SC_SIGACT || 
        type == SC_GETSTDIO || type == SC_WAITPID) && mh.srcpid == SYS) {
    mh.tag = tag = ((unsigned int*)(mp->buf))[1];
    search_fn = is_msg_tag;
  }

  while(1) {
    /* look in hash table under the destination pid, but search using both src 
       and dest */
    if((newmsgp=(Message_t*)hremove(msgq, search_fn, (const char*)(&(mh)), sizeof(int)))!=NULL) {
      if ((newmsgp->dst != p->pid) || ((newmsgp->src != from) && (from != ANY))) {
        kprintf("ERROR kmsg_recv msg->dst %d != %d; msg->src %d != %d\n",
  	      newmsgp->dst, p->pid, newmsgp->src, from);
        kpanic("kmsg recv failed");
      }
      
      /* deliver it by attaching to process */
      kmemcpy(mp->buf, newmsgp->buf, mp->len < newmsgp->len ? mp->len : newmsgp->len );   /* Copy buf */

      mp->status->src = newmsgp->src;                /* Update status */
      mp->status->bytes_rcvd = mp->len < newmsgp->len ? mp->len : newmsgp->len;
      mp->status->msgsize_orig = newmsgp->len;

      kfree_track(KMSG_SITE,newmsgp->buf);
      kfree_track(KMSG_SITE,newmsgp);
      
      /* Message was delivered */
      rc = 1;
      break;
    }
    else { /* recv executed before a send */
      
      /* signify to process there is no message yet */
      p->recvp = mp;
      p->recvfrom = from;
      p->search_tag = tag;

      /* suspend the process under receivers pid */
      hput(waitingq,(void*)p, (const char*)(&(p->pid)), sizeof(p->pid));
      
      /* Message was not delivered */
      rc = 0;

      update_proc_status(p,0,STOPPED);
#ifdef SLB_THESIS
      if ( p->ring0 ) {
	p->blocked = 1;
	break;
      }
      else
#endif      
      ksched_yield();
    }
  }
 
  return rc;
}

void kmsg_ps(void *resp) {
  happly2(waitingq,resp,kmsg_printproc);
}

#define TABSTOP 8

static void kmsg_printproc(void *resp,void *ep) {
  Proc_t *p;
  Ps_resp_t *rp;

  p=(Proc_t*)ep;
  rp=(Ps_resp_t*)resp;
  ksched_save_entry('S',rp,p);
  if(kstrlen(p->procnm)>=TABSTOP) 	/* use one less tab */
    kprintf("S  %d\t%s\t",p->pid,p->procnm);
  else
    kprintf("S  %d\t%s\t\t",p->pid,p->procnm);
  ksched_printrelations(p);
}

/*
 * is_msg -- is an element of the hash table a message that is addressed to the
 * reveiver and is from either ANY process or the process designated in the
 * recieve call ie. recv(frompid, message) or recv(ANY, message).
 */
static int is_msg(void *msgp,const void *vmhp) {
  MsgHeader *mhp;
  Message_t* mp;
  
  /* NOTE: First coerce the arguments to be correct types */
  mhp = (MsgHeader*)vmhp;
  mp  = (Message_t*)msgp;
  
  /* mp is the message we aer checking if it fits */
  /* mhp is the struct we're using to search */

  return (((mhp->destpid) == mp->dst) && 
	  (((mhp->srcpid) == ANY) || ((mhp->srcpid) == (mp->src))));
}

static int is_msg_tag(void *msgp,const void *vmhp) {
  MsgHeader *mhp;
  Message_t* mp;
  
  /* NOTE: First coerce the arguments to be correct types */
  mhp = (MsgHeader*)vmhp;
  mp  = (Message_t*)msgp;
  
  /* mp is the message we aer checking if it fits */
  /* mhp is the struct we're using to search */

  return (((mhp->destpid) == mp->dst) && 
	  (((mhp->srcpid) == ANY) || ((mhp->srcpid) == (mp->src))) &&
	  (mhp->tag == ((unsigned int*)(mp->buf))[1]));
}

static int is_waiting_for(void *vp,const void *vmhp) {
  MsgHeader *mhp;
  Proc_t *p;
  
  mhp = (MsgHeader*)vmhp;	
  p   = (Proc_t*)vp;
  
  return ((p->pid == mhp->destpid) &&     /* Destination is correct, AND     */
	  ((p->recvfrom == ANY) ||        /*  Destination looking for any OR */
	   (p->recvfrom == mhp->srcpid)));/*  Destination looking for pid x  */
}

static int is_waiting_for_tag(void *vp,const void *vmhp) {
  MsgHeader *mhp;
  Proc_t *p;
  
  mhp = (MsgHeader*)vmhp;	
  p   = (Proc_t*)vp;
  
  return ((p->pid == mhp->destpid) &&       /* Destination is correct, AND   */
	  ((p->recvfrom == ANY) ||         /* Destination looking for any OR */
	   (p->recvfrom == mhp->srcpid)) && /* Destination looking for pid x */
	  (p->search_tag == mhp->tag));
}
