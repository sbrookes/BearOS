#pragma once

#ifdef KERNEL 

#include <constants.h>
#include <proc.h>

int     ksched_init    ();          /* Init module */
Proc_t *ksched_get_last();          /* Proc that ran before kernel */
Proc_t *ksched_schedule();          /* Run the scheduling algorithm */
void    ksched_block   (Proc_t *p); /* Keep given process from running */
void    ksched_unblock (Proc_t *p); /* Allow given process to run */
void    ksched_add     (Proc_t *p); /* Add proc to scheduler queue */
void    ksched_purge   (Proc_t *p); /* Purge proc from scheduler queue */
void    ksched_ps(void *rp);	    /* print blocked processes */

/* Scheduler hooks. */
typedef void(*ksched_hook)(Proc_t *);
void ksched_hook_add(ksched_hook);
void ksched_hook_remove(ksched_hook);

/* print the relations of p */
void ksched_printrelations(Proc_t *p);
/* record a process in the ps response */
void ksched_save_entry(char status,Ps_resp_t *rp,Proc_t* p); 

void ksched_yield(void);

Proc_t **proc_ptr_array;
Proc_t **idleps;                 /* For when all procs are blocked */

#ifdef SLB_THESIS
Proc_t **ring0_idleps;
Proc_t **ring0_proc_ptr_array;
Proc_t **ring0_nproc_ptr_array;
void ksched_add_remote(Proc_t *p);
Proc_t *ksched_get_remote(void);
#endif

#endif
