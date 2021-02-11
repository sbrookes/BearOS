#pragma once
/******************************************************************************
 *
 * Filename: kernel.h
 *
 * Description: Includes panic function, kernel config macros, etc.
 *
 ******************************************************************************/

#include <constants.h>  /* For PL_x      */
#include <proc.h>       /* For Proc_t    */
#include <elf_loader.h>

/*******************************************************************************
 * DEFINES *********************************************************************
 ******************************************************************************/



/* Segments and their associated privilege level */
#define K_CODESEG (0x8  | PL_0)
#define K_DATASEG (0x10 | PL_0)
#define U_CODESEG (0x18 | PL_3)
#define U_DATASEG (0x20 | PL_3)


/*******************************************************************************
 * PUBLIC FUNCTIONS ************************************************************
 ******************************************************************************/

/* Prints the given error string and halts the system. */
void kpanic(char *);

Proc_t *kernel_exit();

/* Handles the PIT timer interrupt. */
void systick_handler(unsigned int, void*);
typedef void(*systick_hook)(void);
void systick_hook_add(systick_hook);
void systask_hook_remove(systick_hook);

/* Converts an interrupt into a message to the given process */
void interrupt(unsigned int, void*);

/* Loads a binary file into a process's memspace. */
int load_elf_proc(void); /* Get bin off of disk; load  */

/* funciton to search a queue of procs by pid. */
int is_process(void*,const void*);

/* Sets the permissions for the vgad process so it can see VGA mem */
void set_vgad_perms(Proc_t *p);

/* Sets the permissions for the kbd process so it can see kbd hardware */
void set_kbd_perms(Proc_t *p);

/* First routine to be called by new_proc to start the process */
void kstart();

#ifdef SLB_THESIS
void asmp_kernel_syscall(Message_t *mp, Proc_t *cp);
#endif
