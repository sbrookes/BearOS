# asm_interrupts.S
# Contains the interrupt-handling assembly code

#include <asm_linkage.h>
#include <constants.h>
#include <mregs.h>


	.extern intr_invoke_handler
#ifdef KERNEL
  .extern kernel_exit
  .extern ksched_get_last
#ifdef ENABLE_SMP
  .extern interrupt_release_lock
  .extern interrupt_acquire_lock
#endif
#endif
  .extern print_exception_info_one
	.extern print_exception_info_two


#ifdef HYPV
	.extern lapic_eoi
	.extern systick_hypv_handler
	.extern keyboard_hypv_handler
	.extern network_hypv_handler
	.extern vtd_fault_handler
#endif
	
	.text # Is this right?

.section .note.GNU-stack,"",%progbits

######### MACRO DEFINITIONS ##########

# This macro currently does nothing :(
# Leaving it here in case I ever return to the problem of where to keep
# the current process pointer
#define CURR_PROC_OFFSET 40 /* Processor pushes 40 bytes onto non-exception stack */

# This macro copies the pointer in PROC_ARRAY into target_reg.
#   The processor pushes 40 bytes of data onto the stack when
# a non-exception interrupt occurs in ia-32e mode.  We then 
# pushed on an additional 8. FIXME: +16 instead.
#   Minix puts a pointer to the currently-running process at the
# top of the stack.  With alignment being what it is on x86-64, we've
# been having trouble with that.  So we just put it at a fixed place
# in memory, PROC_ARRAY.
#  FIXME: Cannot be called with target_reg = %rbx

.macro POINTER_SAVE_CONTEXT
    pushq %rax 
    pushq %rcx 
    pushq  %rdx 
    pushq  %rbx 
    pushq  %rsi 
    pushq  %rdi 
    pushq  %r8  
    pushq  %r9  
    pushq  %r10
    pushq  %r11
    pushq  %r12
    pushq  %r13
    pushq  %r14
    pushq  %r15
    pushq  %rsp
.endm

#Restore the general purpose registers
.macro POINTER_RESTORE_CONTEXT
    popq  %rsp
    popq  %r15 
    popq  %r14   
    popq  %r13 
    popq  %r12   
    popq  %r11 
    popq  %r10   
    popq  %r9  
    popq  %r8    
    popq  %rdi 
    popq  %rsi 
    popq  %rbx 
    popq  %rdx 
    popq  %rcx 
    popq  %rax 
.endm

#This assumes that the address of the proc struct is already in %rbp.
.macro SAVE_GP_REGS 
	movq %rax, AXREG(%rbp)    
	movq %rbx, BXREG(%rbp)    
	movq %rcx, CXREG(%rbp)    
	movq %rdx, DXREG(%rbp)    
	movq %rsi, SIREG(%rbp)    
	movq %rdi, DIREG(%rbp)    
	movq %r8, R8REG(%rbp)     
	movq %r9, R9REG(%rbp)     
	movq %r10, R10REG(%rbp)   
	movq %r11, R11REG(%rbp)   
	movq %r12, R12REG(%rbp)   
	movq %r13, R13REG(%rbp)   
	movq %r14, R14REG(%rbp)   
	movq %r15, R15REG(%rbp)
.endm

# This assumes that the address of the proc struct is already in %rbp.
.macro SAVE_CTRL_REGS 
	movq 8(%rsp), %r11       
	movq %r11, PCREG(%rbp)  
	movq 16(%rsp), %r11      
	movq %r11, CSREG(%rbp)  
	movq 24(%rsp), %r11     
	movq %r11, EFLREG(%rbp) 
	movq 32(%rsp), %r11     
	movq %r11, SPREG(%rbp)  
	movq 40(%rsp), %r11     
	movq %r11, SSREG(%rbp)
.endm

# Saves the FPU/MMX/SSE Registers.
.macro SAVE_SSE_REGS        
	movq FXDATA(%rbp), %r11 
	fxsaveq (%r11)
.endm
	
# Saves all the state we're keeping into the proc struct.
.macro SAVE_CONTEXT        
	pushq %rbp            
#ifdef KERNEL 
  POINTER_SAVE_CONTEXT
#ifdef ENABLE_SMP
  RELCALL(interrupt_acquire_lock)
#endif
  RELCALL(ksched_get_last)
  movq    %rax, %rbp
  POINTER_RESTORE_CONTEXT 
#endif  
	SAVE_GP_REGS           
	popq %r11              
	movq %r11, BPREG(%rbp) 
	SAVE_CTRL_REGS         
	SAVE_SSE_REGS
.endm

# Restores the control registers.
.macro RESTORE_CTRL_REGS    
	movq SSREG(%rbp), %rax  
	pushq %rax              
	movq SPREG(%rbp), %rax  
	pushq %rax              
	movq EFLREG(%rbp), %rax 
	pushq %rax              
	movq CSREG(%rbp), %rax  
	pushq %rax              
	movq PCREG(%rbp), %rax  
	pushq %rax              
  #invlpg (%rax)  #sk TODO pretty certain we do not need this anymore
  ## FIXME: MOVE THIS INVLPG SOMEWHERE ELSE
.endm

# Restores the General-Purpose registers.
.macro RESTORE_GP_REGS      
	movq AXREG(%rbp), %rax  
	movq CXREG(%rbp), %rcx  
	movq DXREG(%rbp), %rdx  
	movq BXREG(%rbp), %rbx  
	movq SIREG(%rbp), %rsi  
	movq DIREG(%rbp), %rdi  
	movq R8REG(%rbp), %r8   
	movq R9REG(%rbp), %r9   
	movq R10REG(%rbp), %r10 
	movq R11REG(%rbp), %r11 
	movq R12REG(%rbp), %r12 
	movq R13REG(%rbp), %r13 
	movq R14REG(%rbp), %r14 
	movq R15REG(%rbp), %r15 
	movq BPREG(%rbp), %rbp
.endm

# Restores the FPU/MMX/SSE registers.
.macro RESTORE_SSE_REGS     
	movq FXDATA(%rbp), %r11 
	fxrstor (%r11)
.endm

 
 #Save the general purpose regs in the hypervisor 
.macro HYPV_SAVE_CONTEXT 
	pushq %rax  
	pushq %rcx  
	pushq  %rdx  
	pushq  %rbx  
	pushq  %rsi  
	pushq  %rdi  
	pushq  %r8   
	pushq  %r9   
	pushq  %r10 
	pushq  %r11 
	pushq  %r12 
	pushq  %r13 
	pushq  %r14 
	pushq  %r15 
	pushq  %rbp
	pushq  %rsp
.endm

#Restore the general purpose registers 
.macro HYPV_RESTORE_CONTEXT 
	popq  %rsp
	popq	%rbp  
	popq 	%r15  
	popq  %r14	
	popq 	%r13  
	popq  %r12	
	popq 	%r11  
	popq  %r10	
	popq 	%r9   
	popq  %r8 	
	popq  %rdi  
	popq  %rsi  
	popq  %rbx  
	popq  %rdx  
	popq  %rcx  
	popq  %rax  
.endm

##########################  END OF MACROS #####################################


######################### SAVE KERNEL CONTEXT #################################

#ifdef KERNEL
ENTRY(save_kernel_context)
# save the rbp on the stack
  pushq %rbp       

# save the rax register because it will be clobbered shortely
  pushq %rax

# call our helper function that returns the pointer to the last
# proc that was run. This pointer is found in the proc_ptr_array 
  RELCALL(ksched_get_last)

# the function above returned this pointer in rax; move it into rbp
  movq    %rax, %rbp

# restore the clobbered rax
  popq %rax

# rbp contains a pointer to the proc structure. the first 168 bytes of that
# structure contain the user machine context. The next 168 bytes contain the 
# kernel context we want to save.
# (RMD) I wrote this in a way I understand assebmly. We are moving down the 
# pointer in rbp by 8 bytes at a time in accordance with Intel x86-64 assembly
# another way of doing this without seeing the numbers is by looking at the 
# save gp regs funtion above that is a macro that hides these direct indicies
# from view.
# IMPORTANT if the kernel machine context moves this will break
  movq %rax, 168(%rbp)    
  movq %rbx, 176(%rbp)    
  movq %rcx, 184(%rbp)    
  movq %rdx, 192(%rbp)    
  movq %rsi, 200(%rbp)    
  movq %rdi, 208(%rbp)    
  movq %r8,  216(%rbp)     
  movq %r9,  224(%rbp)     
  movq %r10, 232(%rbp)   
  movq %r11, 240(%rbp)   
  movq %r12, 248(%rbp)   
  movq %r13, 256(%rbp)   
  movq %r14, 264(%rbp)   
  movq %r15, 272(%rbp)

  movq %cs, %rax
  movq %rax, 288(%rbp)  #we know the kernel code segment

  pushfq                 #pushes the eflags on the stack
  popq  296(%rbp)         #dump them into the proc_t contect location 
 
  movq %ss, %rax
  movq %rax, 312(%rbp)  #we also know the kernel stack segment

  movq 328(%rbp), %r11   #load the pointer for the fx reg into rbp 
  fxsaveq (%r11)         #dref the pointer and load the value of the fx there  

# pushq %rbx          
# lea (%rip), %rbx       #loads the current instruction pointer
# movq %rbx, 280(%rbp)   #intermediate step becasue immediate to reg is a no-no
# popq %rbx             
  
# movq %rdi, 280(%rbp)   #rdi is the argument which has our passed in RIP

  popq %rax              #fetch the previous rbp from the stack
  movq %rax, 320(%rbp)   #save the base pointer value
  movq %rax, %rbp        #restore the original rbp value

 retq

SET_SIZE(save_kernel_context)

ENTRY(restore_kernel_proc)

  movq 328(%rdi), %r11   #load the pointer for the fx reg into r11
  fxrstorq (%r11)         #restore fx register

  movq 312(%rdi), %rax
  movq %rax, %ss    
    
  movq 296(%rdi), %r11 
 # pushq %r11
 # popfq
  movq 304(%rdi), %rsp   
  movq 320(%rdi), %rbp

  movq 168(%rdi), %rax
  movq 176(%rdi), %rbx
  movq 184(%rdi), %rcx
  movq 192(%rdi), %rdx
  movq 200(%rdi), %rsi
  movq 216(%rdi), %r8
  movq 224(%rdi), %r9
  movq 232(%rdi), %r10
  movq 240(%rdi), %r11
  movq 248(%rdi), %r12
  movq 256(%rdi), %r13
  movq 264(%rdi), %r14
  movq 272(%rdi), %r15

  movq 336(%rdi), %rax
  movq %rax, %cr3
  
  jmpq *280(%rdi)

SET_SIZE(restore_kernel_proc)

#ifdef SLB_THESIS
ENTRY(kernel_to_ring0_proc)

  # first, switch to the process' cr3 target
  movq %rdi, %cr3 # first arg (rdi) is the phys cr3
	
  lgdt (%rsi)
  mov $0x28, %ax
  ltr %ax
  lidt (%rdx)

ring0_idle:
	sti
	hlt
	jmp ring0_idle


	# set stack pointer
  movq SPREG(%rdi), %rsp
	hlt

  jmpq *PCREG(%rdi)

# i dont think we're changing SS from kernel to ring0 proc.
#  movq SSREG(%rdi), %rax
#  movq %rax, %ss    
	
SET_SIZE(kernel_to_ring0_proc)
#endif

#ifdef HYPV_SHIM
ENTRY(restore_kernel_from_shim)

  movq 328(%rdi), %r11   #load the pointer for the fx reg into r11
  fxrstorq (%r11)         #restore fx register

  movq 312(%rdi), %rax
  movq %rax, %ss    
    
  movq 296(%rdi), %r11 
 # pushq %r11
 # popfq
  movq 304(%rdi), %rsp   
  movq 320(%rdi), %rbp

  movq 168(%rdi), %rax
  movq 176(%rdi), %rbx
  movq 184(%rdi), %rcx
  movq 192(%rdi), %rdx
  movq 200(%rdi), %rsi
  movq 216(%rdi), %r8
  movq 224(%rdi), %r9
  movq 232(%rdi), %r10
  movq 240(%rdi), %r11
  movq 248(%rdi), %r12
  movq 256(%rdi), %r13
  movq 264(%rdi), %r14
  movq 272(%rdi), %r15

	vmlaunch

SET_SIZE(restore_kernel_from_shim)

#endif				
##the one above closes out HYPV_SHIM
#endif

######### HYPV HANDLERS ##########
#ifdef HYPV

ENTRY(systick_asm)
	cli
	HYPV_SAVE_CONTEXT
						
	movq $0x20, %rdi
	RELCALL(systick_hypv_handler)
	RELCALL(lapic_eoi)
	HYPV_RESTORE_CONTEXT

	iretq		
SET_SIZE(systick_asm)

ENTRY(keyboard_asm)
	cli
	HYPV_SAVE_CONTEXT
						
	movq $0x21, %rdi
	RELCALL(keyboard_hypv_handler)
	RELCALL(lapic_eoi)
	HYPV_RESTORE_CONTEXT 

	iretq		
SET_SIZE(keyboard_asm)

ENTRY(network_asm)
	cli
	HYPV_SAVE_CONTEXT
						
	movq $0x2B, %rdi
	RELCALL(network_hypv_handler)
	RELCALL(lapic_eoi)
	HYPV_RESTORE_CONTEXT 

	iretq		
SET_SIZE(network_asm)

ENTRY(vtd_fault_asm)
	cli
	HYPV_SAVE_CONTEXT
						
	movq $0x86, %rdi
	RELCALL(vtd_fault_handler)
	RELCALL(lapic_eoi)
	HYPV_RESTORE_CONTEXT

	iretq		
SET_SIZE(vtd_fault_asm)



#endif     

ENTRY(poke_vmm)
	cli                     # Turn off interrupts
  VMCALL                  # Smoke signals for the hypv
  iretq	               # Return to userland
SET_SIZE(poke_vmm)

#### reenable_pic ####
ENTRY(reenable_pic)
	# Save registers. 
	pushq %rdx
	pushq %rax
	xorq %rax, %rax
	xorq %rdx, %rdx
        
  # Send EOI to slave pic 
  movb $0x20,%al
  movw $0xA0,%dx
  outb %al,%dx
  
  # Send EOI to master pic
	movw $0x20,%dx
	outb %al,%dx

  # Restore registers
	popq %rax
	popq %rdx

	ret
SET_SIZE(reenable_pic)
	
#### restore_user_proc ####
# Restores the given process context, sets up the stack for iret, and irets
ENTRY(restore_user_proc)

#ifdef KERNEL
#ifdef ENABLE_SMP
  HYPV_SAVE_CONTEXT
  RELCALL(interrupt_release_lock)
  HYPV_RESTORE_CONTEXT
#endif
#endif

	movq %rdi, %rbp # This should be the address of the Proc_t
	
	# Restore FPU/MMX/SSE State
	RESTORE_SSE_REGS
	
	# Reconstruct the stack for iretq
	RESTORE_CTRL_REGS
	
	# Restore General-Purpose Registers
	RESTORE_GP_REGS

	iretq # Continue to process
SET_SIZE(restore_user_proc)
	
###############################################################################
######################### Genereic Handlers ###################################

#### GENERALIZED HANDLERS for all the functions below ####

#### exc_info ####
ENTRY(exc_info)
	pushq %rbx # Save %rbx
	pushq %rax # Save %rax
	RELCALL(print_exception_info_one)
	popq %r10 # Store %rax in %r10 for parameter
	popq %rbx # Restore %rbx
	popq %rax # Return address
	popq %rdi # The empty word pushed earlier
	popq %r9  # Error code
	movq %r10,%r9
	popq %r8  # RIP
	popq %rcx # code segment
	popq %rdx # rflags
	popq %rsi # rsp
	popq %rdi # stack segment
	pushq %rax # Put the return address back
	pushq %rbx # Save %rbx
	RELCALL(print_exception_info_two)
	popq %rbx # Restore %rbx
	ret
SET_SIZE(exc_info)
	

# Exception Handling
ENTRY(generic_excp)
 HYPV_SAVE_CONTEXT
#if (defined KERNEL && defined ENABLE_SMP)
  RELCALL(interrupt_acquire_lock)
#endif
HYPV_RESTORE_CONTEXT
	SAVE_CONTEXT
  pushq $0
	call exc_info
	hlt
	jmp .
SET_SIZE(generic_excp)

# IRQ 0-7
ENTRY(generic_hwint_master)
  SAVE_CONTEXT
  popq %rdi                  # Pass vector as arg to invoke_handler
  pushq $0                   # Hack for aligning the stack
  RELCALL(intr_invoke_handler) # Call the handler
  xorq %rax, %rax            # Clear rax
  xorq %rdx, %rdx            # Clear rdx
#ifdef KERNEL
  RELCALL(kernel_exit)       # This cleans up and returns to userland
#endif
SET_SIZE(generic_hwint_master)

        
# IRQ 8-15
ENTRY(generic_hwint_slave)
	SAVE_CONTEXT
  popq %rdi                  # Pass vector as arg to invoke_handler
  pushq $0                   # Hack for aligning the stack
  RELCALL(intr_invoke_handler) # Call appropriate handler
  xorq %rax, %rax            # Clear rax
  xorq %rdx, %rdx            # Clear rdx
#ifdef KERNEL
  RELCALL(kernel_exit)       # This returns next proc to run in rax
#endif

SET_SIZE(generic_hwint_slave)

# Software Interrupts
ENTRY(generic_swint)

	SAVE_CONTEXT               # Save proc context into Proc_t
  popq %rdi                  # Interrupt vector
  pushq $0                   # Hack for aligning stack
	RELCALL(intr_invoke_handler) # Call appropriate handler

#ifdef KERNEL
  RELCALL(kernel_exit)       # This returns next proc to run in rax
#endif
SET_SIZE(generic_swint)

#ifdef SLB_THESIS
# IPI handling
ENTRY(generic_ipi)

	# pop the interrupt vector off of the stack and pass to handler
	popq %rdi
	
	# push all regs onto the stack.
	POINTER_SAVE_CONTEXT

	# call the interrupt handler from C
	RELCALL(intr_invoke_handler)
	
	# restore regs from stack.
	POINTER_RESTORE_CONTEXT

	# return
	iretq

SET_SIZE(generic_ipi)
#endif

############################# End of handler for interrupts below #############

#### EXCEPTION HANDLERS ####
# WARNING!!!! intr_init() relies on these functions being
#   EXACTLY THE SAME SIZE and IN ORDER!
#   DO NOT CHANGE THESE UNLESS YOU KNOW EXACTLY WHAT YOU'RE DOING!
#   See below for more about changing the size.

	ENTRY(vec0)
		movq $0x0, %rdi
    jmp generic_excp
	SET_SIZE(vec0)

  ENTRY(vec1)
		movq $0x1, %rdi
    jmp generic_excp
	SET_SIZE(vec1)

	ENTRY(vec2)
		movq $0x2, %rdi
    jmp generic_excp
	SET_SIZE(vec2)

	ENTRY(vec3)
		movq $0x3, %rdi
  	jmp generic_excp
	SET_SIZE(vec3)

	ENTRY(vec4)
		movq $0x4, %rdi
    jmp generic_excp
	SET_SIZE(vec4)

	ENTRY(vec5)
		movq $0x5, %rdi
    jmp generic_excp
	SET_SIZE(vec5)

	ENTRY(vec6)
		movq $0x6, %rdi
    jmp generic_excp
	SET_SIZE(vec6)

	ENTRY(vec7)
		movq $0x7, %rdi
    jmp generic_excp
	SET_SIZE(vec7)

	ENTRY(vec8)
		movq $0x8, %rdi
    jmp generic_excp
	SET_SIZE(vec8)

	ENTRY(vec9)
		movq $0x9, %rdi
    jmp generic_excp
	SET_SIZE(vec9)

	ENTRY(vecA)
		movq $0xA, %rdi
    jmp generic_excp
	SET_SIZE(vecA)

	ENTRY(vecB)
		movq $0xB, %rdi
    jmp generic_excp
	SET_SIZE(vecB)

	ENTRY(vecC)
		movq $0xC, %rdi
    jmp generic_excp
	SET_SIZE(vecC)

	ENTRY(vecD)
		movq $0xD, %rdi
    jmp generic_excp
	SET_SIZE(vecD)

	ENTRY(vecE)
		movq $0xE, %rdi
    jmp generic_excp
	SET_SIZE(vecE)

	ENTRY(vecF)
		movq $0xF, %rdi
    jmp generic_excp
	SET_SIZE(vecF)

	ENTRY(vec10)
		movq $0x10, %rdi
    jmp generic_excp
	SET_SIZE(vec10)

	ENTRY(vec11)
		movq $0x11, %rdi
    jmp generic_excp
	SET_SIZE(vec11)

	ENTRY(vec12)
		movq $0x12, %rdi
    jmp generic_excp
	SET_SIZE(vec12)

	ENTRY(vec13)
		movq $0x13, %rdi
    jmp generic_excp
	SET_SIZE(vec13)

	ENTRY(vec14)
		movq $0x14, %rdi
    jmp generic_excp
	SET_SIZE(vec14)

	ENTRY(vec15)
		movq $0x15, %rdi
    jmp generic_excp
	SET_SIZE(vec15)

	ENTRY(vec16)
		movq $0x16, %rdi
    jmp generic_excp
	SET_SIZE(vec16)

	ENTRY(vec17)
		movq $0x17, %rdi
    jmp generic_excp
	SET_SIZE(vec17)

	ENTRY(vec18)
		movq $0x18, %rdi
    jmp generic_excp
	SET_SIZE(vec18)

	ENTRY(vec19)
		movq $0x19, %rdi
    jmp generic_excp
	SET_SIZE(vec19)

	ENTRY(vec1A)
		movq $0x1A, %rdi
    jmp generic_excp
	SET_SIZE(vec1A)

	ENTRY(vec1B)
		movq $0x1B, %rdi
    jmp generic_excp
	SET_SIZE(vec1B)

	ENTRY(vec1C)
		movq $0x1C, %rdi
    jmp generic_excp
	SET_SIZE(vec1C)

	ENTRY(vec1D)
		movq $0x1D, %rdi
    jmp generic_excp
	SET_SIZE(vec1D)

	ENTRY(vec1E)
		movq $0x1E, %rdi
    jmp generic_excp
	SET_SIZE(vec1E)

	ENTRY(vec1F)
		movq $0x1F, %rdi
    jmp generic_excp
	SET_SIZE(vec1F)

# Declare the size of the interrupt handlers. THIS IS REQUIRED FOR REPLICATION
# TO WORK! IF YOU EVER CHANGE THE SIZE, YOU MUST CHANGE THE SIZE OF THIS!
	DATA_ENTRY(exception_handler_len)
	.word vec1-vec0
	SET_SIZE(exception_handler_len)

#### MASTER PIC HANDLERS ####
# Interrupts are configured so that irq0 == vector 0x20
# WARNING!!!! intr_init() relies on these functions being
#   EXACTLY THE SAME SIZE and IN ORDER!
#   DO NOT CHANGE THESE UNLESS YOU KNOW EXACTLY WHAT YOU'RE DOING!

  ENTRY(vec20)
  cli
  pushq $0x20
  jmp generic_hwint_master
  SET_SIZE(vec20)

  ENTRY(vec21)
  cli
  pushq $0x21
  jmp generic_hwint_master
  SET_SIZE(vec21)

  ENTRY(vec22)
  cli
  pushq $0x22
  jmp generic_hwint_master
  SET_SIZE(vec22)

  ENTRY(vec23)
  cli
  pushq $0x23
  jmp generic_hwint_master
  SET_SIZE(vec23)

  ENTRY(vec24)
  cli
  pushq $0x24
  jmp generic_hwint_master
  SET_SIZE(vec24)

  ENTRY(vec25)
  cli
  pushq $0x25
  jmp generic_hwint_master
  SET_SIZE(vec25)

  ENTRY(vec26)
  cli
  pushq $0x26
  jmp generic_hwint_master
  SET_SIZE(vec26)

  # HACK: Ignore spurious interrupts.
  ENTRY(vec27)
  iretq
  SET_SIZE(vec27)

  ENTRY(vec28)
  cli
  pushq $0x28
  jmp generic_hwint_slave
  SET_SIZE(vec28)

  ENTRY(vec29)
  cli
  pushq $0x29
  jmp generic_hwint_slave
  SET_SIZE(vec29)

  ENTRY(vec2A)
  cli
  pushq $0x2A
  jmp generic_hwint_slave
  SET_SIZE(vec2A)

  ENTRY(vec2B)
  cli
  pushq $0x2B
  jmp generic_hwint_slave
  SET_SIZE(vec2B)

  ENTRY(vec2C)
  cli
  pushq $0x2C
  jmp generic_hwint_slave
  SET_SIZE(vec2C)

  ENTRY(vec2D)
  cli
  pushq $0x2D
  jmp generic_hwint_slave
  SET_SIZE(vec2D)

  ENTRY(vec2E)
  cli
  pushq $0x2E
  jmp generic_hwint_slave
  SET_SIZE(vec2E)

  ENTRY(vec2F)
  cli
  pushq $0x2F
  jmp generic_hwint_slave
  SET_SIZE(vec2F)

# Declare the size of the interrupt handlers. THIS IS REQUIRED FOR REPLICATION
# TO WORK! IF YOU EVER CHANGE THE SIZE, YOU MUST CHANGE THE SIZE OF THIS!
	DATA_ENTRY(pic_handler_len)
	.word vec21-vec20
	SET_SIZE(pic_handler_len)

#### SOFTWARE INTERRUPT HANDLERS ####
# For size and convenience, skipping to 0x80 and going to 0x90.
# WARNING!!!! intr_init() relies on these functions being
#   EXACTLY THE SAME SIZE and IN ORDER!
#   DO NOT CHANGE THESE UNLESS YOU KNOW EXACTLY WHAT YOU'RE DOING!

  ENTRY(vec7F)
  cli
  pushq $0x7F
  jmp generic_swint
  SET_SIZE(vec7F)

  ENTRY(vec80)
  cli
  pushq $0x80
  jmp generic_swint
  SET_SIZE(vec80)

  ENTRY(vec81)
  cli
  pushq $0x81
  jmp generic_swint
  SET_SIZE(vec81)

  ENTRY(vec82)
  cli
  pushq $0x82
  jmp generic_swint
  SET_SIZE(vec82)

  ENTRY(vec83)
  cli
  pushq $0x83
  jmp generic_swint
  SET_SIZE(vec83)

  ENTRY(vec84)
  cli
  pushq $0x84
  jmp generic_swint
  SET_SIZE(vec84)

  ENTRY(vec85)
  cli
  pushq $0x85
  jmp generic_swint
  SET_SIZE(vec85)

  ENTRY(vec86)
  cli
  pushq $0x86
  jmp generic_swint
  SET_SIZE(vec86)

  ENTRY(vec87)
  cli
  pushq $0x87
  jmp generic_swint
  SET_SIZE(vec87)

  ENTRY(vec88)
  cli
  pushq $0x88
  jmp generic_swint
  SET_SIZE(vec88)

  ENTRY(vec89)
  cli
  pushq $0x89
  jmp generic_swint
  SET_SIZE(vec89)

  ENTRY(vec8A)
  cli
  pushq $0x8A
  jmp generic_swint
  SET_SIZE(vec8A)

  ENTRY(vec8B)
  cli
  pushq $0x8B
  jmp generic_swint
  SET_SIZE(vec8B)

  ENTRY(vec8C)
  cli
  pushq $0x8C
  jmp generic_swint
  SET_SIZE(vec8C)

  ENTRY(vec8D)
  cli
  pushq $0x8D
  jmp generic_swint
  SET_SIZE(vec8D)

  ENTRY(vec8E)
  cli
  pushq $0x8E
  jmp generic_swint
  SET_SIZE(vec8E)

  ENTRY(vec8F)
  cli
  pushq $0x8F
  jmp generic_swint
  SET_SIZE(vec8F)

	
# Declare the size of the interrupt handlers. THIS IS REQUIRED FOR REPLICATION
# TO WORK! IF YOU EVER CHANGE THE SIZE, YOU MUST CHANGE THE SIZE OF THIS!
	DATA_ENTRY(swi_handler_len)
	.word vec81-vec80
	SET_SIZE(swi_handler_len)

#ifdef SLB_THESIS
# We will set the rest up for IPIs... just because.
	
	ENTRY(vec90)
	cli
	pushq $0x90
	jmp generic_ipi
	SET_SIZE(vec90)

	ENTRY(vec91)
	cli
	pushq $0x91
	jmp generic_ipi
	SET_SIZE(vec91)

	ENTRY(vec92)
	cli
	pushq $0x92
	jmp generic_ipi
	SET_SIZE(vec92)

	ENTRY(vec93)
	cli
	pushq $0x93
	jmp generic_ipi
	SET_SIZE(vec93)

	ENTRY(vec94)
	cli
	pushq $0x94
	jmp generic_ipi
	SET_SIZE(vec94)

	ENTRY(vec95)
	cli
	pushq $0x95
	jmp generic_ipi
	SET_SIZE(vec95)

	ENTRY(vec96)
	cli
	pushq $0x96
	jmp generic_ipi
	SET_SIZE(vec96)

	ENTRY(vec97)
	cli
	pushq $0x97
	jmp generic_ipi
	SET_SIZE(vec97)

	ENTRY(vec98)
	cli
	pushq $0x98
	jmp generic_ipi
	SET_SIZE(vec98)

	ENTRY(vec99)
	cli
	pushq $0x99
	jmp generic_ipi
	SET_SIZE(vec99)

	ENTRY(vec9A)
	cli
	pushq $0x9A
	jmp generic_ipi
	SET_SIZE(vec9A)

	ENTRY(vec9B)
	cli
	pushq $0x9B
	jmp generic_ipi
	SET_SIZE(vec9B)

	ENTRY(vec9C)
	cli
	pushq $0x9C
	jmp generic_ipi
	SET_SIZE(vec9C)

	ENTRY(vec9D)
	cli
	pushq $0x9D
	jmp generic_ipi
	SET_SIZE(vec9D)

	ENTRY(vec9E)
	cli
	pushq $0x9E
	jmp generic_ipi
	SET_SIZE(vec9E)

	ENTRY(vec9F)
	cli
	pushq $0x9F
	jmp generic_ipi
	SET_SIZE(vec9F)

	ENTRY(vecA0)
	cli
	pushq $0xA0
	jmp generic_ipi
	SET_SIZE(vecA0)

	ENTRY(vecA1)
	cli
	pushq $0xA1
	jmp generic_ipi
	SET_SIZE(vecA1)

	ENTRY(vecA2)
	cli
	pushq $0xA2
	jmp generic_ipi
	SET_SIZE(vecA2)

	ENTRY(vecA3)
	cli
	pushq $0xA3
	jmp generic_ipi
	SET_SIZE(vecA3)

	ENTRY(vecA4)
	cli
	pushq $0xA4
	jmp generic_ipi
	SET_SIZE(vecA4)

	ENTRY(vecA5)
	cli
	pushq $0xA5
	jmp generic_ipi
	SET_SIZE(vecA5)

	ENTRY(vecA6)
	cli
	pushq $0xA6
	jmp generic_ipi
	SET_SIZE(vecA6)

	ENTRY(vecA7)
	cli
	pushq $0xA7
	jmp generic_ipi
	SET_SIZE(vecA7)

	ENTRY(vecA8)
	cli
	pushq $0xA8
	jmp generic_ipi
	SET_SIZE(vecA8)

	ENTRY(vecA9)
	cli
	pushq $0xA9
	jmp generic_ipi
	SET_SIZE(vecA9)

	ENTRY(vecAA)
	cli
	pushq $0xAA
	jmp generic_ipi
	SET_SIZE(vecAA)

	ENTRY(vecAB)
	cli
	pushq $0xAB
	jmp generic_ipi
	SET_SIZE(vecAB)

	ENTRY(vecAC)
	cli
	pushq $0xAC
	jmp generic_ipi
	SET_SIZE(vecAC)

	ENTRY(vecAD)
	cli
	pushq $0xAD
	jmp generic_ipi
	SET_SIZE(vecAD)

	ENTRY(vecAE)
	cli
	pushq $0xAE
	jmp generic_ipi
	SET_SIZE(vecAE)

	ENTRY(vecAF)
	cli
	pushq $0xAF
	jmp generic_ipi
	SET_SIZE(vecAF)

	ENTRY(vecB0)
	cli
	pushq $0xB0
	jmp generic_ipi
	SET_SIZE(vecB0)

	ENTRY(vecB1)
	cli
	pushq $0xB1
	jmp generic_ipi
	SET_SIZE(vecB1)

	ENTRY(vecB2)
	cli
	pushq $0xB2
	jmp generic_ipi
	SET_SIZE(vecB2)

	ENTRY(vecB3)
	cli
	pushq $0xB3
	jmp generic_ipi
	SET_SIZE(vecB3)

	ENTRY(vecB4)
	cli
	pushq $0xB4
	jmp generic_ipi
	SET_SIZE(vecB4)

	ENTRY(vecB5)
	cli
	pushq $0xB5
	jmp generic_ipi
	SET_SIZE(vecB5)

	ENTRY(vecB6)
	cli
	pushq $0xB6
	jmp generic_ipi
	SET_SIZE(vecB6)

	ENTRY(vecB7)
	cli
	pushq $0xB7
	jmp generic_ipi
	SET_SIZE(vecB7)

	ENTRY(vecB8)
	cli
	pushq $0xB8
	jmp generic_ipi
	SET_SIZE(vecB8)

	ENTRY(vecB9)
	cli
	pushq $0xB9
	jmp generic_ipi
	SET_SIZE(vecB9)

	ENTRY(vecBA)
	cli
	pushq $0xBA
	jmp generic_ipi
	SET_SIZE(vecBA)

	ENTRY(vecBB)
	cli
	pushq $0xBB
	jmp generic_ipi
	SET_SIZE(vecBB)

	ENTRY(vecBC)
	cli
	pushq $0xBC
	jmp generic_ipi
	SET_SIZE(vecBC)

	ENTRY(vecBD)
	cli
	pushq $0xBD
	jmp generic_ipi
	SET_SIZE(vecBD)

	ENTRY(vecBE)
	cli
	pushq $0xBE
	jmp generic_ipi
	SET_SIZE(vecBE)

	ENTRY(vecBF)
	cli
	pushq $0xBF
	jmp generic_ipi
	SET_SIZE(vecBF)

	ENTRY(vecC0)
	cli
	pushq $0xC0
	jmp generic_ipi
	SET_SIZE(vecC0)

	ENTRY(vecC1)
	cli
	pushq $0xC1
	jmp generic_ipi
	SET_SIZE(vecC1)

	ENTRY(vecC2)
	cli
	pushq $0xC2
	jmp generic_ipi
	SET_SIZE(vecC2)

	ENTRY(vecC3)
	cli
	pushq $0xC3
	jmp generic_ipi
	SET_SIZE(vecC3)

	ENTRY(vecC4)
	cli
	pushq $0xC4
	jmp generic_ipi
	SET_SIZE(vecC4)

	ENTRY(vecC5)
	cli
	pushq $0xC5
	jmp generic_ipi
	SET_SIZE(vecC5)

	ENTRY(vecC6)
	cli
	pushq $0xC6
	jmp generic_ipi
	SET_SIZE(vecC6)

	ENTRY(vecC7)
	cli
	pushq $0xC7
	jmp generic_ipi
	SET_SIZE(vecC7)

	ENTRY(vecC8)
	cli
	pushq $0xC8
	jmp generic_ipi
	SET_SIZE(vecC8)

	ENTRY(vecC9)
	cli
	pushq $0xC9
	jmp generic_ipi
	SET_SIZE(vecC9)

	ENTRY(vecCA)
	cli
	pushq $0xCA
	jmp generic_ipi
	SET_SIZE(vecCA)

	ENTRY(vecCB)
	cli
	pushq $0xCB
	jmp generic_ipi
	SET_SIZE(vecCB)

	ENTRY(vecCC)
	cli
	pushq $0xCC
	jmp generic_ipi
	SET_SIZE(vecCC)

	ENTRY(vecCD)
	cli
	pushq $0xCD
	jmp generic_ipi
	SET_SIZE(vecCD)

	ENTRY(vecCE)
	cli
	pushq $0xCE
	jmp generic_ipi
	SET_SIZE(vecCE)

	ENTRY(vecCF)
	cli
	pushq $0xCF
	jmp generic_ipi
	SET_SIZE(vecCF)

	ENTRY(vecD0)
	cli
	pushq $0xD0
	jmp generic_ipi
	SET_SIZE(vecD0)

	ENTRY(vecD1)
	cli
	pushq $0xD1
	jmp generic_ipi
	SET_SIZE(vecD1)

	ENTRY(vecD2)
	cli
	pushq $0xD2
	jmp generic_ipi
	SET_SIZE(vecD2)

	ENTRY(vecD3)
	cli
	pushq $0xD3
	jmp generic_ipi
	SET_SIZE(vecD3)

	ENTRY(vecD4)
	cli
	pushq $0xD4
	jmp generic_ipi
	SET_SIZE(vecD4)

	ENTRY(vecD5)
	cli
	pushq $0xD5
	jmp generic_ipi
	SET_SIZE(vecD5)

	ENTRY(vecD6)
	cli
	pushq $0xD6
	jmp generic_ipi
	SET_SIZE(vecD6)

	ENTRY(vecD7)
	cli
	pushq $0xD7
	jmp generic_ipi
	SET_SIZE(vecD7)

	ENTRY(vecD8)
	cli
	pushq $0xD8
	jmp generic_ipi
	SET_SIZE(vecD8)

	ENTRY(vecD9)
	cli
	pushq $0xD9
	jmp generic_ipi
	SET_SIZE(vecD9)

	ENTRY(vecDA)
	cli
	pushq $0xDA
	jmp generic_ipi
	SET_SIZE(vecDA)

	ENTRY(vecDB)
	cli
	pushq $0xDB
	jmp generic_ipi
	SET_SIZE(vecDB)

	ENTRY(vecDC)
	cli
	pushq $0xDC
	jmp generic_ipi
	SET_SIZE(vecDC)

	ENTRY(vecDD)
	cli
	pushq $0xDD
	jmp generic_ipi
	SET_SIZE(vecDD)

	ENTRY(vecDE)
	cli
	pushq $0xDE
	jmp generic_ipi
	SET_SIZE(vecDE)

	ENTRY(vecDF)
	cli
	pushq $0xDF
	jmp generic_ipi
	SET_SIZE(vecDF)

	ENTRY(vecE0)
	cli
	pushq $0xE0
	jmp generic_ipi
	SET_SIZE(vecE0)

	ENTRY(vecE1)
	cli
	pushq $0xE1
	jmp generic_ipi
	SET_SIZE(vecE1)

	ENTRY(vecE2)
	cli
	pushq $0xE2
	jmp generic_ipi
	SET_SIZE(vecE2)

	ENTRY(vecE3)
	cli
	pushq $0xE3
	jmp generic_ipi
	SET_SIZE(vecE3)

	ENTRY(vecE4)
	cli
	pushq $0xE4
	jmp generic_ipi
	SET_SIZE(vecE4)

	ENTRY(vecE5)
	cli
	pushq $0xE5
	jmp generic_ipi
	SET_SIZE(vecE5)

	ENTRY(vecE6)
	cli
	pushq $0xE6
	jmp generic_ipi
	SET_SIZE(vecE6)

	ENTRY(vecE7)
	cli
	pushq $0xE7
	jmp generic_ipi
	SET_SIZE(vecE7)

	ENTRY(vecE8)
	cli
	pushq $0xE8
	jmp generic_ipi
	SET_SIZE(vecE8)

	ENTRY(vecE9)
	cli
	pushq $0xE9
	jmp generic_ipi
	SET_SIZE(vecE9)

	ENTRY(vecEA)
	cli
	pushq $0xEA
	jmp generic_ipi
	SET_SIZE(vecEA)

	ENTRY(vecEB)
	cli
	pushq $0xEB
	jmp generic_ipi
	SET_SIZE(vecEB)

	ENTRY(vecEC)
	cli
	pushq $0xEC
	jmp generic_ipi
	SET_SIZE(vecEC)

	ENTRY(vecED)
	cli
	pushq $0xED
	jmp generic_ipi
	SET_SIZE(vecED)

	ENTRY(vecEE)
	cli
	pushq $0xEE
	jmp generic_ipi
	SET_SIZE(vecEE)

	ENTRY(vecEF)
	cli
	pushq $0xEF
	jmp generic_ipi
	SET_SIZE(vecEF)

	ENTRY(vecF0)
	cli
	pushq $0xF0
	jmp generic_ipi
	SET_SIZE(vecF0)

	ENTRY(vecF1)
	cli
	pushq $0xF1
	jmp generic_ipi
	SET_SIZE(vecF1)

	ENTRY(vecF2)
	cli
	pushq $0xF2
	jmp generic_ipi
	SET_SIZE(vecF2)

	ENTRY(vecF3)
	cli
	pushq $0xF3
	jmp generic_ipi
	SET_SIZE(vecF3)

	ENTRY(vecF4)
	cli
	pushq $0xF4
	jmp generic_ipi
	SET_SIZE(vecF4)

	ENTRY(vecF5)
	cli
	pushq $0xF5
	jmp generic_ipi
	SET_SIZE(vecF5)

	ENTRY(vecF6)
	cli
	pushq $0xF6
	jmp generic_ipi
	SET_SIZE(vecF6)

	ENTRY(vecF7)
	cli
	pushq $0xF7
	jmp generic_ipi
	SET_SIZE(vecF7)

	ENTRY(vecF8)
	cli
	pushq $0xF8
	jmp generic_ipi
	SET_SIZE(vecF8)

	ENTRY(vecF9)
	cli
	pushq $0xF9
	jmp generic_ipi
	SET_SIZE(vecF9)

	ENTRY(vecFA)
	cli
	pushq $0xFA
	jmp generic_ipi
	SET_SIZE(vecFA)

	ENTRY(vecFB)
	cli
	pushq $0xFB
	jmp generic_ipi
	SET_SIZE(vecFB)

	ENTRY(vecFC)
	cli
	pushq $0xFC
	jmp generic_ipi
	SET_SIZE(vecFC)

	ENTRY(vecFD)
	cli
	pushq $0xFD
	jmp generic_ipi
	SET_SIZE(vecFD)

	ENTRY(vecFE)
	cli
	pushq $0xFE
	jmp generic_ipi
	SET_SIZE(vecFE)

	ENTRY(vecFF)
	cli
	pushq $0xFF
	jmp generic_ipi
	SET_SIZE(vecFF)
	
	# declare the size of each handler
	DATA_ENTRY(ipi_handler_len)
	.word vec91-vec90
	SET_SIZE(ipi_handler_len)
#endif

### This is the dirt simply way to register interrupts  I leave this here as 
#a tutorial if needed in the future. 
#if 0
#### dir_list ####
#ifndef HYPV
	ENTRY(dir_list)
	cli
	SAVE_CONTEXT            # Save proc context into Proc_t

	pushq $0                # Hack for aligning the stack
	RELCALL(print_directory_list)
	SET_SIZE(dir_list)
#endif
#endif

#if defined(HYPV_SHIM) && defined(KERNEL)

	ENTRY(shim_trap)

	SET_SIZE(shim_trap)
#endif
