#include <asm_linkage.h>
#include <mregs.h>
	
.section .note.GNU-stack,"",%progbits

# push GP regs onto the stack.
.macro SAVE_CONTEXT_STACK
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
 #   pushq  %rsp
.endm

    #Restore the general purpose registers
.macro RESTORE_CONTEXT_STACK
#   popq  %rsp
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

ENTRY(_ring0_proc_save_state)

  RELCALL(get_mcontext)
  # save context for myself
  movq %rbp, BPREG(%rax)
  movq %r15, R15REG(%rax)
  movq %r14, R14REG(%rax) 	
  movq %r13, R13REG(%rax) 
  movq %r12, R12REG(%rax) 
  movq %r11, R11REG(%rax) 
  movq %r10, R10REG(%rax) 
  movq %r9 , R9REG(%rax)  
  movq %r8 , R8REG(%rax)  
  movq %rsi, SIREG(%rax)  
  movq %rdi, DIREG(%rax)  
  movq %rbx, BXREG(%rax)  
  movq %rdx, DXREG(%rax)  
  movq %rcx, CXREG(%rax)  
  movq %rsp, SPREG(%rax)

  retq
SET_SIZE(_ring0_proc_save_state)
	
ENTRY(_ring0_proc_yield_asm)

  RELCALL(get_mcontext)

  # save context for myself
  movq %rbp, BPREG(%rax)
  movq %r15, R15REG(%rax)
  movq %r14, R14REG(%rax) 	
  movq %r13, R13REG(%rax) 
  movq %r12, R12REG(%rax) 
  movq %r11, R11REG(%rax) 
  movq %r10, R10REG(%rax) 
  movq %r9 , R9REG(%rax)  
  movq %r8 , R8REG(%rax)  
  movq %rsi, SIREG(%rax)  
  movq %rdi, DIREG(%rax)  
  movq %rbx, BXREG(%rax)  
  movq %rdx, DXREG(%rax)  
  movq %rcx, CXREG(%rax)  
  movq %rsp, SPREG(%rax)

  movq %ss, %rbx
  movq %rbx, SSREG(%rax)
	
  # switch to the new process' cr3 target
  RELCALL(get_nextproc)
  movq %rax, %cr3 # second arg (rsi) is the phys cr3

  # TODO: This cannot be an interrupt, it must be a function call. This makes
  #       me worry that my interrupt handling is not robust enough... 
  RELCALL(_ring0_proc_checkin)
	
  RELCALL(get_mcontext)
	
  # set stack pointer
  movq SPREG(%rax), %rsp
  movq BPREG(%rax), %rbp

  # TODO TODO need to map some floating point shit into the process.
  # Restore FPU/MMX/SSE State
#  movq FXDATA(%rdi), %rax 
#  fxrstor (%rax)

  movq SSREG(%rax), %rbx
  movq %rbx, %ss

  # restore general purpose regs
  movq CXREG(%rax), %rcx  
  movq DXREG(%rax), %rdx  
  movq BXREG(%rax), %rbx  
  movq SIREG(%rax), %rsi  
  movq R8REG(%rax), %r8   
  movq R9REG(%rax), %r9   
  movq R10REG(%rax), %r10 
  movq R11REG(%rax), %r11 
  movq R12REG(%rax), %r12 
  movq R13REG(%rax), %r13 
  movq R14REG(%rax), %r14 
  movq R15REG(%rax), %r15 

  cmpq $0x0, PCREG(%rax)
  jne first

  # 'return'
  retq

first:
  pushq SSREG(%rax)
  pushq SPREG(%rax)
  pushq EFLREG(%rax)
  pushq CSREG(%rax)
  pushq PCREG(%rax)

  movq $0x0, PCREG(%rax)

  iretq

# i dont think we're changing SS from kernel to ring0 proc.
#  movq SSREG(%rdi), %rax
#  movq %rax, %ss    
	
SET_SIZE(_ring0_proc_yield_asm)
	
# jump to C from an interrupt
ENTRY(_common_handler)

    # pop the interrupt vector off the stack to pass to handler.
    popq %rdi

    # push all GP regs onto the stack
    SAVE_CONTEXT_STACK

    # jump to C
    RELCALL(_intr_invoke_handler)
	
    # restore regs from stack
    RESTORE_CONTEXT_STACK

    # return
    iretq

SET_SIZE(_common_handler)
	
ENTRY(usr_vec0)
    cli
    pushq $0x0
    jmp _common_handler
SET_SIZE(usr_vec0)

ENTRY(usr_vec1)
    cli
    pushq $0x1
    jmp _common_handler
SET_SIZE(usr_vec1)

ENTRY(usr_vec2)
    cli
    pushq $0x2
    jmp _common_handler
SET_SIZE(usr_vec2)

ENTRY(usr_vec3)
    cli
    pushq $0x3
    jmp _common_handler
SET_SIZE(usr_vec3)

ENTRY(usr_vec4)
    cli
    pushq $0x4
    jmp _common_handler
SET_SIZE(usr_vec4)

ENTRY(usr_vec5)
    cli
    pushq $0x5
    jmp _common_handler
SET_SIZE(usr_vec5)

ENTRY(usr_vec6)
    cli
    pushq $0x6
    jmp _common_handler
SET_SIZE(usr_vec6)

ENTRY(usr_vec7)
    cli
    pushq $0x7
    jmp _common_handler
SET_SIZE(usr_vec7)

ENTRY(usr_vec8)
    cli
    pushq $0x8
    jmp _common_handler
SET_SIZE(usr_vec8)

ENTRY(usr_vec9)
    cli
    pushq $0x9
    jmp _common_handler
SET_SIZE(usr_vec9)

ENTRY(usr_vecA)
    cli
    pushq $0xA
    jmp _common_handler
SET_SIZE(usr_vecA)

ENTRY(usr_vecB)
    cli
    pushq $0xB
    jmp _common_handler
SET_SIZE(usr_vecB)

ENTRY(usr_vecC)
    cli
    pushq $0xC
    jmp _common_handler
SET_SIZE(usr_vecC)

ENTRY(usr_vecD)
    cli
    pushq $0xD
    jmp _common_handler
SET_SIZE(usr_vecD)

ENTRY(usr_vecE)
    cli
    pushq $0xE
    jmp _common_handler
SET_SIZE(usr_vecE)

ENTRY(usr_vecF)
    cli
    pushq $0xF
    jmp _common_handler
SET_SIZE(usr_vecF)

ENTRY(usr_vec10)
    cli
    pushq $0x10
    jmp _common_handler
SET_SIZE(usr_vec10)

ENTRY(usr_vec11)
    cli
    pushq $0x11
    jmp _common_handler
SET_SIZE(usr_vec11)

ENTRY(usr_vec12)
    cli
    pushq $0x12
    jmp _common_handler
SET_SIZE(usr_vec12)

ENTRY(usr_vec13)
    cli
    pushq $0x13
    jmp _common_handler
SET_SIZE(usr_vec13)

ENTRY(usr_vec14)
    cli
    pushq $0x14
    jmp _common_handler
SET_SIZE(usr_vec14)

ENTRY(usr_vec15)
    cli
    pushq $0x15
    jmp _common_handler
SET_SIZE(usr_vec15)

ENTRY(usr_vec16)
    cli
    pushq $0x16
    jmp _common_handler
SET_SIZE(usr_vec16)

ENTRY(usr_vec17)
    cli
    pushq $0x17
    jmp _common_handler
SET_SIZE(usr_vec17)

ENTRY(usr_vec18)
    cli
    pushq $0x18
    jmp _common_handler
SET_SIZE(usr_vec18)

ENTRY(usr_vec19)
    cli
    pushq $0x19
    jmp _common_handler
SET_SIZE(usr_vec19)

ENTRY(usr_vec1A)
    cli
    pushq $0x1A
    jmp _common_handler
SET_SIZE(usr_vec1A)

ENTRY(usr_vec1B)
    cli
    pushq $0x1B
    jmp _common_handler
SET_SIZE(usr_vec1B)

ENTRY(usr_vec1C)
    cli
    pushq $0x1C
    jmp _common_handler
SET_SIZE(usr_vec1C)

ENTRY(usr_vec1D)
    cli
    pushq $0x1D
    jmp _common_handler
SET_SIZE(usr_vec1D)

ENTRY(usr_vec1E)
    cli
    pushq $0x1E
    jmp _common_handler
SET_SIZE(usr_vec1E)

ENTRY(usr_vec1F)
    cli
    pushq $0x1F
    jmp _common_handler
SET_SIZE(usr_vec1F)

ENTRY(usr_vec20)
    cli
    pushq $0x20
    jmp _common_handler
SET_SIZE(usr_vec20)

ENTRY(usr_vec21)
    cli
    pushq $0x21
    jmp _common_handler
SET_SIZE(usr_vec21)

ENTRY(usr_vec22)
    cli
    pushq $0x22
    jmp _common_handler
SET_SIZE(usr_vec22)

ENTRY(usr_vec23)
    cli
    pushq $0x23
    jmp _common_handler
SET_SIZE(usr_vec23)

ENTRY(usr_vec24)
    cli
    pushq $0x24
    jmp _common_handler
SET_SIZE(usr_vec24)

ENTRY(usr_vec25)
    cli
    pushq $0x25
    jmp _common_handler
SET_SIZE(usr_vec25)

ENTRY(usr_vec26)
    cli
    pushq $0x26
    jmp _common_handler
SET_SIZE(usr_vec26)

ENTRY(usr_vec27)
    cli
    pushq $0x27
    jmp _common_handler
SET_SIZE(usr_vec27)

ENTRY(usr_vec28)
    cli
    pushq $0x28
    jmp _common_handler
SET_SIZE(usr_vec28)

ENTRY(usr_vec29)
    cli
    pushq $0x29
    jmp _common_handler
SET_SIZE(usr_vec29)

ENTRY(usr_vec2A)
    cli
    pushq $0x2A
    jmp _common_handler
SET_SIZE(usr_vec2A)

ENTRY(usr_vec2B)
    cli
    pushq $0x2B
    jmp _common_handler
SET_SIZE(usr_vec2B)

ENTRY(usr_vec2C)
    cli
    pushq $0x2C
    jmp _common_handler
SET_SIZE(usr_vec2C)

ENTRY(usr_vec2D)
    cli
    pushq $0x2D
    jmp _common_handler
SET_SIZE(usr_vec2D)

ENTRY(usr_vec2E)
    cli
    pushq $0x2E
    jmp _common_handler
SET_SIZE(usr_vec2E)

ENTRY(usr_vec2F)
    cli
    pushq $0x2F
    jmp _common_handler
SET_SIZE(usr_vec2F)

ENTRY(usr_vec30)
    cli
    pushq $0x30
    jmp _common_handler
SET_SIZE(usr_vec30)

ENTRY(usr_vec31)
    cli
    pushq $0x31
    jmp _common_handler
SET_SIZE(usr_vec31)

ENTRY(usr_vec32)
    cli
    pushq $0x32
    jmp _common_handler
SET_SIZE(usr_vec32)

ENTRY(usr_vec33)
    cli
    pushq $0x33
    jmp _common_handler
SET_SIZE(usr_vec33)

ENTRY(usr_vec34)
    cli
    pushq $0x34
    jmp _common_handler
SET_SIZE(usr_vec34)

ENTRY(usr_vec35)
    cli
    pushq $0x35
    jmp _common_handler
SET_SIZE(usr_vec35)

ENTRY(usr_vec36)
    cli
    pushq $0x36
    jmp _common_handler
SET_SIZE(usr_vec36)

ENTRY(usr_vec37)
    cli
    pushq $0x37
    jmp _common_handler
SET_SIZE(usr_vec37)

ENTRY(usr_vec38)
    cli
    pushq $0x38
    jmp _common_handler
SET_SIZE(usr_vec38)

ENTRY(usr_vec39)
    cli
    pushq $0x39
    jmp _common_handler
SET_SIZE(usr_vec39)

ENTRY(usr_vec3A)
    cli
    pushq $0x3A
    jmp _common_handler
SET_SIZE(usr_vec3A)

ENTRY(usr_vec3B)
    cli
    pushq $0x3B
    jmp _common_handler
SET_SIZE(usr_vec3B)

ENTRY(usr_vec3C)
    cli
    pushq $0x3C
    jmp _common_handler
SET_SIZE(usr_vec3C)

ENTRY(usr_vec3D)
    cli
    pushq $0x3D
    jmp _common_handler
SET_SIZE(usr_vec3D)

ENTRY(usr_vec3E)
    cli
    pushq $0x3E
    jmp _common_handler
SET_SIZE(usr_vec3E)

ENTRY(usr_vec3F)
    cli
    pushq $0x3F
    jmp _common_handler
SET_SIZE(usr_vec3F)

ENTRY(usr_vec40)
    cli
    pushq $0x40
    jmp _common_handler
SET_SIZE(usr_vec40)

ENTRY(usr_vec41)
    cli
    pushq $0x41
    jmp _common_handler
SET_SIZE(usr_vec41)

ENTRY(usr_vec42)
    cli
    pushq $0x42
    jmp _common_handler
SET_SIZE(usr_vec42)

ENTRY(usr_vec43)
    cli
    pushq $0x43
    jmp _common_handler
SET_SIZE(usr_vec43)

ENTRY(usr_vec44)
    cli
    pushq $0x44
    jmp _common_handler
SET_SIZE(usr_vec44)

ENTRY(usr_vec45)
    cli
    pushq $0x45
    jmp _common_handler
SET_SIZE(usr_vec45)

ENTRY(usr_vec46)
    cli
    pushq $0x46
    jmp _common_handler
SET_SIZE(usr_vec46)

ENTRY(usr_vec47)
    cli
    pushq $0x47
    jmp _common_handler
SET_SIZE(usr_vec47)

ENTRY(usr_vec48)
    cli
    pushq $0x48
    jmp _common_handler
SET_SIZE(usr_vec48)

ENTRY(usr_vec49)
    cli
    pushq $0x49
    jmp _common_handler
SET_SIZE(usr_vec49)

ENTRY(usr_vec4A)
    cli
    pushq $0x4A
    jmp _common_handler
SET_SIZE(usr_vec4A)

ENTRY(usr_vec4B)
    cli
    pushq $0x4B
    jmp _common_handler
SET_SIZE(usr_vec4B)

ENTRY(usr_vec4C)
    cli
    pushq $0x4C
    jmp _common_handler
SET_SIZE(usr_vec4C)

ENTRY(usr_vec4D)
    cli
    pushq $0x4D
    jmp _common_handler
SET_SIZE(usr_vec4D)

ENTRY(usr_vec4E)
    cli
    pushq $0x4E
    jmp _common_handler
SET_SIZE(usr_vec4E)

ENTRY(usr_vec4F)
    cli
    pushq $0x4F
    jmp _common_handler
SET_SIZE(usr_vec4F)

ENTRY(usr_vec50)
    cli
    pushq $0x50
    jmp _common_handler
SET_SIZE(usr_vec50)

ENTRY(usr_vec51)
    cli
    pushq $0x51
    jmp _common_handler
SET_SIZE(usr_vec51)

ENTRY(usr_vec52)
    cli
    pushq $0x52
    jmp _common_handler
SET_SIZE(usr_vec52)

ENTRY(usr_vec53)
    cli
    pushq $0x53
    jmp _common_handler
SET_SIZE(usr_vec53)

ENTRY(usr_vec54)
    cli
    pushq $0x54
    jmp _common_handler
SET_SIZE(usr_vec54)

ENTRY(usr_vec55)
    cli
    pushq $0x55
    jmp _common_handler
SET_SIZE(usr_vec55)

ENTRY(usr_vec56)
    cli
    pushq $0x56
    jmp _common_handler
SET_SIZE(usr_vec56)

ENTRY(usr_vec57)
    cli
    pushq $0x57
    jmp _common_handler
SET_SIZE(usr_vec57)

ENTRY(usr_vec58)
    cli
    pushq $0x58
    jmp _common_handler
SET_SIZE(usr_vec58)

ENTRY(usr_vec59)
    cli
    pushq $0x59
    jmp _common_handler
SET_SIZE(usr_vec59)

ENTRY(usr_vec5A)
    cli
    pushq $0x5A
    jmp _common_handler
SET_SIZE(usr_vec5A)

ENTRY(usr_vec5B)
    cli
    pushq $0x5B
    jmp _common_handler
SET_SIZE(usr_vec5B)

ENTRY(usr_vec5C)
    cli
    pushq $0x5C
    jmp _common_handler
SET_SIZE(usr_vec5C)

ENTRY(usr_vec5D)
    cli
    pushq $0x5D
    jmp _common_handler
SET_SIZE(usr_vec5D)

ENTRY(usr_vec5E)
    cli
    pushq $0x5E
    jmp _common_handler
SET_SIZE(usr_vec5E)

ENTRY(usr_vec5F)
    cli
    pushq $0x5F
    jmp _common_handler
SET_SIZE(usr_vec5F)

ENTRY(usr_vec60)
    cli
    pushq $0x60
    jmp _common_handler
SET_SIZE(usr_vec60)

ENTRY(usr_vec61)
    cli
    pushq $0x61
    jmp _common_handler
SET_SIZE(usr_vec61)

ENTRY(usr_vec62)
    cli
    pushq $0x62
    jmp _common_handler
SET_SIZE(usr_vec62)

ENTRY(usr_vec63)
    cli
    pushq $0x63
    jmp _common_handler
SET_SIZE(usr_vec63)

ENTRY(usr_vec64)
    cli
    pushq $0x64
    jmp _common_handler
SET_SIZE(usr_vec64)

ENTRY(usr_vec65)
    cli
    pushq $0x65
    jmp _common_handler
SET_SIZE(usr_vec65)

ENTRY(usr_vec66)
    cli
    pushq $0x66
    jmp _common_handler
SET_SIZE(usr_vec66)

ENTRY(usr_vec67)
    cli
    pushq $0x67
    jmp _common_handler
SET_SIZE(usr_vec67)

ENTRY(usr_vec68)
    cli
    pushq $0x68
    jmp _common_handler
SET_SIZE(usr_vec68)

ENTRY(usr_vec69)
    cli
    pushq $0x69
    jmp _common_handler
SET_SIZE(usr_vec69)

ENTRY(usr_vec6A)
    cli
    pushq $0x6A
    jmp _common_handler
SET_SIZE(usr_vec6A)

ENTRY(usr_vec6B)
    cli
    pushq $0x6B
    jmp _common_handler
SET_SIZE(usr_vec6B)

ENTRY(usr_vec6C)
    cli
    pushq $0x6C
    jmp _common_handler
SET_SIZE(usr_vec6C)

ENTRY(usr_vec6D)
    cli
    pushq $0x6D
    jmp _common_handler
SET_SIZE(usr_vec6D)

ENTRY(usr_vec6E)
    cli
    pushq $0x6E
    jmp _common_handler
SET_SIZE(usr_vec6E)

ENTRY(usr_vec6F)
    cli
    pushq $0x6F
    jmp _common_handler
SET_SIZE(usr_vec6F)

ENTRY(usr_vec70)
    cli
    pushq $0x70
    jmp _common_handler
SET_SIZE(usr_vec70)

ENTRY(usr_vec71)
    cli
    pushq $0x71
    jmp _common_handler
SET_SIZE(usr_vec71)

ENTRY(usr_vec72)
    cli
    pushq $0x72
    jmp _common_handler
SET_SIZE(usr_vec72)

ENTRY(usr_vec73)
    cli
    pushq $0x73
    jmp _common_handler
SET_SIZE(usr_vec73)

ENTRY(usr_vec74)
    cli
    pushq $0x74
    jmp _common_handler
SET_SIZE(usr_vec74)

ENTRY(usr_vec75)
    cli
    pushq $0x75
    jmp _common_handler
SET_SIZE(usr_vec75)

ENTRY(usr_vec76)
    cli
    pushq $0x76
    jmp _common_handler
SET_SIZE(usr_vec76)

ENTRY(usr_vec77)
    cli
    pushq $0x77
    jmp _common_handler
SET_SIZE(usr_vec77)

ENTRY(usr_vec78)
    cli
    pushq $0x78
    jmp _common_handler
SET_SIZE(usr_vec78)

ENTRY(usr_vec79)
    cli
    pushq $0x79
    jmp _common_handler
SET_SIZE(usr_vec79)

ENTRY(usr_vec7A)
    cli
    pushq $0x7A
    jmp _common_handler
SET_SIZE(usr_vec7A)

ENTRY(usr_vec7B)
    cli
    pushq $0x7B
    jmp _common_handler
SET_SIZE(usr_vec7B)

ENTRY(usr_vec7C)
    cli
    pushq $0x7C
    jmp _common_handler
SET_SIZE(usr_vec7C)

ENTRY(usr_vec7D)
    cli
    pushq $0x7D
    jmp _common_handler
SET_SIZE(usr_vec7D)

ENTRY(usr_vec7E)
    cli
    pushq $0x7E
    jmp _common_handler
SET_SIZE(usr_vec7E)

ENTRY(usr_vec7F)
    cli
    pushq $0x7F
    jmp _common_handler
SET_SIZE(usr_vec7F)

ENTRY(usr_vec80)
    cli
    pushq $0x80
    jmp _common_handler
SET_SIZE(usr_vec80)

ENTRY(usr_vec81)
    cli
    pushq $0x81
    jmp _common_handler
SET_SIZE(usr_vec81)

ENTRY(usr_vec82)
    cli
    pushq $0x82
    jmp _common_handler
SET_SIZE(usr_vec82)

ENTRY(usr_vec83)
    cli
    pushq $0x83
    jmp _common_handler
SET_SIZE(usr_vec83)

ENTRY(usr_vec84)
    cli
    pushq $0x84
    jmp _common_handler
SET_SIZE(usr_vec84)

ENTRY(usr_vec85)
    cli
    pushq $0x85
    jmp _common_handler
SET_SIZE(usr_vec85)

ENTRY(usr_vec86)
    cli
    pushq $0x86
    jmp _common_handler
SET_SIZE(usr_vec86)

ENTRY(usr_vec87)
    cli
    pushq $0x87
    jmp _common_handler
SET_SIZE(usr_vec87)

ENTRY(usr_vec88)
    cli
    pushq $0x88
    jmp _common_handler
SET_SIZE(usr_vec88)

ENTRY(usr_vec89)
    cli
    pushq $0x89
    jmp _common_handler
SET_SIZE(usr_vec89)

ENTRY(usr_vec8A)
    cli
    pushq $0x8A
    jmp _common_handler
SET_SIZE(usr_vec8A)

ENTRY(usr_vec8B)
    cli
    pushq $0x8B
    jmp _common_handler
SET_SIZE(usr_vec8B)

ENTRY(usr_vec8C)
    cli
    pushq $0x8C
    jmp _common_handler
SET_SIZE(usr_vec8C)

ENTRY(usr_vec8D)
    cli
    pushq $0x8D
    jmp _common_handler
SET_SIZE(usr_vec8D)

ENTRY(usr_vec8E)
    cli
    pushq $0x8E
    jmp _common_handler
SET_SIZE(usr_vec8E)

ENTRY(usr_vec8F)
    cli
    pushq $0x8F
    jmp _common_handler
SET_SIZE(usr_vec8F)

ENTRY(usr_vec90)
    cli
    pushq $0x90
    jmp _common_handler
SET_SIZE(usr_vec90)

ENTRY(usr_vec91)
    cli
    pushq $0x91
    jmp _common_handler
SET_SIZE(usr_vec91)

ENTRY(usr_vec92)
    cli
    pushq $0x92
    jmp _common_handler
SET_SIZE(usr_vec92)

ENTRY(usr_vec93)
    cli
    pushq $0x93
    jmp _common_handler
SET_SIZE(usr_vec93)

ENTRY(usr_vec94)
    cli
    pushq $0x94
    jmp _common_handler
SET_SIZE(usr_vec94)

ENTRY(usr_vec95)
    cli
    pushq $0x95
    jmp _common_handler
SET_SIZE(usr_vec95)

ENTRY(usr_vec96)
    cli
    pushq $0x96
    jmp _common_handler
SET_SIZE(usr_vec96)

ENTRY(usr_vec97)
    cli
    pushq $0x97
    jmp _common_handler
SET_SIZE(usr_vec97)

ENTRY(usr_vec98)
    cli
    pushq $0x98
    jmp _common_handler
SET_SIZE(usr_vec98)

ENTRY(usr_vec99)
    cli
    pushq $0x99
    jmp _common_handler
SET_SIZE(usr_vec99)

ENTRY(usr_vec9A)
    cli
    pushq $0x9A
    jmp _common_handler
SET_SIZE(usr_vec9A)

ENTRY(usr_vec9B)
    cli
    pushq $0x9B
    jmp _common_handler
SET_SIZE(usr_vec9B)

ENTRY(usr_vec9C)
    cli
    pushq $0x9C
    jmp _common_handler
SET_SIZE(usr_vec9C)

ENTRY(usr_vec9D)
    cli
    pushq $0x9D
    jmp _common_handler
SET_SIZE(usr_vec9D)

ENTRY(usr_vec9E)
    cli
    pushq $0x9E
    jmp _common_handler
SET_SIZE(usr_vec9E)

ENTRY(usr_vec9F)
    cli
    pushq $0x9F
    jmp _common_handler
SET_SIZE(usr_vec9F)

ENTRY(usr_vecA0)
    cli
    pushq $0xA0
    jmp _common_handler
SET_SIZE(usr_vecA0)

ENTRY(usr_vecA1)
    cli
    pushq $0xA1
    jmp _common_handler
SET_SIZE(usr_vecA1)

ENTRY(usr_vecA2)
    cli
    pushq $0xA2
    jmp _common_handler
SET_SIZE(usr_vecA2)

ENTRY(usr_vecA3)
    cli
    pushq $0xA3
    jmp _common_handler
SET_SIZE(usr_vecA3)

ENTRY(usr_vecA4)
    cli
    pushq $0xA4
    jmp _common_handler
SET_SIZE(usr_vecA4)

ENTRY(usr_vecA5)
    cli
    pushq $0xA5
    jmp _common_handler
SET_SIZE(usr_vecA5)

ENTRY(usr_vecA6)
    cli
    pushq $0xA6
    jmp _common_handler
SET_SIZE(usr_vecA6)

ENTRY(usr_vecA7)
    cli
    pushq $0xA7
    jmp _common_handler
SET_SIZE(usr_vecA7)

ENTRY(usr_vecA8)
    cli
    pushq $0xA8
    jmp _common_handler
SET_SIZE(usr_vecA8)

ENTRY(usr_vecA9)
    cli
    pushq $0xA9
    jmp _common_handler
SET_SIZE(usr_vecA9)

ENTRY(usr_vecAA)
    cli
    pushq $0xAA
    jmp _common_handler
SET_SIZE(usr_vecAA)

ENTRY(usr_vecAB)
    cli
    pushq $0xAB
    jmp _common_handler
SET_SIZE(usr_vecAB)

ENTRY(usr_vecAC)
    cli
    pushq $0xAC
    jmp _common_handler
SET_SIZE(usr_vecAC)

ENTRY(usr_vecAD)
    cli
    pushq $0xAD
    jmp _common_handler
SET_SIZE(usr_vecAD)

ENTRY(usr_vecAE)
    cli
    pushq $0xAE
    jmp _common_handler
SET_SIZE(usr_vecAE)

ENTRY(usr_vecAF)
    cli
    pushq $0xAF
    jmp _common_handler
SET_SIZE(usr_vecAF)

ENTRY(usr_vecB0)
    cli
    pushq $0xB0
    jmp _common_handler
SET_SIZE(usr_vecB0)

ENTRY(usr_vecB1)
    cli
    pushq $0xB1
    jmp _common_handler
SET_SIZE(usr_vecB1)

ENTRY(usr_vecB2)
    cli
    pushq $0xB2
    jmp _common_handler
SET_SIZE(usr_vecB2)

ENTRY(usr_vecB3)
    cli
    pushq $0xB3
    jmp _common_handler
SET_SIZE(usr_vecB3)

ENTRY(usr_vecB4)
    cli
    pushq $0xB4
    jmp _common_handler
SET_SIZE(usr_vecB4)

ENTRY(usr_vecB5)
    cli
    pushq $0xB5
    jmp _common_handler
SET_SIZE(usr_vecB5)

ENTRY(usr_vecB6)
    cli
    pushq $0xB6
    jmp _common_handler
SET_SIZE(usr_vecB6)

ENTRY(usr_vecB7)
    cli
    pushq $0xB7
    jmp _common_handler
SET_SIZE(usr_vecB7)

ENTRY(usr_vecB8)
    cli
    pushq $0xB8
    jmp _common_handler
SET_SIZE(usr_vecB8)

ENTRY(usr_vecB9)
    cli
    pushq $0xB9
    jmp _common_handler
SET_SIZE(usr_vecB9)

ENTRY(usr_vecBA)
    cli
    pushq $0xBA
    jmp _common_handler
SET_SIZE(usr_vecBA)

ENTRY(usr_vecBB)
    cli
    pushq $0xBB
    jmp _common_handler
SET_SIZE(usr_vecBB)

ENTRY(usr_vecBC)
    cli
    pushq $0xBC
    jmp _common_handler
SET_SIZE(usr_vecBC)

ENTRY(usr_vecBD)
    cli
    pushq $0xBD
    jmp _common_handler
SET_SIZE(usr_vecBD)

ENTRY(usr_vecBE)
    cli
    pushq $0xBE
    jmp _common_handler
SET_SIZE(usr_vecBE)

ENTRY(usr_vecBF)
    cli
    pushq $0xBF
    jmp _common_handler
SET_SIZE(usr_vecBF)

ENTRY(usr_vecC0)
    cli
    pushq $0xC0
    jmp _common_handler
SET_SIZE(usr_vecC0)

ENTRY(usr_vecC1)
    cli
    pushq $0xC1
    jmp _common_handler
SET_SIZE(usr_vecC1)

ENTRY(usr_vecC2)
    cli
    pushq $0xC2
    jmp _common_handler
SET_SIZE(usr_vecC2)

ENTRY(usr_vecC3)
    cli
    pushq $0xC3
    jmp _common_handler
SET_SIZE(usr_vecC3)

ENTRY(usr_vecC4)
    cli
    pushq $0xC4
    jmp _common_handler
SET_SIZE(usr_vecC4)

ENTRY(usr_vecC5)
    cli
    pushq $0xC5
    jmp _common_handler
SET_SIZE(usr_vecC5)

ENTRY(usr_vecC6)
    cli
    pushq $0xC6
    jmp _common_handler
SET_SIZE(usr_vecC6)

ENTRY(usr_vecC7)
    cli
    pushq $0xC7
    jmp _common_handler
SET_SIZE(usr_vecC7)

ENTRY(usr_vecC8)
    cli
    pushq $0xC8
    jmp _common_handler
SET_SIZE(usr_vecC8)

ENTRY(usr_vecC9)
    cli
    pushq $0xC9
    jmp _common_handler
SET_SIZE(usr_vecC9)

ENTRY(usr_vecCA)
    cli
    pushq $0xCA
    jmp _common_handler
SET_SIZE(usr_vecCA)

ENTRY(usr_vecCB)
    cli
    pushq $0xCB
    jmp _common_handler
SET_SIZE(usr_vecCB)

ENTRY(usr_vecCC)
    cli
    pushq $0xCC
    jmp _common_handler
SET_SIZE(usr_vecCC)

ENTRY(usr_vecCD)
    cli
    pushq $0xCD
    jmp _common_handler
SET_SIZE(usr_vecCD)

ENTRY(usr_vecCE)
    cli
    pushq $0xCE
    jmp _common_handler
SET_SIZE(usr_vecCE)

ENTRY(usr_vecCF)
    cli
    pushq $0xCF
    jmp _common_handler
SET_SIZE(usr_vecCF)

ENTRY(usr_vecD0)
    cli
    pushq $0xD0
    jmp _common_handler
SET_SIZE(usr_vecD0)

ENTRY(usr_vecD1)
    cli
    pushq $0xD1
    jmp _common_handler
SET_SIZE(usr_vecD1)

ENTRY(usr_vecD2)
    cli
    pushq $0xD2
    jmp _common_handler
SET_SIZE(usr_vecD2)

ENTRY(usr_vecD3)
    cli
    pushq $0xD3
    jmp _common_handler
SET_SIZE(usr_vecD3)

ENTRY(usr_vecD4)
    cli
    pushq $0xD4
    jmp _common_handler
SET_SIZE(usr_vecD4)

ENTRY(usr_vecD5)
    cli
    pushq $0xD5
    jmp _common_handler
SET_SIZE(usr_vecD5)

ENTRY(usr_vecD6)
    cli
    pushq $0xD6
    jmp _common_handler
SET_SIZE(usr_vecD6)

ENTRY(usr_vecD7)
    cli
    pushq $0xD7
    jmp _common_handler
SET_SIZE(usr_vecD7)

ENTRY(usr_vecD8)
    cli
    pushq $0xD8
    jmp _common_handler
SET_SIZE(usr_vecD8)

ENTRY(usr_vecD9)
    cli
    pushq $0xD9
    jmp _common_handler
SET_SIZE(usr_vecD9)

ENTRY(usr_vecDA)
    cli
    pushq $0xDA
    jmp _common_handler
SET_SIZE(usr_vecDA)

ENTRY(usr_vecDB)
    cli
    pushq $0xDB
    jmp _common_handler
SET_SIZE(usr_vecDB)

ENTRY(usr_vecDC)
    cli
    pushq $0xDC
    jmp _common_handler
SET_SIZE(usr_vecDC)

ENTRY(usr_vecDD)
    cli
    pushq $0xDD
    jmp _common_handler
SET_SIZE(usr_vecDD)

ENTRY(usr_vecDE)
    cli
    pushq $0xDE
    jmp _common_handler
SET_SIZE(usr_vecDE)

ENTRY(usr_vecDF)
    cli
    pushq $0xDF
    jmp _common_handler
SET_SIZE(usr_vecDF)

ENTRY(usr_vecE0)
    cli
    pushq $0xE0
    jmp _common_handler
SET_SIZE(usr_vecE0)

ENTRY(usr_vecE1)
    cli
    pushq $0xE1
    jmp _common_handler
SET_SIZE(usr_vecE1)

ENTRY(usr_vecE2)
    cli
    pushq $0xE2
    jmp _common_handler
SET_SIZE(usr_vecE2)

ENTRY(usr_vecE3)
    cli
    pushq $0xE3
    jmp _common_handler
SET_SIZE(usr_vecE3)

ENTRY(usr_vecE4)
    cli
    pushq $0xE4
    jmp _common_handler
SET_SIZE(usr_vecE4)

ENTRY(usr_vecE5)
    cli
    pushq $0xE5
    jmp _common_handler
SET_SIZE(usr_vecE5)

ENTRY(usr_vecE6)
    cli
    pushq $0xE6
    jmp _common_handler
SET_SIZE(usr_vecE6)

ENTRY(usr_vecE7)
    cli
    pushq $0xE7
    jmp _common_handler
SET_SIZE(usr_vecE7)

ENTRY(usr_vecE8)
    cli
    pushq $0xE8
    jmp _common_handler
SET_SIZE(usr_vecE8)

ENTRY(usr_vecE9)
    cli
    pushq $0xE9
    jmp _common_handler
SET_SIZE(usr_vecE9)

ENTRY(usr_vecEA)
    cli
    pushq $0xEA
    jmp _common_handler
SET_SIZE(usr_vecEA)

ENTRY(usr_vecEB)
    cli
    pushq $0xEB
    jmp _common_handler
SET_SIZE(usr_vecEB)

ENTRY(usr_vecEC)
    cli
    pushq $0xEC
    jmp _common_handler
SET_SIZE(usr_vecEC)

ENTRY(usr_vecED)
    cli
    pushq $0xED
    jmp _common_handler
SET_SIZE(usr_vecED)

ENTRY(usr_vecEE)
    cli
    pushq $0xEE
    jmp _common_handler
SET_SIZE(usr_vecEE)

ENTRY(usr_vecEF)
    cli
    pushq $0xEF
    jmp _common_handler
SET_SIZE(usr_vecEF)

ENTRY(usr_vecF0)
    cli
    pushq $0xF0
    jmp _common_handler
SET_SIZE(usr_vecF0)

ENTRY(usr_vecF1)
    cli
    pushq $0xF1
    jmp _common_handler
SET_SIZE(usr_vecF1)

ENTRY(usr_vecF2)
    cli
    pushq $0xF2
    jmp _common_handler
SET_SIZE(usr_vecF2)

ENTRY(usr_vecF3)
    cli
    pushq $0xF3
    jmp _common_handler
SET_SIZE(usr_vecF3)

ENTRY(usr_vecF4)
    cli
    pushq $0xF4
    jmp _common_handler
SET_SIZE(usr_vecF4)

ENTRY(usr_vecF5)
    cli
    pushq $0xF5
    jmp _common_handler
SET_SIZE(usr_vecF5)

ENTRY(usr_vecF6)
    cli
    pushq $0xF6
    jmp _common_handler
SET_SIZE(usr_vecF6)

ENTRY(usr_vecF7)
    cli
    pushq $0xF7
    jmp _common_handler
SET_SIZE(usr_vecF7)

ENTRY(usr_vecF8)
    cli
    pushq $0xF8
    jmp _common_handler
SET_SIZE(usr_vecF8)

ENTRY(usr_vecF9)
    cli
    pushq $0xF9
    jmp _common_handler
SET_SIZE(usr_vecF9)

ENTRY(usr_vecFA)
    cli
    pushq $0xFA
    jmp _common_handler
SET_SIZE(usr_vecFA)

ENTRY(usr_vecFB)
    cli
    pushq $0xFB
    jmp _common_handler
SET_SIZE(usr_vecFB)

ENTRY(usr_vecFC)
    cli
    pushq $0xFC
    jmp _common_handler
SET_SIZE(usr_vecFC)

ENTRY(usr_vecFD)
    cli
    pushq $0xFD
    jmp _common_handler
SET_SIZE(usr_vecFD)

ENTRY(usr_vecFE)
    cli
    pushq $0xFE
    jmp _common_handler
SET_SIZE(usr_vecFE)

ENTRY(usr_vecFF)
    cli
    pushq $0xFF
    jmp _common_handler
SET_SIZE(usr_vecFF)

	# declare the size of each handler
	DATA_ENTRY(usr_handler_len)
	.word usr_vec91-usr_vec90
	SET_SIZE(usr_handler_len)
