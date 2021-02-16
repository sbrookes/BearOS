#include <ring0.h>
#include <mcontext.h>

/* TODO: take out extern? */
extern uint64_t lapicaddr;
void (*_intr_handler_array[256])(uint64_t);

void lapic_write(uint32_t offset, uint32_t data){
  *(uint32_t *)(lapicaddr+offset) = data;
  return;
}

void lapic_eoi(void){

  lapic_write(APIC_EOI, 0);
  asm volatile("sti");

  return;
}

void send_ipi(uint8_t apicid, uint32_t int_vector){

  lapic_write(APIC_ICRH, apicid<<24);
  lapic_write(APIC_ICRL, APIC_ASSERT | int_vector);

  return;
}

void _intr_invoke_handler(uint64_t vector) {

  _intr_handler_array[vector](vector);

  return;
}

void _ring0_proc_checkin(uint64_t vector) {

  /* 
     TODO: need a check mechanism to ensure that this proc cannot checkin for 
           another proc. Per proc kernel-controlled random number set at 
	   load-time, proc must write it back to another global var so that 
	   the kernel knows for sure that its the correct proc. 
  */

  send_ipi(kernel_core_apicid, 0xb1);

  lapic_eoi();

  return;
}

void _intr_generic_handler(uint64_t vector) {

  send_ipi(kernel_core_apicid, vector == 0xE ? 0xc0 : vector == 0xD ? 0xc1 : 0xff);

  if ( vector == 0xE || vector == 0xD ) 
    asm volatile("hlt");

  lapic_eoi();
  
  return;
}

void _ring0_proc_yield(void) {

  _ring0_proc_yield_asm();

  lapic_eoi();

  return;
}

uint64_t get_nextproc(void) {
  return _next_proc_cr3;
}

struct mcontext *get_mcontext(void) {
  return _mcontext;
}
