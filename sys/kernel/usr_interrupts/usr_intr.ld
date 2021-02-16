/* Linker script for the post-MBR boot code. It's linked as a binary
 * file, just flat, no header or anything like that. The entry point
 * that the MBR code should call is at the very start of the file,
 * which means it's at the very top of the memory where this is
 * loaded. The rest of the code comes right after, then the data.
*/
OUTPUT_FORMAT(elf64-x86-64);
ENTRY(_common_handler); /* This is just to shut the linker up. */

SECTIONS {
	. = 0xa0000000000;
}
