/* Place _start at exactly 0x80000000 with no ELF headers in the loaded image,
   so the same binary boots identically under QEMU's virt machine and simmerv. */
OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS
{
	. = 0x80000000;
	.text : { *(.text.init) *(.text*) }
	. = ALIGN(64);
	.rodata : { *(.rodata*) }
	.data : { *(.data*) *(.sdata*) }
	.bss : { *(.bss*) *(.sbss*) *(COMMON) }
	/DISCARD/ : { *(.note*) *(.comment) *(.riscv.attributes) }
}
