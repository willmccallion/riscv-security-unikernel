OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY
{
    /* 64KB Total RAM */
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 64K
}

SECTIONS
{
    .text : { *(.text.entry) *(.text .text.*) } > RAM
    .rodata : { *(.rodata .rodata.*) } > RAM
    .data : { *(.data .data.*) } > RAM
    .bss : { 
        _sbss = .; 
        *(.bss .bss.*) 
        *(COMMON) 
        _ebss = .; 
    } > RAM

    /* Heap/Stack space */
    _heap_start = _ebss;
    _stack_top = ORIGIN(RAM) + LENGTH(RAM);
}
