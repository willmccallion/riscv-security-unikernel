OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY
{
    /* 64KB Total RAM */
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 64K
}

SECTIONS
{
    .text : {
        _stext = .;
        *(.text.entry)
        *(.text .text.*)
        . = ALIGN(4);
        _etext = .;
    } > RAM

    .rodata : {
        _srodata = .;
        *(.rodata .rodata.*)
        . = ALIGN(4);
        _erodata = .;
    } > RAM

    .data : {
        _sdata = .;
        *(.data .data.*)
        . = ALIGN(4);
        _edata = .;
    } > RAM

    .bss : {
        _sbss = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4);
        _ebss = .;
    } > RAM

    /* Heap/Stack space */
    _heap_start = _ebss;
    _stack_top = ORIGIN(RAM) + LENGTH(RAM);
}
