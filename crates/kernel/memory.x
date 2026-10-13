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
        . = ALIGN(8);
        _sbss = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(8);
        _ebss = .;
    } > RAM

    /* Sentinel bytes between .bss and the stack; see stack_guard.rs. */
    .stack_guard : {
        _stack_guard_start = .;
        . = . + 256;
        _stack_guard_end = .;
    } > RAM

    _stack_top = ORIGIN(RAM) + LENGTH(RAM);
}
