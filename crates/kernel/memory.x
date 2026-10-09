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

    /*
     * Stack guard: 256 bytes filled at boot with a fixed sentinel
     * pattern. The stack grows down from _stack_top; once it's used
     * enough to walk into the heap/data region it will land here
     * first. The telemetry tick re-reads the bytes and halts the
     * kernel if the pattern has changed, so a silent overflow turns
     * into a loud, localised crash instead of corrupting whatever
     * data structure happened to share that address.
     */
    .stack_guard : {
        _stack_guard_start = .;
        . = . + 256;
        _stack_guard_end = .;
    } > RAM

    /* Heap/Stack space */
    _heap_start = _stack_guard_end;
    _stack_top = ORIGIN(RAM) + LENGTH(RAM);
}
