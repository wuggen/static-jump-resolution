; nasm -f elf64 -o simprocs.o simprocs.s
; Compiled with nasm 2.14.02

; If you want to actually link the output, it needs to be statically linked:
; gcc -static -o simprocs simprocs.o

BITS 64
DEFAULT REL

SECTION .text
GLOBAL main:function
main:
    push rbp
    mov rbp,rsp

    cmp edi,2
    jge .args_okay

    mov edi,2
    call exit

  .args_okay:
    mov rdi,[rsi+8]
    call puts

    xor eax,eax
    pop rbp
    ret

EXTERN exit, puts
