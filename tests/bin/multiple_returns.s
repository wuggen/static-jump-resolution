; nasm -f elf64 -o multiple_returns.o multiple_returns.s
; Compiled with nasm 2.14.02
BITS 64
DEFAULT REL

SECTION .text
GLOBAL main
main:
    push rbp
    mov rbp,rsp

    mov edi,100
    call fn

    mov bl,0
    jmp main.test

  .loop:
    mov edi,ebx
    call fn
    inc bl

  .test:
    cmp bl,10
    jle main.loop

    mov eax,0
    pop rbp
    ret

fn:
    push rbp
    mov rbp,rsp

    mov eax,edx
    add eax,10

    pop rbp
    ret
