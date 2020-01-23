; nasm -f elf64 -o simple_supergraph.o simple_supergraph.s
; Compiled with nasm 2.14.02
BITS 64
DEFAULT REL

SECTION .text
GLOBAL main
main:
    push rbp
    mov rbp,rsp
    call fn
    mov eax,0
    pop rbp
    ret

GLOBAL fn
fn:
    push rbp
    mov rbp,rsp
    pop rbp
    ret
