; nasm -f elf64 -o simple_supergraph.o simple_supergraph.s
BITS 64

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
