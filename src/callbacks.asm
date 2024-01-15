section .text

global WorkCallback8

WorkCallback8:
    mov rcx, [rdx+0x28] 
    mov [rsp+0x28],rcx
    mov rcx, [rdx+0x30]
    mov [rsp+0x30],rcx
    mov rcx, [rdx+0x38]
    mov [rsp+0x38], rcx
    mov rcx, [rdx+0x40]
    mov [rsp+0x40], rcx
    mov rcx, [rdx + 0x8]
    mov r8, [rdx+0x18]
    mov r9, [rdx+0x20]
    mov rax, [rdx] 
    mov rdx, [rdx+0x10]
    jmp rax
