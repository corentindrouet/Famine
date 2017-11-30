section .text
	global _treat_file
	global _final_end

_treat_file:
	enter 4128, 0 ; equal to push rbp - mov rbp, rsp - sub rsp, 16
				; sub 8 bytes for read return value
				; sub 8 bytes for fd
				; sub 4096 bytes for read (buffer)
	cmp rdi, 0
	je _final_end
;;;;;;;;;;;;;;;;;
; open file
	mov rax, 2
	mov rsi, 2
	xor rdx, rdx
	syscall
	cmp rax, -1
	jle _final_end
	mov QWORD [rsp + 4096], rax ; store the fd

_read_file_header_64:
;;;;;;;;;;;;;;;;;
; read the header from file, if it has one (64 bytes)
	xor rax, rax
	mov rdi, QWORD [rsp + 4096]
	mov rsi, rsp
	mov rdx, 64
	syscall
	cmp rax, 64  ; if their is less than 64 bytes readed, then the file is not a binary
	jl _final_end
;; check magic number
	cmp DWORD [rsp], 0x464c457f
	jne _final_end
;; check class file (only 64 bits are treated)
	cmp BYTE [rsp + 4], 2
	jne _final_end
;; check the file type, only exec files are treated
	cmp WORD [rsp + 16], 2
	jne _final_end
;;;;;;;;;;;;;;;;;;;;;;;;
;; just print string for debug, will not appear in final version
	push 0x000a6b6f
	mov rax, 1
	mov rdi, 1
	mov rsi, rsp
	mov rdx, 3
	syscall
;;;;;;;;;;;;;;;;;;;;;;;;
; close file
	mov rax, 3
	mov rdi, QWORD [rsp + 4096]
	syscall

_final_end:
	leave
	ret
