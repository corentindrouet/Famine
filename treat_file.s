section .text:
	global _treat_file

_treat_file:
	enter 4128, 0 ; equal to push rbp - mov rbp, rsp - sub rsp, 16
				; sub 8 bytes for read return value
				; sub 8 bytes for fd
				; sub 4096 bytes for read (buffer)
	cmp rdi, 0
	je _end
	mov rax, 2
	mov rsi, 2
	xor rdx, rdx
	syscall
	cmp rax, -1
	jle _end
	mov QWORD [rsp + 4096], rax

_read_file_header_64:
	xor rax, rax
	mov rdi, QWORD [rsp + 4096]
	mov rsi, rsp
	mov rdx, 64
	syscall
	cmp rax, 64
	jl _end
	cmp DWORD [rsp], 0x464c457f
	jne _end
	cmp BYTE [rsp + 4], 2
	jne _end
	cmp WORD [rsp + 16], 2
	jne _end
	push 0x000a6b6f
	mov rax, 1
	mov rdi, 1
	mov rsi, rsp
	mov rdx, 3
	syscall
	mov rax, 3
	mov rdi, QWORD [rsp + 4096]
	syscall

_end:
	leave
	ret
