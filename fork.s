section .text
	global _thread_create
	extern _verif

_thread_create:
	mov rax, 0
	push rax
	push rsi ; push file path
	lea rax, [rel _verif]
	push rax
;	push rsp
;	add QWORD [rsp], 16
	push rdx ; push file name
	push rdx ; push path/name
	mov rax, 57
	syscall
	cmp rax, 0
	jne _parent_ret
	mov rax, 59
	mov rdi, QWORD [rsp]
	mov rsi, rsp
	add rsi, 8
	xor rdx, rdx
	syscall

_parent_ret:
	pop rdi
	pop rdi
	pop rdi
	pop rdi
	pop rdi
	ret
