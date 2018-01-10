section .text
	global _thread_create

_thread_create:
	mov rax, 0
	push rax
	push rsi ; push file path
	mov rax, 0x1122334455667788
	push rax
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
