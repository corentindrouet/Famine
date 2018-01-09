section .text
	global _thread_create

_thread_create:
	push rdx
	push rsi
	push rdi
	mov rax, 57
	syscall
	pop rdi
	pop rsi
	pop rdx
	cmp rax, 0
	jne _parent_ret
	push rdx
	push rsi
	call rdi
	mov rax, 60
	mov rdi, 0
	syscall

_parent_ret:
	ret
