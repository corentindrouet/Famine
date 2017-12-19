;; sys/syscall.h
%define SYS_write	1
%define SYS_mmap	9
%define SYS_clone	56
%define SYS_exit	60

;; unistd.h
%define STDIN		0
%define STDOUT		1
%define STDERR		2

;; sched.h
%define CLONE_VM	0x00000100
%define CLONE_FS	0x00000200
%define CLONE_FILES	0x00000400
%define CLONE_SIGHAND	0x00000800
%define CLONE_PARENT	0x00008000
%define CLONE_THREAD	0x00010000
%define CLONE_IO	0x80000000

;; sys/mman.h
%define MAP_GROWSDOWN	0x0100
%define MAP_ANONYMOUS	0x0020
%define MAP_PRIVATE	0x0002
%define PROT_READ	0x1
%define PROT_WRITE	0x2
%define PROT_EXEC	0x4

%define THREAD_FLAGS \
 CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_PARENT|CLONE_THREAD|CLONE_IO

%define STACK_SIZE	(4096 * 1024)

section .text
	global _thread_create
	extern _force_exit

;; long thread_create(void (*)(void))
_thread_create:
	push rdx
	push rsi
	push rdi ; mov the function to call on the stack
	call stack_create ; create the stack for our new thread
; Now here is the big part:
;	rax is our stack pointer, but he is in the bottom of the mmap
;	when we will call sys_clone, our thread will start at the ret instruction after the syscall instruction
;	so we will ret to the address in the top of his stack.
;	rax is the bottom of this stack, so we add STACK_SIZE to rax to go at the top of the stack, and then we
;	sub 8 bytes for our return address, and here we store the address passed in parameter in thread_create.
;	so the ret instruction will pop out the address we stored, and jmp to it.
;	that why we ABSOLUTELLY NEED this ret after the syscall
	lea rsi, [rax + STACK_SIZE - 32]
	pop QWORD [rsi]
	lea rax, [rel _force_exit]
	mov QWORD [rsi + 8], rax
	pop QWORD [rsi + 16]
	pop QWORD [rsi + 24]
	mov rdi, THREAD_FLAGS
	mov rax, SYS_clone
	syscall
	ret

;; void *stack_create(void)
;; here it's just a mmap, but we add MAP_GROWSDOWN to have a stack like addresses.
stack_create:
	mov rdi, 0
	mov rsi, STACK_SIZE
	mov rdx, PROT_WRITE | PROT_READ
	mov r10, MAP_ANONYMOUS | MAP_PRIVATE | MAP_GROWSDOWN
	mov rax, SYS_mmap
	syscall
	ret
