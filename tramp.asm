%if __BITS__ == 64
	%define tword qword
	%define _M_X64 qword
	%define _bits 8
	%define regcnt 16
	%define rest resq
	%define regsize reg_size - 2 * _bits ;2 - (hook + retadr)
	%define pushft pushfq
	%define popft popfq
	%define tax rax
	%define tcx rcx
	%define tdx rdx
	%define tbx rbx
	%define tsi rsi
	%define tdi rdi
	%define tsp rsp
	%define tbp rbp
%else
	%define trampoline _trampoline
	%define trampGlobal _trampGlobal
	%define getTramp @getTramp@4
	%define tword dword
	%define _bits 4
	%define regcnt 8
	%define rest resd
	%define regsize reg_size - 2 * _bits
	%define pushft pushfd
	%define popft popfd
	%define tax eax
	%define tcx ecx
	%define tdx edx
	%define tbx ebx
	%define tsi esi
	%define tdi edi
	%define tsp esp
	%define tbp ebp
%endif

struc reg
	.origFunc rest 1
	.pt rest 1
	.state rest 1
	.argcnt rest 1
	.tflags rest 1
	%ifdef _M_X64
	._r15 rest 1
	._r14 rest 1
	._r13 rest 1
	._r12 rest 1
	._r11 rest 1
	._r10 rest 1
	._r9 rest 1
	._r8 rest 1
	%endif
	._tdi rest 1
	._tsi rest 1
	._tbp rest 1
	._tbx rest 1
	._tdx rest 1
	._tcx rest 1
	._tax rest 1
	.hook rest 1
	.retadr rest 1
endstruc

struc tramp
	.hookPoint rest 1
	.hookFunc rest 1
	.origFunc rest 1
	.codebuf resb 24
	%ifdef _M_X64
	.jmpbuf resb 24
	%else
	.jmpbuf resb 14
	%endif
	.origLen resb 1
	.inuse resb 1
	alignb _bits
	.next rest 1
endstruc


%macro prologueSaveRegBegin 0
	;push tax
	;%ifndef _M_X64
	;xchg tax,tword[tsp]
	;%endif
	push tcx
	push tdx
	push tbx
	push tbp
	push tsi
	push tdi
	%ifdef	_M_X64
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	%endif
	pushft
	sub tsp,_bits*4
%endmacro


%macro prologueSaveReg 0
	push tax
	push tcx
	push tdx
	push tbx
	push tbp
	push tsi
	push tdi
	%ifdef	_M_X64
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	%endif
	pushft
	sub tsp,_bits*4
%endmacro

%macro epilogueRestoreReg 0
	add tsp,_bits*4
	popft
	%ifdef	_M_X64
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	%endif
	pop tdi
	pop tsi
	pop tbp
	pop tbx
	pop tdx
	pop tcx
	pop tax
%endmacro

extern getTramp
extern trampGlobal

%macro getTrampData 1
%ifdef	_M_X64
	default rel
%endif
	mov tax,[trampGlobal]
	test tax,tax
	%%.cmpnext:
	cmp tword[tax],%1
	jz %%.retval
	mov tax,tword[tax+tramp.next]
	test tax,tax
	jnz %%.cmpnext
	%%.retval:
%endmacro


global trampoline
trampoline:
	prologueSaveRegBegin
	xor tcx,tcx
	mov [tsp+reg.state],tcx
	mov [tsp+reg.argcnt],tcx
	;mov tcx, [tsp+reg.hook]
	;sub tcx,5
	;getTrampData(tcx)
	;call getTramp
	mov [tsp+reg.pt],tax
	mov tcx,[tax+tramp.origFunc]
	mov byte [tax+tramp.inuse],1
	mov [tsp+reg.hook],tcx
	mov [tsp+reg.origFunc],tcx
	mov tcx,tsp
	call [tax+tramp.hookFunc]
	mov tcx,[tsp+reg.origFunc]
	mov [tsp+reg.hook],tcx
	mov tax,[tsp+reg.pt]
	mov byte [tax+tramp.inuse],0
	mov tax,[tsp+reg.state]
	cmp tax,1
	jz retargcnt
	ja retwithoutorig
	retrestorereg:
	epilogueRestoreReg
	ret
	retargcnt:
	mov tax,[tsp+reg.argcnt]
	lea tax,[(tax*_bits)+_bits+_bits] ;hook + return
	mov [tsp+reg.argcnt],tax
	retrestorereg2:
	epilogueRestoreReg
	mov tcx,[tsp-(regsize-reg.retadr)]
	add tsp,[tsp-(regsize-reg.argcnt)]
	jmp tcx
	retwithoutorig:
	mov tcx,[tsp+reg.pt]
	movzx tax,byte [tcx+tramp.origLen]
	add tax,[tcx+tramp.origFunc]
	mov [tsp+reg.hook],tax
	mov tax,[tsp+reg.argcnt]
	test tax,tax
	jnz retwithoutorigargcnt
	jmp retrestorereg
	retwithoutorigargcnt:
	lea tax,[(tax*_bits)+_bits] ;return
	mov [tsp+reg.argcnt],tax
	epilogueRestoreReg
	mov tcx,[tsp-(regsize-reg.hook)]
	add tsp,[tsp-(regsize-reg.argcnt)]
	jmp tcx
