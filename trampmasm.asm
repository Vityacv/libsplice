option casemap:none

IFDEF RAX
tword typedef QWORD
_M_X64 typedef QWORD
_bits equ sizeof tword
regcnt equ 16
regsize equ (sizeof reg-18*_bits) ;18 - (hook + v15)
pushft equ pushfq
popft equ popfq
tax equ rax
tcx equ rcx
tdx equ rdx
tbx equ rbx
tsi equ rsi
tdi equ rdi
tsp equ rsp
tbp equ rbp
extern getTramp:PROC
ELSE
.686
.model  flat,c
tword typedef DWORD
_bits equ sizeof tword
regcnt equ 8
regsize equ (sizeof reg-18*_bits)
pushft equ pushfd
popft equ popfd
tax equ eax
tcx equ ecx
tdx equ edx
tbx equ ebx
tsi equ esi
tdi equ edi
tsp equ esp
tbp equ ebp
EXTERNDEF SYSCALL @getTramp@4:PROC
getTramp TEXTEQU <@getTramp@4>
ENDIF

reg STRUCT
	origFunc tword ? ;alignment
	pt tword ?
	state tword ?
	argcnt tword ?
IFDEF _M_X64
	_r15 tword ?
	_r14 tword ?
	_r13 tword ?
	_r12 tword ?
	_r11 tword ?
	_r10 tword ?
	_r9 tword ?
	_r8 tword ?
ENDIF
	_tdi tword ?
	_tsi tword ?
	_tbp tword ?
	_tbx tword ?
	_tdx tword ?
	_tcx tword ?
	_tax tword ?
	tflags tword ?
	hook tword ?
	retadr tword ?
	v0 tword ?
	v1 tword ?
	v2 tword ?
	v3 tword ?
	v4 tword ?
	v5 tword ?
	v6 tword ?
	v7 tword ?
	v8 tword ?
	v9 tword ?
	v10 tword ?
	v11 tword ?
	v12 tword ?
	v13 tword ?
	v14 tword ?
	v15 tword ?
reg ENDS

tramp STRUCT _bits
	hookPoint tword ?
	hookFunc tword ?
	origFunc tword ?
	codebuf   BYTE 24 dup(?)
IFDEF _M_X64
	jmpbuf   BYTE 14 dup(?)
ENDIF
 origLen BYTE ?
 inuse BYTE ?
	next tword ?
tramp ENDS

.code
prologueSaveReg macro
	pushft
	push	tax
	push	tcx
	push	tdx
	push tbx
	push tbp
	push tsi
	push tdi
	IFDEF	_M_X64
	push	r8
	push	r9
	push	r10
	push	r11
	push	r12
	push	r13
	push	r14
	push	r15
	ENDIF
	sub tsp,_bits*4
endm

epilogueRestoreReg macro
	add tsp,_bits*4
	IFDEF _M_X64
	pop		r15
	pop		r14
	pop		r13
	pop		r12
	pop		r11
	pop		r10
	pop		r9
	pop		r8
	ENDIF
	pop  tdi
	pop  tsi
	pop  tbp
	pop  tbx
	pop		tdx
	pop		tcx
	pop		tax
	popft
endm

public trampoline      ; make both functions available

trampoline  proc
OPTION PROLOGUE:NONE, EPILOGUE:NONE
	prologueSaveReg
	xor tcx,tcx
	mov [tsp].reg.state,tcx
	mov [tsp].reg.argcnt,tcx
	mov tcx, [tsp].reg.hook
	sub tcx,5
	call getTramp
	mov [tsp].reg.pt,tax
	mov tcx,[tax].tramp.origFunc
	mov [tax].tramp.inuse,1
	mov [tsp].reg.hook,tcx
	mov [tsp].reg.origFunc,tcx
	mov tcx,tsp
	call [tax].tramp.hookFunc
	mov tcx,[tsp].reg.origFunc
	mov [tsp].reg.hook,tcx
	mov tax,[tsp].reg.pt
	mov [tax].tramp.inuse,0
	mov tax,[tsp].reg.state
	cmp tax,1
	jz retargcnt
	ja retwithoutorig
	retrestorereg:
	epilogueRestoreReg
	ret
	retargcnt:
	mov tax,[tsp].reg.argcnt
	lea tax,[(tax*_bits)+_bits+_bits] ;hook + return
	mov [tsp].reg.argcnt,tax
	retrestorereg2:
	epilogueRestoreReg
	mov tcx,[tsp-regsize].reg.retadr
	add tsp,[tsp-regsize].reg.argcnt
	jmp tcx
	retwithoutorig:
	mov tcx,[tsp].reg.pt
	movzx tax,[tcx].tramp.origLen
	add tax,[tcx].tramp.origFunc
	mov [tsp].reg.hook,tax
	mov tax,[tsp].reg.argcnt
	test tax,tax
	jnz retwithoutorigargcnt
	jmp retrestorereg
	retwithoutorigargcnt:
	lea tax,[(tax*_bits)+_bits] ;return
	mov [tsp].reg.argcnt,tax
	epilogueRestoreReg
	mov tcx,[tsp-regsize].reg.hook
	add tsp,[tsp-regsize].reg.argcnt
	jmp tcx
	;jmp retrestorereg2
trampoline  endp
end
