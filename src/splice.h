#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#ifndef _WIN32
#define _M_X64
#endif

typedef struct tramp *ptramp;

struct reg {
	uintptr_t origFunc;
	ptramp pt;
	unsigned char state;
	uintptr_t argcnt;
#ifdef _M_X64
	uintptr_t r15;
	uintptr_t r14;
	uintptr_t r13;
	uintptr_t r12;
	uintptr_t r11;
	uintptr_t r10;
	uintptr_t r9;
	uintptr_t r8;
#endif
	uintptr_t tdi;
	uintptr_t tsi;
	uintptr_t tbp;
	uintptr_t tbx;
	uintptr_t tdx;
	uintptr_t tcx;
	uintptr_t tax;
	uintptr_t tflags;
	uintptr_t hook;
	uintptr_t retadr;
	uintptr_t v0;
	uintptr_t v1;
	uintptr_t v2;
	uintptr_t v3;
	uintptr_t v4;
	uintptr_t v5;
	uintptr_t v6;
	uintptr_t v7;
	uintptr_t v8;
	uintptr_t v9;
	uintptr_t v10;
	uintptr_t v11;
	uintptr_t v12;
	uintptr_t v13;
	uintptr_t v14;
	uintptr_t v15;
};

struct tramp {
  unsigned char *hookPoint; //point of hook
  unsigned char *hookFunc; //function to execute
  unsigned char *origFunc; //need for custom codebuf
  unsigned origProtect; //original protection of page
  unsigned char codebuf[30]; //code buffer containing original code in most cases
#if defined _M_X64
  unsigned char jmpbuf[28]; //buffer of jump to hook function
#else
  unsigned char jmpbuf[14];
#endif
  unsigned char origLen; //length of original code
  unsigned char inuse;
  ptramp next;
};

ptramp regcall spliceUp(void *, void *);
unsigned char regcall spliceDown(void *);
void regcall freeSplice();
ptramp regcall getTramp(void *);
unsigned regcall getTrampCount();
uint32_t regcall getOpcodeLen(void *adr);
unsigned char regcall checkHookPoint(unsigned char *orig, ptramp pt,
                                        unsigned char *hookPoint);
#ifdef _M_X64
#define getVal4FromRel(x) (unsigned char *)x+(*(uint32_t *)((unsigned char *)x)>0x7FFFFFFF?0xFFFFFFFF00000000|*(uint32_t *)((unsigned char *)x):*(uint32_t *)((unsigned char *)x))+4
#else
#define getVal4FromRel(x) (unsigned char *)x+(*(uint32_t *)((unsigned char *)x))+4
#endif
#define getRel4FromVal(x,y) ((unsigned char *)y-(unsigned char *)x)-4


#ifdef __cplusplus
}
#endif
