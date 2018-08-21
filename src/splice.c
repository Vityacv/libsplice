#include "pch.h"
#include "splice.h"
#include "splicealloc.h"
#include "dizahex.h"



#ifdef __cplusplus
extern "C" {
#endif
ptramp trampGlobal;
void __cdecl trampoline();
uint32_t __fastcall getOpcodeLen(void *adr) {
  DIZAHEX_STRUCT diza = {};
#if defined _M_X64
  diza.mode = DISASM_MODE_64;
#else
  diza.mode = DISASM_MODE_32;
#endif
  return dizahex_disasm((uint8_t *)adr, &diza);
}

ptramp createTramp(unsigned char *hookPoint) {
  ptramp pt;
  pt = (ptramp)AllocateBuffer(hookPoint);
  if (!pt) return nullptr;
  {
    if(!VirtualProtect((void *)hookPoint, 32, PAGE_EXECUTE_READWRITE, (LPDWORD)&pt->origProtect))
    	return nullptr;
  }
  pt->hookPoint = hookPoint;
  pt->next = trampGlobal;
  trampGlobal = pt;
  return pt;
}

void __fastcall freeTramp(void *hookPoint) {
  ptramp pt = trampGlobal;
  ptramp prevpt = NULL;
  while (pt) {
    if (pt->hookPoint == hookPoint) {
      if (prevpt)
        prevpt->next = pt->next;
      else
        trampGlobal = pt->next;
      FreeBuffer(pt);
      return;
    }
    prevpt = pt;
    pt = pt->next;
  }
}

ptramp __fastcall getTramp(void * hookPoint) {
  ptramp pt = trampGlobal;
  if (pt) {
    while (pt) {
      if (pt->hookPoint == hookPoint) return pt;
      pt = pt->next;
    }
  }
  return 0;
}

unsigned __fastcall getTrampCount() {
  ptramp pt = trampGlobal;
  unsigned i = 0;
  if (pt) {
    while (pt) {
      pt = pt->next;
      i++;
    }
  }
  return i;
}

void __fastcall blockAllTramp() {
  ptramp pt = trampGlobal;
  if (pt) {
    while (pt) {
      tramp *temp = pt->next;
      //if(IsExecutableAddress((void *)pt->hookPoint))
        uintptr_t oldProtect;
        if(VirtualProtect((void *)pt->hookPoint, 32, PAGE_EXECUTE_READWRITE, (LPDWORD)&oldProtect))
        {
      	   *(unsigned short *)(pt->hookPoint)=0xFEEB;
           VirtualProtect((void *)pt->hookPoint, 32, pt->origProtect, (LPDWORD)&oldProtect);
        }

      pt = temp;
    }
  }
}

void __fastcall freeAllTramp() {
  ptramp pt = trampGlobal;
  if (pt) {
    while (pt) {
      tramp *temp = pt->next;
      if(!pt->inuse)
        spliceDown(pt->hookPoint);
      pt = temp;
    }
  }
}

void __fastcall freeSplice(){
  while(getTrampCount()){
        blockAllTramp();
        freeAllTramp();
      }
}

unsigned char __fastcall checkHookPoint(unsigned char *orig, ptramp pt,
                                        unsigned char *hookPoint) {
  unsigned origLen = 0;

  if (!orig) orig = pt->codebuf;
  do {
    uintptr_t len = getOpcodeLen(hookPoint);
    if (!len) return 0;

    if (5 == len && (0xE8 == *hookPoint || 0xE9 == *hookPoint)) {
      pt->codebuf[origLen] = *hookPoint;
      unsigned char *dest = (hookPoint + 5) + *(unsigned *)(hookPoint + 1);
      unsigned offs = dest - (orig + origLen + 5);
      *(unsigned *)(pt->codebuf + origLen + 1) = offs;
    } else {
      if (1 == len && (0xC3 == *hookPoint || 0xCB == *hookPoint) &&
          origLen + 1 < 5)
        return 0;

      else if (3 == len && (0xC2 == *hookPoint || 0xCA == *hookPoint) &&
               origLen + 3 < 5)
        return 0;

      memcpy(pt->codebuf + origLen, hookPoint, len);
    }
    hookPoint += len;
    origLen += len;

  } while (origLen < 5);

  pt->origLen = origLen;
  return 1;
}

ptramp __fastcall spliceUp(void *hookPoint, void *hookFunc) {
  if (!hookPoint) return 0;
  ptramp pt = getTramp(hookPoint);
  if(pt)
    return pt;
  pt = createTramp((unsigned char *)hookPoint);
  if (!pt) return 0;
  if (!checkHookPoint(0, pt, (unsigned char *)hookPoint)) {
    freeTramp(hookPoint);
    return 0;
  }
  if (hookFunc != NULL)
    pt->hookFunc = (unsigned char *)hookFunc;
  else
    pt->hookFunc = nullptr;
  pt->origFunc = pt->codebuf;
  unsigned origLen = pt->origLen;
#if defined _M_X64
  *(unsigned short *)((unsigned char *)pt->codebuf + pt->origLen) = 0x25FF;
  *(unsigned long *)((unsigned char *)pt->codebuf + pt->origLen + 2) = 0;
  *(uintptr_t *)((unsigned char *)pt->codebuf + pt->origLen + 6) =
      (uintptr_t)((unsigned char *)hookPoint + origLen );
#else
  {
    unsigned char *adr = pt->codebuf + pt->origLen;
    *(adr) = 0xE9;
    *(unsigned *)(adr + 1) = ((unsigned char *)hookPoint + pt->origLen) -
                             (pt->codebuf + origLen + 5);
  }
#endif
  unsigned rel32;

#if defined _M_X64
  rel32 = (((PBYTE)pt->jmpbuf - (PBYTE)hookPoint) - 5);
  //*(unsigned*)(pt->jmpbuf)=0x58d4850;
  //*(unsigned*)(pt->jmpbuf+4)=0xFFFFFFC4;//-0x34
  *(uintptr_t *)(pt->jmpbuf)=0x158D48E024548948;
  *(uintptr_t *)(pt->jmpbuf+8)=0x000025FFFFFFFFC0;
  
  //*(unsigned short *)(pt->jmpbuf+8) = 0x25FF;
  //*(unsigned long *)((char *)pt->jmpbuf + 13) = 0;
  *(uintptr_t *)((char *)pt->jmpbuf + 18) = (uintptr_t)trampoline;
#else
  rel32 = (((unsigned char *)pt->jmpbuf - (unsigned char *)hookPoint) - 5);
  *(unsigned *)(pt->jmpbuf)=0xF0245489;
  *(unsigned char*)(pt->jmpbuf+4)=0xBA;
  *(uintptr_t*)(pt->jmpbuf+5)=(uintptr_t)pt;
  *(pt->jmpbuf+9)=0xE9;
  *(uintptr_t*)(pt->jmpbuf+10)=getRel4FromVal((pt->jmpbuf+10),trampoline);
#endif
  *(unsigned char *)(hookPoint) = 0xE8;
  *(unsigned *)((unsigned char *)hookPoint + 1) = rel32;
  uintptr_t oldProtect;
  VirtualProtect((void *)hookPoint, 32, pt->origProtect, (LPDWORD)&oldProtect);
  return pt;
}
unsigned char __fastcall spliceDown(void * hookPoint) {
  ptramp pt = getTramp(hookPoint);
  if(!pt)
  	return 0;
  //if(IsExecutableAddress((void *)hookPoint)){
  {
  uintptr_t oldProtect;
  if(VirtualProtect((void *)hookPoint, 32, PAGE_EXECUTE_READWRITE, (LPDWORD)&oldProtect)){
    checkHookPoint((unsigned char*)hookPoint, pt,(unsigned char*)pt->codebuf);
    memcpy(hookPoint, pt->codebuf, pt->origLen);
    VirtualProtect((void *)hookPoint, 32, pt->origProtect, (LPDWORD)&oldProtect);
  }
  }
  freeTramp(hookPoint);
  return TRUE;
}

#ifdef __cplusplus
}
#endif



