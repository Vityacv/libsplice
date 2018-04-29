#include "pch.h"
#include "splice.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>


#undef _tmain
#ifdef _UNICODE
#define _tmain wmain
#else
#define _tmain main
#endif

extern int _CRT_glob;
extern 
#ifdef __cplusplus
"C" 
#endif
void __wgetmainargs(int*,wchar_t***,wchar_t***,int,int*);

#ifdef MAIN_USE_ENVP
int __fastcall wmain(int argc, wchar_t *argv[], wchar_t *envp[]);
#else
int __fastcall wmain(int argc, wchar_t *argv[]);
#endif



extern "C" int entry() {
	wchar_t **enpv, **argv;
	int argc, si = 0;
	__wgetmainargs(&argc, &argv, &enpv, _CRT_glob, &si); // this also creates the global variable __wargv
#ifdef MAIN_USE_ENVP
	return wmain(argc, argv, enpv);
#else
	return wmain(argc, argv);
#endif
}


unsigned __fastcall hookTest1(reg * p){
	printf("tax: %p\ntcx: %p\ntdx: %p\nflags: %p\n",p->tax,p->tcx,p->tdx,p->tflags);
	uintptr_t v0;
	wchar_t * v1, * v2;
	unsigned v3;
	#ifdef _M_X64
	v0 = p->tcx;
	v1 = (wchar_t *)p->tdx;
	v2= (wchar_t *)p->r8;
	v3 = p->r9;
	p->argcnt=0;
	#define convention __fastcall
	#else
	v0 = p->v0;
	v1 = (wchar_t *)p->v1;
	v2= (wchar_t *)p->v2;
	v3 = p->v3;
	p->argcnt=4;
	#define convention __stdcall
	#endif
	wchar_t buf[1024];
	wsprintfW(buf,L"%s %s %p", v2, v1, 100500 );
	wprintf(buf);
 p->tax=((unsigned (convention *)(uintptr_t,wchar_t *,wchar_t *,unsigned))p->hook)(v0,v1,v2,v3);
 p->state=1;
}

unsigned __fastcall hookTest2(reg * p){
	p->state=2;
	p->argcnt=5;
}

unsigned __fastcall hookTest3(reg * p){
	uintptr_t v0;
	uintptr_t v1, v2;
	uintptr_t v3;
		#ifdef _M_X64
	v0 = p->tcx;
	v1 = p->tdx;
	v2= p->r8;
	v3 = p->r9;
	#else
	v0 = p->v0;
	v1 = p->v1;
	v2= p->v2;
	v3 = p->v3;
	//p->argcnt=5;
	//p->state=1;
	#endif

	printf("%p %p %p %p",v0,v1,v2,v3);
}


int __fastcall _tmain(int argc, TCHAR *argv[])
{
				spliceUp((void *)wsprintfW,(void *)hookTest3);
				spliceUp((void *)MessageBoxW,(void *)hookTest1);
				MessageBox(0,argv[0],L"test",0);
				spliceDown((void *)MessageBoxW);
				//spliceUp((void *)((unsigned char *)MessageBoxW+0x13),(void *)hookTest2);
				MessageBox(0,argv[0],L"test",0);
				freeSplice();
    return 0;
}
