#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifdef _WIN32
#include <tchar.h>
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h> 
#include <fcntl.h>
#include <unistd.h>
#endif
