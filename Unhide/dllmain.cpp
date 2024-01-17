#define WIN32_LEAN_AND_MEAN

#include "Windows.h"

void setDAForWindows() {
	HWND windowHandle = NULL;
	while ((windowHandle = FindWindowEx(NULL, windowHandle, NULL, NULL)) != NULL) {
		SetWindowDisplayAffinity(windowHandle, WDA_NONE);
	}
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		setDAForWindows();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
