#define DLL_NAME "TestDLL.dll"        //your dll name here

#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>


DWORD getProcessID(WCHAR*);
int enableDebugPrivilege(WCHAR*);

int main(void)
{
	char dllPath[MAX_PATH];
	WCHAR procName[MAX_PATH];

	printf("Target Process Name = ");         //user input target process name for injection
	wscanf(L"%ls", procName);
	printf("\n");

	printf("Initializing...\n");
	printf("Enabling Debug Privilege...");        //get debug privilege(not necessary)
	if (enableDebugPrivilege(SE_DEBUG_NAME))
		printf("warning\nFailed To Gain Debug Privilege.");
	else
		printf("succeed\n");

	printf("Locating Target Process...");

	try
	{
		DWORD targetPID = getProcessID(procName);       //get processID of target process

		if (targetPID == -1)
			throw("error\nFailed To Gain Target ProcessId");

		printf("succeed\nTarget procID Gained: %d.\n", targetPID);
		printf("Accessing Target Process...");

		HANDLE hRemoteProc = OpenProcess(PROCESS_ALL_ACCESS, 0, targetPID);       //get a handle to the process

		if (!hRemoteProc)
			throw("error\nFailed To Gain Access To Target Process");

		printf("succeed\nTarget procHandle Gained: %x.\n", hRemoteProc);
		printf("Initialization Complete.\n\nPreparing For Injection...\n");
		printf("Retrieving DLL Full Path...");

		if (!GetFullPathNameA(DLL_NAME, sizeof(dllPath), dllPath, NULL))        //get the path of the dll
			throw("error: Failed To Gain Path of DLL");

		printf("succeed\nDLL Path Gained: %s.\n", dllPath);
		printf("Allocating Memory In Target Process...");

		LPVOID pRemoteDLLPath = VirtualAllocEx(hRemoteProc, NULL, sizeof(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);       //create a remote memory space in the target process to store the dll path

		if (!pRemoteDLLPath)
			throw("ERROR\nFailed To Allocate Memory In Target Process");

		printf("succeed\nWriting Into Allocated Memory...");

		SIZE_T ReSize;
		if (WriteProcessMemory(hRemoteProc, pRemoteDLLPath, dllPath, sizeof(dllPath) + 1, &ReSize) == NULL)               //write the dll path in the that remote memory space
			throw("error\nFailed To Write DLL Path To Target Process");

		printf("succeed\nLocating LoadLibraryA API...");

		LPTHREAD_START_ROUTINE pLoadLibraryA = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");         //get address of LoadLibraryA for loading dll  into that process
		if (!pLoadLibraryA)
			throw("error\nFailed To Locate LoadLibraryA");

		printf("succeed\nCreating Remote Thread...");

		HANDLE hThread = CreateRemoteThread(hRemoteProc, NULL, 0, pLoadLibraryA, pRemoteDLLPath, 0, NULL);                                           //create a thread that does LoadLibraryA and loads our dll to the process
		if (!hThread)
			throw("error\nFailed To Create Remote Thread");

		printf("succeed\nWaiting For Thread Response...");

		WaitForSingleObject(hThread, INFINITE);

		printf("succeed\nDLL Injection Complete.\n\nReleasing Target Virtual Memory Space...");
    
    //-----------------------------At this point the injection process is complete.-------------------------
    //following up are some cleanup afterwards

		if (!VirtualFreeEx(hRemoteProc, pRemoteDLLPath, 0, MEM_RELEASE))      //free the remote memory space
			throw("warning\nFailed To Release Target Virtual Memory Space");
		else
			printf("succeed\n");

		printf("Closing Resources...");
		CloseHandle(hThread);                                               //destory handles
		CloseHandle(hRemoteProc);
		printf("succeed\nProgram Terminating...");
	}
  //--------------error processing---------------
	catch (char *errorMsg)
	{
		printf("%s. Error Code: %d.\n", errorMsg, GetLastError());
		printf("\n\n");
		system("pause");
		return -1;
	}

	printf("\n\n");
	system("pause");
	return GetLastError();
}


//Retrieves Target Process PID
//Retrieve: WCHAR String Ptr To Process Name
//Return: succeed: Target Process PID; Failed: -1
DWORD getProcessID(WCHAR *procName)
{
	PROCESSENTRY32 pe32;

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return -1;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32))
		return -1;

	do {
		if (wcscmp(procName, pe32.szExeFile) == 0)
			return pe32.th32ProcessID;
	} while (Process32Next(hProcessSnap, &pe32));

	return -1;
}

//Gain Privilege For Current Program
//Retrieve: Privilege Name
//Return: succeed: 0; Failed: error Code
int enableDebugPrivilege(WCHAR *privilegeName)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID pluid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return GetLastError();

	if (!LookupPrivilegeValue(NULL, privilegeName, &pluid))
		return GetLastError();

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = pluid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (AdjustTokenPrivileges(hToken, 0, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL) == 0)
		return GetLastError();

	return 0;
}
