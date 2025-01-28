// TestExecutable.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include "TestLibrary.h"
#include "SignatureVerification.h"
#include "AuthenticodeInformation.h"

int main()
{
    
	HMODULE hModule = LoadLibraryEx(L"TestLibrary.dll", NULL, 0);
	wchar_t fileName[MAX_PATH];
	
	if (!hModule)
	{
		std::cout << "Load Failed" << std::endl;
		DWORD error = GetLastError();
		std::cout << "Error : " << error << std::endl;
	}

	DWORD ret = GetModuleFileName(hModule, fileName, MAX_PATH);
	if (!ret)
	{
		std::cout << "Could not determine the file name for module TestLibrary.dll" << std::endl;
	}
	else
	{
		std::wcout << L"Module TestLibrary.dll was loaded from " << fileName << std::endl;

	}

	
	VerifyEmbeddedSignature(fileName);
	GetAuthenticodeInformation(fileName);

	PrintMessage();
}

