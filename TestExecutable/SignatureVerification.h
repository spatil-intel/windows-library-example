#pragma once
#include <Windows.h>
#include<iostream>
#include <WinTrust.h>
#include <Softpub.h>
BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile);