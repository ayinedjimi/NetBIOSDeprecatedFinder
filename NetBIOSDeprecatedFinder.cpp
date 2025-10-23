/*
 * NetBIOSDeprecatedFinder - Detecteur NetBIOS et SMBv1
 * Auteur: Ayi NEDJIMI
 * Description: Scanne le reseau local pour detecter les appareils
 *              exposant NetBIOS et SMBv1 (protocoles deprecies)
 * Version: 1.0
 * Date: 2025-10-20
 */

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commctrl.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <fstream>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "netapi32.lib")

// Constantes
#define WM_SCAN_COMPLETE (WM_USER + 1)
#define ID_LISTVIEW 1001
#define ID_EDIT_RANGE 1002
#define ID_BTN_SCAN 1003
#define ID_BTN_EXPORT 1004
#define ID_BTN_CLEAR 1005
#define ID_STATUS 1006
#define ID_LABEL_RANGE 1007

// Structure pour un resultat de scan
struct ScanResult {
    std::wstring ipAddress;
    std::wstring netbiosName;
    std::wstring smbv1Detected;
    std::wstring notes;
};

// Variables globales
HWND g_hMainWindow = nullptr;
HWND g_hListView = nullptr;
HWND g_hEditRange = nullptr;
HWND g_hStatus = nullptr;
std::vector<ScanResult> g_results;
std::mutex g_resultMutex;
bool g_scanning = false;
int g_totalHosts = 0;
int g_scannedHosts = 0;

// Classe RAII pour sockets
class AutoSocket {
private:
    SOCKET sock;
public:
    AutoSocket(SOCKET s = INVALID_SOCKET) : sock(s) {}
    ~AutoSocket() {
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
        }
    }
    operator SOCKET() const { return sock; }
    SOCKET* operator&() { return &sock; }
    SOCKET get() const { return sock; }
    void reset(SOCKET s = INVALID_SOCKET) {
        if (sock != INVALID_SOCKET && sock != s) {
            closesocket(sock);
        }
        sock = s;
    }
};

// Fonction de logging
void LogMessage(const std::wstring& message) {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring logFile = std::wstring(tempPath) + L"WinTools_NetBIOSDeprecatedFinder_log.txt";

    std::wofstream log(logFile, std::ios::app);
    if (log.is_open()) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        log << std::setfill(L'0')
            << std::setw(4) << st.wYear << L"-"
            << std::setw(2) << st.wMonth << L"-"
            << std::setw(2) << st.wDay << L" "
            << std::setw(2) << st.wHour << L":"
            << std::setw(2) << st.wMinute << L":"
            << std::setw(2) << st.wSecond << L" - "
            << message << std::endl;
        log.close();
    }
}

// Convertir IP en string
std::wstring IpToString(DWORD ip) {
    wchar_t buffer[16];
    swprintf_s(buffer, L"%d.%d.%d.%d",
               (ip >> 24) & 0xFF,
               (ip >> 16) & 0xFF,
               (ip >> 8) & 0xFF,
               ip & 0xFF);
    return buffer;
}

// Convertir string en IP
DWORD StringToIp(const std::wstring& str) {
    int a, b, c, d;
    if (swscanf_s(str.c_str(), L"%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
        return 0;
    }
    return (a << 24) | (b << 16) | (c << 8) | d;
}

// Query NetBIOS name service (port 137 UDP)
std::wstring QueryNetBiosName(const std::wstring& ipAddr) {
    AutoSocket sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock.get() == INVALID_SOCKET) {
        return L"";
    }

    // Timeout de 1 seconde
    DWORD timeout = 1000;
    setsockopt(sock.get(), SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    // Convertir IP
    int ipLen = WideCharToMultiByte(CP_UTF8, 0, ipAddr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::vector<char> ipUtf8(ipLen);
    WideCharToMultiByte(CP_UTF8, 0, ipAddr.c_str(), -1, ipUtf8.data(), ipLen, nullptr, nullptr);

    sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(137);
    inet_pton(AF_INET, ipUtf8.data(), &addr.sin_addr);

    // NetBIOS Name Query packet (simplifie)
    unsigned char query[] = {
        0x00, 0x00,                     // Transaction ID
        0x00, 0x10,                     // Flags: Query, Broadcast
        0x00, 0x01,                     // Questions: 1
        0x00, 0x00,                     // Answer RRs
        0x00, 0x00,                     // Authority RRs
        0x00, 0x00,                     // Additional RRs
        // Question section (simplifie - wildcard query)
        0x20,                           // Length: 32
        'C','K','A','A','A','A','A','A','A','A','A','A','A','A','A','A',
        'A','A','A','A','A','A','A','A','A','A','A','A','A','A','A','A',
        0x00,                           // Name end
        0x00, 0x21,                     // Type: NB (NetBIOS)
        0x00, 0x01                      // Class: IN
    };

    int sent = sendto(sock.get(), (char*)query, sizeof(query), 0,
                      (sockaddr*)&addr, sizeof(addr));
    if (sent == SOCKET_ERROR) {
        return L"";
    }

    // Recevoir reponse
    char buffer[512];
    int received = recvfrom(sock.get(), buffer, sizeof(buffer), 0, nullptr, nullptr);

    if (received > 12) {
        // Parser la reponse NetBIOS (tres simplifie)
        // En pratique, il faudrait parser completement le format NetBIOS
        // Pour l'instant, on indique juste qu'il y a eu une reponse
        return L"NetBIOS actif";
    }

    return L"";
}

// Tester SMBv1 sur port 445 TCP
bool TestSmbv1(const std::wstring& ipAddr) {
    AutoSocket sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock.get() == INVALID_SOCKET) {
        return false;
    }

    // Timeout de connexion
    u_long mode = 1; // Non-blocking
    ioctlsocket(sock.get(), FIONBIO, &mode);

    // Convertir IP
    int ipLen = WideCharToMultiByte(CP_UTF8, 0, ipAddr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::vector<char> ipUtf8(ipLen);
    WideCharToMultiByte(CP_UTF8, 0, ipAddr.c_str(), -1, ipUtf8.data(), ipLen, nullptr, nullptr);

    sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(445);
    inet_pton(AF_INET, ipUtf8.data(), &addr.sin_addr);

    connect(sock.get(), (sockaddr*)&addr, sizeof(addr));

    // Attendre la connexion avec select
    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(sock.get(), &writeSet);

    timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    int result = select(0, nullptr, &writeSet, nullptr, &timeout);
    if (result <= 0) {
        return false; // Timeout ou erreur
    }

    // Connexion reussie, envoyer une negociation SMB
    // SMB Negotiate Protocol Request (SMBv1 dialect)
    unsigned char smbNegotiate[] = {
        0x00, 0x00, 0x00, 0x85,         // NetBIOS Session Service
        0xFF, 'S', 'M', 'B',            // SMB Header
        0x72,                           // Negotiate Protocol
        0x00, 0x00, 0x00, 0x00,         // NT Status
        0x18,                           // Flags
        0x07, 0xC0,                     // Flags2
        0x00, 0x00,                     // PID High
        0x00, 0x00, 0x00, 0x00,         // Signature
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,                     // Reserved
        0x00, 0x00,                     // TID
        0xFF, 0xFE,                     // PID
        0x00, 0x00,                     // UID
        0x00, 0x00,                     // MID
        // Parameter block
        0x00,                           // Word Count
        0x62, 0x00,                     // Byte Count
        // Dialects
        0x02, 'P','C',' ','N','E','T','W','O','R','K',' ','P','R','O','G','R','A','M',' ','1','.','0',0x00,
        0x02, 'L','A','N','M','A','N','1','.','0',0x00,
        0x02, 'W','i','n','d','o','w','s',' ','f','o','r',' ','W','o','r','k','g','r','o','u','p','s',' ','3','.','1','a',0x00,
        0x02, 'L','M','1','.','2','X','0','0','2',0x00,
        0x02, 'L','A','N','M','A','N','2','.','1',0x00,
        0x02, 'N','T',' ','L','M',' ','0','.','1','2',0x00
    };

    mode = 0; // Blocking
    ioctlsocket(sock.get(), FIONBIO, &mode);

    int sent = send(sock.get(), (char*)smbNegotiate, sizeof(smbNegotiate), 0);
    if (sent == SOCKET_ERROR) {
        return false;
    }

    // Recevoir reponse
    char buffer[1024];
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(sock.get(), &readSet);

    result = select(0, &readSet, nullptr, nullptr, &timeout);
    if (result <= 0) {
        return false;
    }

    int received = recv(sock.get(), buffer, sizeof(buffer), 0);
    if (received > 4) {
        // Verifier si c'est une reponse SMB valide
        if (buffer[4] == 0xFF && buffer[5] == 'S' && buffer[6] == 'M' && buffer[7] == 'B') {
            // C'est du SMB - verifier si SMBv1 est accepte
            // Si on recoit une reponse au Negotiate avec dialecte SMBv1, c'est que SMBv1 est actif
            return true;
        }
    }

    return false;
}

// Scanner une IP
void ScanHost(const std::wstring& ipAddr) {
    ScanResult result;
    result.ipAddress = ipAddr;
    result.netbiosName = L"N/A";
    result.smbv1Detected = L"Non";
    result.notes = L"";

    // Tester NetBIOS
    std::wstring netbios = QueryNetBiosName(ipAddr);
    if (!netbios.empty()) {
        result.netbiosName = netbios;
        result.notes += L"NetBIOS detecte; ";
    }

    // Tester SMBv1
    if (TestSmbv1(ipAddr)) {
        result.smbv1Detected = L"OUI - CRITIQUE";
        result.notes += L"SMBv1 actif (protocole deprecie et dangereux)";
    } else {
        // Tester juste si le port 445 est ouvert
        AutoSocket testSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (testSock.get() != INVALID_SOCKET) {
            u_long mode = 1;
            ioctlsocket(testSock.get(), FIONBIO, &mode);

            int ipLen = WideCharToMultiByte(CP_UTF8, 0, ipAddr.c_str(), -1, nullptr, 0, nullptr, nullptr);
            std::vector<char> ipUtf8(ipLen);
            WideCharToMultiByte(CP_UTF8, 0, ipAddr.c_str(), -1, ipUtf8.data(), ipLen, nullptr, nullptr);

            sockaddr_in addr = { 0 };
            addr.sin_family = AF_INET;
            addr.sin_port = htons(445);
            inet_pton(AF_INET, ipUtf8.data(), &addr.sin_addr);

            connect(testSock.get(), (sockaddr*)&addr, sizeof(addr));

            fd_set writeSet;
            FD_ZERO(&writeSet);
            FD_SET(testSock.get(), &writeSet);

            timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            if (select(0, nullptr, &writeSet, nullptr, &timeout) > 0) {
                result.notes += L"SMB actif (version non determinee)";
            }
        }
    }

    // Ajouter si quelque chose a ete detecte
    if (!netbios.empty() || result.smbv1Detected != L"Non" || !result.notes.empty()) {
        std::lock_guard<std::mutex> lock(g_resultMutex);
        g_results.push_back(result);
    }

    // Mettre a jour le compteur
    {
        std::lock_guard<std::mutex> lock(g_resultMutex);
        g_scannedHosts++;

        wchar_t status[256];
        swprintf_s(status, L"Scan en cours: %d/%d hotes scannes",
                   g_scannedHosts, g_totalHosts);
        SendMessageW(g_hStatus, SB_SETTEXTW, 0, (LPARAM)status);
    }
}

// Thread de scan
void ScanThread(const std::wstring& range) {
    g_scanning = true;
    g_scannedHosts = 0;

    {
        std::lock_guard<std::mutex> lock(g_resultMutex);
        g_results.clear();
    }

    LogMessage(L"Debut du scan: " + range);

    // Parser la plage (format: 192.168.1.1-192.168.1.254)
    size_t dashPos = range.find(L"-");
    if (dashPos == std::wstring::npos) {
        LogMessage(L"Format de plage invalide");
        PostMessageW(g_hMainWindow, WM_SCAN_COMPLETE, 0, 0);
        g_scanning = false;
        return;
    }

    std::wstring startIp = range.substr(0, dashPos);
    std::wstring endIp = range.substr(dashPos + 1);

    DWORD start = StringToIp(startIp);
    DWORD end = StringToIp(endIp);

    if (start == 0 || end == 0 || start > end) {
        LogMessage(L"Plage IP invalide");
        PostMessageW(g_hMainWindow, WM_SCAN_COMPLETE, 0, 0);
        g_scanning = false;
        return;
    }

    g_totalHosts = (int)(end - start + 1);

    // Scanner chaque IP
    std::vector<std::thread> threads;
    for (DWORD ip = start; ip <= end; ip++) {
        std::wstring ipAddr = IpToString(ip);

        // Limiter le nombre de threads concurrents
        if (threads.size() >= 50) {
            threads[0].join();
            threads.erase(threads.begin());
        }

        threads.push_back(std::thread(ScanHost, ipAddr));
    }

    // Attendre tous les threads
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    LogMessage(L"Scan termine");
    PostMessageW(g_hMainWindow, WM_SCAN_COMPLETE, 0, 0);
    g_scanning = false;
}

// Mettre a jour le ListView
void UpdateListView() {
    ListView_DeleteAllItems(g_hListView);

    std::lock_guard<std::mutex> lock(g_resultMutex);

    for (size_t i = 0; i < g_results.size(); i++) {
        const auto& res = g_results[i];

        LVITEMW lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = static_cast<int>(i);

        // IP
        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPWSTR>(res.ipAddress.c_str());
        ListView_InsertItem(g_hListView, &lvi);

        // NetBIOS Name
        lvi.iSubItem = 1;
        lvi.pszText = const_cast<LPWSTR>(res.netbiosName.c_str());
        ListView_SetItem(g_hListView, &lvi);

        // SMBv1 Detected
        lvi.iSubItem = 2;
        lvi.pszText = const_cast<LPWSTR>(res.smbv1Detected.c_str());
        ListView_SetItem(g_hListView, &lvi);

        // Notes
        lvi.iSubItem = 3;
        lvi.pszText = const_cast<LPWSTR>(res.notes.c_str());
        ListView_SetItem(g_hListView, &lvi);
    }

    wchar_t status[256];
    swprintf_s(status, L"Scan termine - %zu appareil(s) avec NetBIOS/SMB detecte(s)", g_results.size());
    SendMessageW(g_hStatus, SB_SETTEXTW, 0, (LPARAM)status);
}

// Exporter en CSV
void ExportToCSV() {
    wchar_t fileName[MAX_PATH] = L"";
    OPENFILENAMEW ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWindow;
    ofn.lpstrFilter = L"Fichiers CSV (*.csv)\0*.csv\0Tous les fichiers (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"csv";
    ofn.Flags = OFN_OVERWRITEPROMPT;

    if (!GetSaveFileNameW(&ofn)) {
        return;
    }

    std::wofstream csv(fileName, std::ios::binary);
    if (!csv.is_open()) {
        MessageBoxW(g_hMainWindow, L"Impossible de creer le fichier CSV", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    // BOM UTF-8
    const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
    csv.write(reinterpret_cast<const wchar_t*>(bom), sizeof(bom));

    // En-tetes
    csv << L"IP;NetBIOSName;SMBv1Detected;Notes\n";

    std::lock_guard<std::mutex> lock(g_resultMutex);
    for (const auto& res : g_results) {
        csv << res.ipAddress << L";"
            << res.netbiosName << L";"
            << res.smbv1Detected << L";"
            << res.notes << L"\n";
    }

    csv.close();
    LogMessage(std::wstring(L"Export CSV: ") + fileName);
    MessageBoxW(g_hMainWindow, L"Export CSV termine avec succes", L"Information", MB_OK | MB_ICONINFORMATION);
}

// Obtenir la plage IP locale par defaut
std::wstring GetDefaultRange() {
    // Obtenir l'adaptateur reseau principal
    PIP_ADAPTER_INFO adapterInfo = nullptr;
    ULONG bufLen = sizeof(IP_ADAPTER_INFO);
    adapterInfo = (IP_ADAPTER_INFO*)malloc(bufLen);

    if (GetAdaptersInfo(adapterInfo, &bufLen) == ERROR_BUFFER_OVERFLOW) {
        free(adapterInfo);
        adapterInfo = (IP_ADAPTER_INFO*)malloc(bufLen);
    }

    std::wstring range = L"192.168.1.1-192.168.1.254";

    if (GetAdaptersInfo(adapterInfo, &bufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO adapter = adapterInfo;
        while (adapter) {
            // Trouver le premier adaptateur Ethernet actif
            if (adapter->Type == MIB_IF_TYPE_ETHERNET &&
                strcmp(adapter->IpAddressList.IpAddress.String, "0.0.0.0") != 0) {

                // Convertir l'IP en wstring
                int ipLen = MultiByteToWideChar(CP_UTF8, 0, adapter->IpAddressList.IpAddress.String, -1, nullptr, 0);
                std::vector<wchar_t> ipWide(ipLen);
                MultiByteToWideChar(CP_UTF8, 0, adapter->IpAddressList.IpAddress.String, -1, ipWide.data(), ipLen);

                std::wstring ip = ipWide.data();

                // Extraire le reseau (ex: 192.168.1.x)
                size_t lastDot = ip.find_last_of(L".");
                if (lastDot != std::wstring::npos) {
                    std::wstring network = ip.substr(0, lastDot);
                    range = network + L".1-" + network + L".254";
                    break;
                }
            }
            adapter = adapter->Next;
        }
    }

    if (adapterInfo) {
        free(adapterInfo);
    }

    return range;
}

// Creer le ListView
void CreateListViewControl(HWND hwnd) {
    g_hListView = CreateWindowExW(
        0,
        WC_LISTVIEWW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL,
        10, 60, 960, 450,
        hwnd,
        (HMENU)ID_LISTVIEW,
        GetModuleHandle(nullptr),
        nullptr
    );

    ListView_SetExtendedListViewStyle(g_hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    // Colonnes
    LVCOLUMNW lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;

    lvc.pszText = const_cast<LPWSTR>(L"IP");
    lvc.cx = 120;
    ListView_InsertColumn(g_hListView, 0, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"NetBIOS Name");
    lvc.cx = 150;
    ListView_InsertColumn(g_hListView, 1, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"SMBv1 Detecte");
    lvc.cx = 130;
    ListView_InsertColumn(g_hListView, 2, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Notes");
    lvc.cx = 560;
    ListView_InsertColumn(g_hListView, 3, &lvc);
}

// Procedure de fenetre
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        CreateWindowExW(0, L"STATIC", L"Plage IP (ex: 192.168.1.1-192.168.1.254):",
                       WS_CHILD | WS_VISIBLE,
                       10, 15, 280, 20, hwnd, (HMENU)ID_LABEL_RANGE,
                       GetModuleHandle(nullptr), nullptr);

        std::wstring defaultRange = GetDefaultRange();
        g_hEditRange = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", defaultRange.c_str(),
                                      WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                      300, 12, 350, 25, hwnd, (HMENU)ID_EDIT_RANGE,
                                      GetModuleHandle(nullptr), nullptr);

        CreateWindowExW(0, L"BUTTON", L"Scanner",
                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                       660, 12, 100, 25, hwnd, (HMENU)ID_BTN_SCAN,
                       GetModuleHandle(nullptr), nullptr);

        CreateListViewControl(hwnd);

        CreateWindowExW(0, L"BUTTON", L"Exporter CSV",
                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                       10, 520, 120, 30, hwnd, (HMENU)ID_BTN_EXPORT,
                       GetModuleHandle(nullptr), nullptr);

        CreateWindowExW(0, L"BUTTON", L"Effacer",
                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                       140, 520, 100, 30, hwnd, (HMENU)ID_BTN_CLEAR,
                       GetModuleHandle(nullptr), nullptr);

        g_hStatus = CreateWindowExW(0, STATUSCLASSNAMEW, L"Pret - Entrez une plage IP",
                                   WS_CHILD | WS_VISIBLE,
                                   0, 0, 0, 0, hwnd, (HMENU)ID_STATUS,
                                   GetModuleHandle(nullptr), nullptr);
        break;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_BTN_SCAN:
            if (!g_scanning) {
                wchar_t range[256];
                GetWindowTextW(g_hEditRange, range, 256);

                if (wcslen(range) > 0) {
                    std::thread(ScanThread, std::wstring(range)).detach();
                } else {
                    MessageBoxW(hwnd, L"Veuillez entrer une plage IP", L"Erreur", MB_OK | MB_ICONWARNING);
                }
            }
            break;
        case ID_BTN_EXPORT:
            ExportToCSV();
            break;
        case ID_BTN_CLEAR:
            ListView_DeleteAllItems(g_hListView);
            {
                std::lock_guard<std::mutex> lock(g_resultMutex);
                g_results.clear();
            }
            SendMessageW(g_hStatus, SB_SETTEXTW, 0, (LPARAM)L"Liste effacee");
            break;
        }
        break;

    case WM_SCAN_COMPLETE:
        UpdateListView();
        break;

    case WM_SIZE:
        SendMessageW(g_hStatus, WM_SIZE, 0, 0);
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

// Point d'entree
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    // Initialiser WinSock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        MessageBoxW(nullptr, L"Echec WSAStartup", L"Erreur", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Initialiser Common Controls
    INITCOMMONCONTROLSEX icc = { 0 };
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    LogMessage(L"Demarrage de NetBIOSDeprecatedFinder");

    // Enregistrer la classe de fenetre
    WNDCLASSEXW wc = { 0 };
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"NetBIOSDeprecatedFinderClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);

    RegisterClassExW(&wc);

    // Creer la fenetre
    g_hMainWindow = CreateWindowExW(
        0,
        L"NetBIOSDeprecatedFinderClass",
        L"NetBIOSDeprecatedFinder - Detecteur NetBIOS et SMBv1",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1000, 630,
        nullptr, nullptr, hInstance, nullptr
    );

    ShowWindow(g_hMainWindow, nCmdShow);
    UpdateWindow(g_hMainWindow);

    // Boucle de messages
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    WSACleanup();
    LogMessage(L"Fermeture de NetBIOSDeprecatedFinder");
    return static_cast<int>(msg.wParam);
}
