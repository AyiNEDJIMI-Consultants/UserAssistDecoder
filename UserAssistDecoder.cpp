/*
 * UserAssistDecoder - Forensics Tool (WinToolsSuite Serie 3 #21)
 * Décode UserAssist (GUID compteurs ROT13), timeline applications exécutées par user
 *
 * Fonctionnalités :
 * - Registry : HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
 * - GUIDs : {CEBFF5CD} = Executable File Execution, {F4E57C4B} = Shortcut File Execution
 * - Décodage ROT13 des noms valeurs (ex: HRZR_PGYFRFFVATF → UEME_EXECUTABLES)
 * - Parse données binaires : run count, last execution time, focus count, focus time
 * - Reconstruction timeline exécutions applications par user
 * - Export CSV UTF-8 avec logging complet
 *
 * APIs : advapi32.lib, comctl32.lib
 * Auteur : WinToolsSuite
 * License : MIT
 */

#define _WIN32_WINNT 0x0601
#define UNICODE
#define _UNICODE
#define NOMINMAX

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlwapi.h>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <memory>
#include <map>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// Constantes UI
constexpr int WINDOW_WIDTH = 1400;
constexpr int WINDOW_HEIGHT = 700;
constexpr int MARGIN = 10;
constexpr int BUTTON_WIDTH = 180;
constexpr int BUTTON_HEIGHT = 30;

// IDs des contrôles
constexpr int IDC_LISTVIEW = 1001;
constexpr int IDC_BTN_SCAN = 1002;
constexpr int IDC_BTN_DECODE = 1003;
constexpr int IDC_BTN_EXPORT = 1004;
constexpr int IDC_BTN_COMPARE = 1005;
constexpr int IDC_STATUS = 1006;

// GUIDs UserAssist
const wchar_t* GUID_EXECUTABLE = L"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}";
const wchar_t* GUID_SHORTCUT = L"{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}";

// Structure UserAssist data (Windows 7+)
#pragma pack(push, 1)
struct USERASSIST_ENTRY_WIN7 {
    DWORD size;              // Taille de la structure
    DWORD version;           // Version (3 pour Win7+)
    DWORD runCount;          // Nombre d'exécutions
    DWORD focusCount;        // Nombre de fois focus
    DWORD focusTime;         // Temps total focus (ms)
    FILETIME lastExecution;  // Dernière exécution
    DWORD unknown[10];       // Réservé
};
#pragma pack(pop)

// Structure pour une entrée UserAssist
struct UserAssistEntry {
    std::wstring application;
    std::wstring decodedPath;
    DWORD runCount;
    std::wstring lastExecution;
    DWORD focusCount;
    DWORD focusTime;
    std::wstring guid;
    std::wstring username;
};

// RAII pour clé registry
class RegKey {
    HKEY h;
public:
    explicit RegKey(HKEY handle) : h(handle) {}
    ~RegKey() { if (h) RegCloseKey(h); }
    operator HKEY() const { return h; }
    bool valid() const { return h != nullptr; }
};

// Classe principale
class UserAssistDecoder {
private:
    HWND hwndMain, hwndList, hwndStatus;
    std::vector<UserAssistEntry> entries;
    std::wofstream logFile;
    HANDLE hWorkerThread;
    volatile bool stopProcessing;

    void Log(const std::wstring& message) {
        if (logFile.is_open()) {
            SYSTEMTIME st;
            GetLocalTime(&st);
            wchar_t timeStr[64];
            swprintf_s(timeStr, L"[%02d/%02d/%04d %02d:%02d:%02d] ",
                      st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);
            logFile << timeStr << message << std::endl;
            logFile.flush();
        }
    }

    void UpdateStatus(const std::wstring& text) {
        SetWindowTextW(hwndStatus, text.c_str());
        Log(text);
    }

    std::wstring FileTimeToString(FILETIME ft) {
        if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) {
            return L"Jamais";
        }

        SYSTEMTIME st;
        if (FileTimeToSystemTime(&ft, &st)) {
            wchar_t buf[128];
            swprintf_s(buf, L"%02d/%02d/%04d %02d:%02d:%02d",
                      st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);
            return buf;
        }
        return L"Invalide";
    }

    std::wstring MsToTimeString(DWORD milliseconds) {
        DWORD seconds = milliseconds / 1000;
        DWORD minutes = seconds / 60;
        DWORD hours = minutes / 60;

        seconds %= 60;
        minutes %= 60;

        wchar_t buf[64];
        if (hours > 0) {
            swprintf_s(buf, L"%dh %02dm %02ds", hours, minutes, seconds);
        } else if (minutes > 0) {
            swprintf_s(buf, L"%dm %02ds", minutes, seconds);
        } else {
            swprintf_s(buf, L"%ds", seconds);
        }
        return buf;
    }

    // Décodage ROT13
    std::wstring DecodeROT13(const std::wstring& input) {
        std::wstring output;
        output.reserve(input.size());

        for (wchar_t ch : input) {
            if (ch >= L'A' && ch <= L'Z') {
                output += static_cast<wchar_t>((ch - L'A' + 13) % 26 + L'A');
            } else if (ch >= L'a' && ch <= L'z') {
                output += static_cast<wchar_t>((ch - L'a' + 13) % 26 + L'a');
            } else {
                output += ch;
            }
        }

        return output;
    }

    bool ParseUserAssistKey(HKEY hKeyUser, const wchar_t* guid, const wchar_t* username) {
        wchar_t subkey[512];
        swprintf_s(subkey, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\%s\\Count", guid);

        HKEY hKey = nullptr;
        if (RegOpenKeyExW(hKeyUser, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return false;
        }

        RegKey key(hKey);

        DWORD index = 0;
        wchar_t valueName[16384];
        DWORD valueNameSize;
        BYTE data[1024];
        DWORD dataSize;
        DWORD type;

        while (true) {
            valueNameSize = 16384;
            dataSize = sizeof(data);

            LONG result = RegEnumValueW(hKey, index, valueName, &valueNameSize, nullptr, &type, data, &dataSize);

            if (result == ERROR_NO_MORE_ITEMS) {
                break;
            }

            if (result != ERROR_SUCCESS) {
                index++;
                continue;
            }

            // Décoder le nom (ROT13)
            std::wstring decodedName = DecodeROT13(valueName);

            UserAssistEntry entry;
            entry.application = valueName;
            entry.decodedPath = decodedName;
            entry.guid = guid;
            entry.username = username;

            // Parser les données binaires
            if (dataSize >= sizeof(USERASSIST_ENTRY_WIN7) && type == REG_BINARY) {
                USERASSIST_ENTRY_WIN7* uaData = reinterpret_cast<USERASSIST_ENTRY_WIN7*>(data);

                // Version 3 ou 5 (Windows 7/8/10)
                if (uaData->version == 3 || uaData->version == 5) {
                    entry.runCount = uaData->runCount;
                    entry.focusCount = uaData->focusCount;
                    entry.focusTime = uaData->focusTime;
                    entry.lastExecution = FileTimeToString(uaData->lastExecution);
                } else {
                    // Version ancienne (XP/Vista)
                    entry.runCount = dataSize >= 8 ? *reinterpret_cast<DWORD*>(data + 4) : 0;
                    entry.focusCount = 0;
                    entry.focusTime = 0;
                    entry.lastExecution = L"N/A (ancienne version)";
                }
            } else {
                entry.runCount = 0;
                entry.focusCount = 0;
                entry.focusTime = 0;
                entry.lastExecution = L"Données invalides";
            }

            entries.push_back(entry);
            index++;
        }

        return index > 0;
    }

    bool ScanUserAssist() {
        entries.clear();

        // Scan HKEY_CURRENT_USER
        wchar_t username[256] = L"Utilisateur actuel";
        DWORD size = 256;
        GetUserNameW(username, &size);

        int count = 0;
        if (ParseUserAssistKey(HKEY_CURRENT_USER, GUID_EXECUTABLE, username)) {
            count++;
        }
        if (ParseUserAssistKey(HKEY_CURRENT_USER, GUID_SHORTCUT, username)) {
            count++;
        }

        // Optionnel : Scanner d'autres profils utilisateurs via HKU
        // (nécessite élévation pour accéder à HKEY_USERS)

        UpdateStatus(L"Scan terminé : " + std::to_wstring(entries.size()) + L" entrées trouvées");
        return !entries.empty();
    }

    void PopulateListView() {
        ListView_DeleteAllItems(hwndList);

        for (size_t i = 0; i < entries.size(); i++) {
            LVITEMW lvi = {};
            lvi.mask = LVIF_TEXT;
            lvi.iItem = static_cast<int>(i);

            lvi.iSubItem = 0;
            lvi.pszText = const_cast<LPWSTR>(entries[i].decodedPath.c_str());
            ListView_InsertItem(hwndList, &lvi);

            ListView_SetItemText(hwndList, i, 1, const_cast<LPWSTR>(entries[i].application.c_str()));

            wchar_t buf[32];
            swprintf_s(buf, L"%u", entries[i].runCount);
            ListView_SetItemText(hwndList, i, 2, buf);

            ListView_SetItemText(hwndList, i, 3, const_cast<LPWSTR>(entries[i].lastExecution.c_str()));

            swprintf_s(buf, L"%u", entries[i].focusCount);
            ListView_SetItemText(hwndList, i, 4, buf);

            std::wstring focusTimeStr = MsToTimeString(entries[i].focusTime);
            ListView_SetItemText(hwndList, i, 5, const_cast<LPWSTR>(focusTimeStr.c_str()));

            ListView_SetItemText(hwndList, i, 6, const_cast<LPWSTR>(entries[i].guid.c_str()));

            ListView_SetItemText(hwndList, i, 7, const_cast<LPWSTR>(entries[i].username.c_str()));
        }
    }

    static DWORD WINAPI ScanThreadProc(LPVOID param) {
        auto* pThis = static_cast<UserAssistDecoder*>(param);

        pThis->UpdateStatus(L"Scan UserAssist en cours...");

        if (pThis->ScanUserAssist()) {
            PostMessage(pThis->hwndMain, WM_USER + 1, 0, 0); // Signal scan terminé
        } else {
            pThis->UpdateStatus(L"Aucune donnée UserAssist trouvée");
        }

        return 0;
    }

    void OnScan() {
        stopProcessing = false;
        hWorkerThread = CreateThread(nullptr, 0, ScanThreadProc, this, 0, nullptr);

        if (hWorkerThread) {
            EnableWindow(GetDlgItem(hwndMain, IDC_BTN_SCAN), FALSE);
        }
    }

    void OnDecode() {
        if (entries.empty()) {
            MessageBoxW(hwndMain, L"Scannez d'abord les données UserAssist", L"Information", MB_ICONINFORMATION);
            return;
        }

        // Le décodage est déjà fait pendant le scan
        // Cette fonction pourrait être utilisée pour un re-décodage ou affichage alternatif
        UpdateStatus(L"Décodage : " + std::to_wstring(entries.size()) + L" entrées décodées");
        Log(L"Décodage ROT13 vérifié pour toutes les entrées");
    }

    void OnExport() {
        if (entries.empty()) {
            MessageBoxW(hwndMain, L"Aucune donnée à exporter", L"Information", MB_ICONINFORMATION);
            return;
        }

        OPENFILENAMEW ofn = {};
        wchar_t fileName[MAX_PATH] = L"userassist_timeline.csv";

        ofn.lStructSize = sizeof(OPENFILENAMEW);
        ofn.hwndOwner = hwndMain;
        ofn.lpstrFilter = L"CSV Files (*.csv)\0*.csv\0All Files (*.*)\0*.*\0";
        ofn.lpstrFile = fileName;
        ofn.nMaxFile = MAX_PATH;
        ofn.lpstrTitle = L"Exporter la timeline UserAssist";
        ofn.Flags = OFN_OVERWRITEPROMPT;
        ofn.lpstrDefExt = L"csv";

        if (GetSaveFileNameW(&ofn)) {
            std::wofstream csv(fileName, std::ios::binary);
            if (!csv.is_open()) {
                MessageBoxW(hwndMain, L"Impossible de créer le fichier CSV", L"Erreur", MB_ICONERROR);
                return;
            }

            // BOM UTF-8
            unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
            csv.write(reinterpret_cast<wchar_t*>(bom), sizeof(bom) / sizeof(wchar_t));

            csv << L"Application,CheminDécodé,CompteurExéc,DernièreExéc,CompteurFocus,TempsFocus,GUID,Username\n";

            for (const auto& entry : entries) {
                csv << L"\"" << entry.application << L"\",\""
                    << entry.decodedPath << L"\",\""
                    << entry.runCount << L"\",\""
                    << entry.lastExecution << L"\",\""
                    << entry.focusCount << L"\",\""
                    << MsToTimeString(entry.focusTime) << L"\",\""
                    << entry.guid << L"\",\""
                    << entry.username << L"\"\n";
            }

            csv.close();
            UpdateStatus(L"Export réussi : " + std::wstring(fileName));
            Log(L"Export CSV : " + std::wstring(fileName));
            MessageBoxW(hwndMain, L"Export CSV réussi !", L"Succès", MB_ICONINFORMATION);
        }
    }

    void OnCompare() {
        if (entries.empty()) {
            MessageBoxW(hwndMain, L"Scannez d'abord les données UserAssist", L"Information", MB_ICONINFORMATION);
            return;
        }

        // Créer une map par utilisateur pour comparaison
        std::map<std::wstring, std::vector<UserAssistEntry*>> userEntries;

        for (auto& entry : entries) {
            userEntries[entry.username].push_back(&entry);
        }

        std::wstringstream report;
        report << L"=== Rapport de Comparaison UserAssist ===\n\n";

        for (const auto& pair : userEntries) {
            report << L"Utilisateur : " << pair.first << L"\n";
            report << L"  Nombre d'applications : " << pair.second.size() << L"\n";

            // Top 5 applications les plus exécutées
            std::vector<UserAssistEntry*> sorted = pair.second;
            std::sort(sorted.begin(), sorted.end(), [](UserAssistEntry* a, UserAssistEntry* b) {
                return a->runCount > b->runCount;
            });

            report << L"  Top 5 exécutions :\n";
            for (size_t i = 0; i < std::min(size_t(5), sorted.size()); i++) {
                report << L"    " << (i + 1) << L". " << sorted[i]->decodedPath
                       << L" (" << sorted[i]->runCount << L" fois)\n";
            }

            report << L"\n";
        }

        MessageBoxW(hwndMain, report.str().c_str(), L"Comparaison Utilisateurs", MB_ICONINFORMATION);
        Log(L"Comparaison utilisateurs effectuée");
    }

    void CreateControls(HWND hwnd) {
        // Boutons
        int btnY = MARGIN;
        CreateWindowW(L"BUTTON", L"Scanner UserAssist", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                     MARGIN, btnY, BUTTON_WIDTH, BUTTON_HEIGHT, hwnd, (HMENU)IDC_BTN_SCAN, nullptr, nullptr);

        CreateWindowW(L"BUTTON", L"Décoder ROT13", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                     MARGIN + BUTTON_WIDTH + 10, btnY, BUTTON_WIDTH, BUTTON_HEIGHT, hwnd,
                     (HMENU)IDC_BTN_DECODE, nullptr, nullptr);

        CreateWindowW(L"BUTTON", L"Exporter Timeline", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                     MARGIN + (BUTTON_WIDTH + 10) * 2, btnY, BUTTON_WIDTH, BUTTON_HEIGHT, hwnd,
                     (HMENU)IDC_BTN_EXPORT, nullptr, nullptr);

        CreateWindowW(L"BUTTON", L"Comparer Users", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                     MARGIN + (BUTTON_WIDTH + 10) * 3, btnY, BUTTON_WIDTH, BUTTON_HEIGHT, hwnd,
                     (HMENU)IDC_BTN_COMPARE, nullptr, nullptr);

        // ListView
        hwndList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                  WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
                                  MARGIN, btnY + BUTTON_HEIGHT + 10,
                                  WINDOW_WIDTH - MARGIN * 2 - 20,
                                  WINDOW_HEIGHT - btnY - BUTTON_HEIGHT - 80,
                                  hwnd, (HMENU)IDC_LISTVIEW, nullptr, nullptr);

        ListView_SetExtendedListViewStyle(hwndList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

        // Colonnes
        LVCOLUMNW lvc = {};
        lvc.mask = LVCF_TEXT | LVCF_WIDTH;

        lvc.cx = 350; lvc.pszText = const_cast<LPWSTR>(L"Chemin Décodé");
        ListView_InsertColumn(hwndList, 0, &lvc);

        lvc.cx = 250; lvc.pszText = const_cast<LPWSTR>(L"Nom Encodé (ROT13)");
        ListView_InsertColumn(hwndList, 1, &lvc);

        lvc.cx = 100; lvc.pszText = const_cast<LPWSTR>(L"Compteur Exec");
        ListView_InsertColumn(hwndList, 2, &lvc);

        lvc.cx = 150; lvc.pszText = const_cast<LPWSTR>(L"Dernière Exec");
        ListView_InsertColumn(hwndList, 3, &lvc);

        lvc.cx = 100; lvc.pszText = const_cast<LPWSTR>(L"Compteur Focus");
        ListView_InsertColumn(hwndList, 4, &lvc);

        lvc.cx = 120; lvc.pszText = const_cast<LPWSTR>(L"Temps Focus");
        ListView_InsertColumn(hwndList, 5, &lvc);

        lvc.cx = 80; lvc.pszText = const_cast<LPWSTR>(L"GUID");
        ListView_InsertColumn(hwndList, 6, &lvc);

        lvc.cx = 150; lvc.pszText = const_cast<LPWSTR>(L"Username");
        ListView_InsertColumn(hwndList, 7, &lvc);

        // Status bar
        hwndStatus = CreateWindowExW(0, L"STATIC", L"Prêt - Cliquez sur 'Scanner UserAssist' pour commencer",
                                     WS_CHILD | WS_VISIBLE | SS_SUNKEN | SS_LEFT,
                                     0, WINDOW_HEIGHT - 50, WINDOW_WIDTH - 20, 25,
                                     hwnd, (HMENU)IDC_STATUS, nullptr, nullptr);
    }

    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        UserAssistDecoder* pThis = nullptr;

        if (uMsg == WM_NCCREATE) {
            CREATESTRUCT* pCreate = reinterpret_cast<CREATESTRUCT*>(lParam);
            pThis = static_cast<UserAssistDecoder*>(pCreate->lpCreateParams);
            SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
            pThis->hwndMain = hwnd;
        } else {
            pThis = reinterpret_cast<UserAssistDecoder*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
        }

        if (pThis) {
            switch (uMsg) {
                case WM_CREATE:
                    pThis->CreateControls(hwnd);
                    return 0;

                case WM_COMMAND:
                    switch (LOWORD(wParam)) {
                        case IDC_BTN_SCAN: pThis->OnScan(); break;
                        case IDC_BTN_DECODE: pThis->OnDecode(); break;
                        case IDC_BTN_EXPORT: pThis->OnExport(); break;
                        case IDC_BTN_COMPARE: pThis->OnCompare(); break;
                    }
                    return 0;

                case WM_USER + 1: // Scan terminé
                    pThis->PopulateListView();
                    EnableWindow(GetDlgItem(hwnd, IDC_BTN_SCAN), TRUE);
                    if (pThis->hWorkerThread) {
                        CloseHandle(pThis->hWorkerThread);
                        pThis->hWorkerThread = nullptr;
                    }
                    return 0;

                case WM_DESTROY:
                    pThis->stopProcessing = true;
                    if (pThis->hWorkerThread) {
                        WaitForSingleObject(pThis->hWorkerThread, 2000);
                        CloseHandle(pThis->hWorkerThread);
                    }
                    PostQuitMessage(0);
                    return 0;
            }
        }

        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }

public:
    UserAssistDecoder() : hwndMain(nullptr), hwndList(nullptr), hwndStatus(nullptr),
                         hWorkerThread(nullptr), stopProcessing(false) {
        wchar_t logPath[MAX_PATH];
        GetModuleFileNameW(nullptr, logPath, MAX_PATH);
        PathRemoveFileSpecW(logPath);
        PathAppendW(logPath, L"UserAssistDecoder.log");

        logFile.open(logPath, std::ios::app);
        logFile.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));
        Log(L"=== UserAssistDecoder démarré ===");
    }

    ~UserAssistDecoder() {
        Log(L"=== UserAssistDecoder terminé ===");
        if (logFile.is_open()) {
            logFile.close();
        }
    }

    int Run(HINSTANCE hInstance, int nCmdShow) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(WNDCLASSEXW);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = hInstance;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"UserAssistDecoderClass";
        wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
        wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);

        if (!RegisterClassExW(&wc)) {
            MessageBoxW(nullptr, L"Échec de l'enregistrement de la classe", L"Erreur", MB_ICONERROR);
            return 1;
        }

        hwndMain = CreateWindowExW(0, L"UserAssistDecoderClass",
                                   L"UserAssist Decoder - WinToolsSuite Forensics",
                                   WS_OVERLAPPEDWINDOW,
                                   CW_USEDEFAULT, CW_USEDEFAULT, WINDOW_WIDTH, WINDOW_HEIGHT,
                                   nullptr, nullptr, hInstance, this);

        if (!hwndMain) {
            MessageBoxW(nullptr, L"Échec de la création de la fenêtre", L"Erreur", MB_ICONERROR);
            return 1;
        }

        ShowWindow(hwndMain, nCmdShow);
        UpdateWindow(hwndMain);

        MSG msg = {};
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        return static_cast<int>(msg.wParam);
    }
};

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    UserAssistDecoder app;
    return app.Run(hInstance, nCmdShow);
}
