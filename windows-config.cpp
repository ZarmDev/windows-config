// USAGE OF AI because win32 is hard to learn :( (for some things not everything)

#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <filesystem>
#include <setupapi.h>
#include <initguid.h>
#include <devguid.h>
#include <iostream>

// For disabling system restore
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

#pragma comment(lib, "setupapi.lib")

using namespace std;
using namespace std::filesystem;

void RunPowerShellCommand(const std::wstring& command) {
    // Create process will expect a wstring
    std::wstring fullCmd = L"powershell.exe -Command \"" + command + L"\"";
    // Required by winAPI to start a process, will either be 32 or 64
    STARTUPINFOW si = { sizeof(si) };
    // Receives information about the process (handle/ID)
    PROCESS_INFORMATION pi;
    // Provide a pointer to the string and a pointer to startup info/process info. Leave the rest blank.
    CreateProcessW(NULL, &fullCmd[0], NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    // Wait for process to execute
    WaitForSingleObject(pi.hProcess, INFINITE);
    // Close handles because we are using C++
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

void SetVisualEffect(BOOL enable) {
    ANIMATIONINFO animInfo;
    // Either 32 bit (68 bytes) or 64 bit (104 bytes)
    animInfo.cbSize = sizeof(ANIMATIONINFO);
    // Depending on enable, set window animation effects (minimizing, maximizing)
    animInfo.iMinAnimate = enable ? TRUE : FALSE;

    /*
    SystemParametersInfo(
        SPI_SETANIMATION,                // Action: set animation settings
        sizeof(ANIMATIONINFO),           // Size of the ANIMATIONINFO structure
        &animInfo,                       // Pointer to your ANIMATIONINFO struct
        SPIF_UPDATEINIFILE | SPIF_SENDCHANGE // Update .ini file and broadcast change
    );
    */
    if (!SystemParametersInfo(SPI_SETANIMATION, sizeof(ANIMATIONINFO), &animInfo, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE)) {
        std::cerr << "Failed to set animation: " << GetLastError() << std::endl;
    }

    // Disable menu fade
    BOOL fade = enable ? TRUE : FALSE;
    SystemParametersInfo(SPI_SETMENUFADE, 0, &fade, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
    SystemParametersInfo(SPI_SETCOMBOBOXANIMATION, 0, &fade, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
    SystemParametersInfo(SPI_SETFONTSMOOTHING, 0, &fade, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
    // Disable UI effects like transitions, etc
    BOOL enableEffects = FALSE;
    if (!SystemParametersInfo(SPI_SETUIEFFECTS, 0, &enableEffects, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE)) {
        std::cerr << "Failed to set UI effects: " << GetLastError() << std::endl;
    }
}

// Disable process in task manager
bool DisableTask(const std::wstring& taskPath) {
    // Use schtasks (task scheduler) to disable it
    std::wstring command = L"schtasks.exe /Change /TN \"" + taskPath + L"\" /Disable";
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    BOOL success = CreateProcessW(
        NULL,
        const_cast<LPWSTR>(command.c_str()), // Cast the c string into a LPWSTR (same thing as doing L"yourstring")
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!success) {
        std::wcerr << L"Failed to disable task: " << taskPath << L" (Error: " << GetLastError() << L")\n";
        return false;
    }

    // Wait for the command to finish
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

bool DisableSystemRestore() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) return false;

    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE, nullptr);
    if (FAILED(hr)) return false;

    IWbemLocator* pLocator = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (void**)&pLocator);
    if (FAILED(hr)) return false;

    IWbemServices* pServices = nullptr;
    hr = pLocator->ConnectServer(
        BSTR(L"ROOT\\DEFAULT"), nullptr, nullptr, nullptr, 0, nullptr, nullptr, &pServices);
    if (FAILED(hr)) return false;

    hr = CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr)) return false;

    // Disable System Restore on C: drive
    IWbemClassObject* pClass = nullptr;
    hr = pServices->GetObject(BSTR(L"SystemRestore"), 0, nullptr, &pClass, nullptr);
    if (FAILED(hr)) return false;

    IWbemClassObject* pInParams = nullptr;
    hr = pClass->GetMethod(L"Disable", 0, &pInParams, nullptr);
    if (FAILED(hr)) return false;

    IWbemClassObject* pInstance = nullptr;
    hr = pInParams->SpawnInstance(0, &pInstance);
    if (FAILED(hr)) return false;

    VARIANT var;
    VariantInit(&var);
    var.vt = VT_BSTR;
    var.bstrVal = SysAllocString(L"C:\\");
    hr = pInstance->Put(L"Drive", 0, &var, 0);
    if (FAILED(hr)) return false;

    IWbemClassObject* pOutParams = nullptr;
    hr = pServices->ExecMethod(BSTR(L"SystemRestore"), BSTR(L"Disable"),
        0, nullptr, pInstance, &pOutParams, nullptr);

    VariantClear(&var);
    if (pLocator) pLocator->Release();
    if (pServices) pServices->Release();
    if (pClass) pClass->Release();
    if (pInParams) pInParams->Release();
    if (pInstance) pInstance->Release();
    if (pOutParams) pOutParams->Release();
    CoUninitialize();

    return SUCCEEDED(hr);
}


// Expects const std::wstring&, a wide string (wchart_t*)
void DisableServiceOnStartup(SC_HANDLE scm, const std::wstring& name) {  
   // Now, actually open the handle service
   SC_HANDLE service = OpenServiceW(scm, name.c_str(), SERVICE_CHANGE_CONFIG);  
   if (!service) {  
       //std::cerr << "Failed to open service: " << GetLastError() << std::endl;  
       CloseServiceHandle(scm);
       return;
   }

   if (service) {  
       // Set startup to disabled, function returns if it was successful  
       if (!ChangeServiceConfigW(service,  
           SERVICE_NO_CHANGE,  
           SERVICE_DISABLED,  
           SERVICE_NO_CHANGE,  
           NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {  
           std::cerr << "Failed to disable service: " << GetLastError() << std::endl;  
       }  
       else {  
           std::cout << "Service disabled successfully." << std::endl;  
       }  
   }  

   CloseServiceHandle(service);  
}

void DisableTelemetryRegistry() {
    HKEY hKey;
    DWORD value = 0;
    BYTE* registryEnable = reinterpret_cast<BYTE*>(&value);

    // First, check if registry key can be accessed
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        // If no error, set the registry key to a value of 0 which disables telementary
        RegSetValueExW(hKey, L"AllowTelemetry", 0, REG_DWORD, registryEnable, sizeof(value));
        RegCloseKey(hKey);
    }
}

void DisableDefenderRegistry() {
    HKEY hKey, hSubKey;
    DWORD disable = 1;

    // Main Defender key
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&disable, sizeof(disable));

        // Real-Time Protection subkey
        if (RegCreateKeyExW(hKey, L"Real-Time Protection", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hSubKey, NULL) == ERROR_SUCCESS) {
            RegSetValueExW(hSubKey, L"DisableRealtimeMonitoring", 0, REG_DWORD, (BYTE*)&disable, sizeof(disable));
            RegSetValueExW(hSubKey, L"DisableBehaviorMonitoring", 0, REG_DWORD, (BYTE*)&disable, sizeof(disable));
            RegSetValueExW(hSubKey, L"DisableScanOnRealtimeEnable", 0, REG_DWORD, (BYTE*)&disable, sizeof(disable));
            RegSetValueExW(hSubKey, L"DisableOnAccessProtection", 0, REG_DWORD, (BYTE*)&disable, sizeof(disable));
            RegSetValueExW(hSubKey, L"DisableIOAVProtection", 0, REG_DWORD, (BYTE*)&disable, sizeof(disable));
            RegCloseKey(hSubKey);
        }
        RegCloseKey(hKey);
    }
}

bool DisableHibernation() {
    std::wstring command = L"powercfg.exe -h off";
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    BOOL success = CreateProcessW(
        NULL,
        const_cast<LPWSTR>(command.c_str()), // must be writable
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!success) {
        std::wcerr << L"Failed to disable hibernation. Error: " << GetLastError() << std::endl;
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

void DisableTransparency() {
    HKEY hKey;
    DWORD value = 0;

    // Registry path for personalization settings
    const wchar_t* subkey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize";

    if (RegOpenKeyExW(HKEY_CURRENT_USER, subkey, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        if (RegSetValueExW(hKey, L"EnableTransparency", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value)) == ERROR_SUCCESS) {
            std::wcout << L"Transparency disabled successfully.\n";
        }
        else {
            std::wcerr << L"Failed to set registry value.\n";
        }
        RegCloseKey(hKey);
    }
    else {
        std::wcerr << L"Failed to open registry key.\n";
    }
}

void CleanStartupFolder() {
    wchar_t* path = nullptr;
    size_t len = 0;

    // Use _wdupenv_s to safely retrieve the environment variable
    if (_wdupenv_s(&path, &len, L"APPDATA") != 0 || path == nullptr) {
        std::wcerr << L"Failed to retrieve APPDATA environment variable." << std::endl;
        return;
    }

    std::wstring startupPath = path;
    startupPath += L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";

    free(path); // Free the allocated memory for the environment variable

    for (auto& entry : filesystem::directory_iterator(startupPath)) {
        wcout << L"Deleting shortcut: " << entry.path().wstring() << std::endl;
        filesystem::remove(entry.path());
    }
}

void DisableARSO() {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {

        DWORD value = 1;
        RegSetValueExW(hKey, L"DisableAutomaticRestartSignOn", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&value), sizeof(value));
        RegCloseKey(hKey);
    }
}

void DisableBackgroundApps() {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {

        DWORD value = 1;
        RegSetValueExW(hKey, L"GlobalUserDisabled", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&value), sizeof(value));
        RegCloseKey(hKey);
    }

    if (RegCreateKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Search",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {

        DWORD value = 0;
        RegSetValueExW(hKey, L"BackgroundAppGlobalToggle", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&value), sizeof(value));
        RegCloseKey(hKey);
    }
}

void DisableGameMode() {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\GameBar",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {

        DWORD value = 0;
        RegSetValueExW(hKey, L"AutoGameModeEnabled", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&value), sizeof(value));
        RegCloseKey(hKey);
    }
}

vector<wstring> ListPhysicalDrives() {
    vector<wstring> physicalDisks;

    HDEVINFO deviceInfoSet = SetupDiGetClassDevs(
        &GUID_DEVINTERFACE_DISK,
        nullptr,
        nullptr,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
    );

    if (deviceInfoSet == INVALID_HANDLE_VALUE) return physicalDisks;

    SP_DEVICE_INTERFACE_DATA deviceInterfaceData = {};
    deviceInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    for (DWORD i = 0; SetupDiEnumDeviceInterfaces(deviceInfoSet, nullptr, &GUID_DEVINTERFACE_DISK, i, &deviceInterfaceData); ++i) {
        DWORD requiredSize = 0;
        SetupDiGetDeviceInterfaceDetail(deviceInfoSet, &deviceInterfaceData, nullptr, 0, &requiredSize, nullptr);

        auto detailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(requiredSize);
        detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

        if (SetupDiGetDeviceInterfaceDetail(deviceInfoSet, &deviceInterfaceData, detailData, requiredSize, nullptr, nullptr)) {
            wstring devicePathStr = detailData->DevicePath;
            // Ensure that it's NOT a virtual disk
            if (devicePathStr.find(L"virtual_disk") == string::npos) {
                physicalDisks.push_back(devicePathStr);
            }
        }

        free(detailData);
    }

    SetupDiDestroyDeviceInfoList(deviceInfoSet);
    
    return physicalDisks;
}

bool IsDriveSSD(const wchar_t* physicalDrivePath) {
    HANDLE hDevice = CreateFileW(
        physicalDrivePath,
        0, // no read/write needed
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if (hDevice == INVALID_HANDLE_VALUE) return false;

    STORAGE_PROPERTY_QUERY query = {};
    query.PropertyId = StorageDeviceSeekPenaltyProperty;
    query.QueryType = PropertyStandardQuery;

    DEVICE_SEEK_PENALTY_DESCRIPTOR result = {};
    DWORD bytesReturned = 0;

    bool isSSD = false;
    if (DeviceIoControl(
        hDevice,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &query,
        sizeof(query),
        &result,
        sizeof(result),
        &bytesReturned,
        nullptr
    )) {
        isSSD = !result.IncursSeekPenalty;
    }

    CloseHandle(hDevice);
    return isSSD;
}

bool IsRamLessThan8GB() {
    MEMORYSTATUSEX memStatus = {};
    memStatus.dwLength = sizeof(memStatus);

    if (GlobalMemoryStatusEx(&memStatus)) {
        DWORDLONG totalRamBytes = memStatus.ullTotalPhys;
        constexpr DWORDLONG eightGB = 8ULL * 1024 * 1024 * 1024;
        return totalRamBytes <= eightGB;
    }

    return false; // fallback if query fails
}

bool DisableSuperfetch(SC_HANDLE hSCManager) {
    if (!hSCManager) return false;

    SC_HANDLE hService = OpenService(hSCManager, L"SysMain", SERVICE_STOP | SERVICE_CHANGE_CONFIG);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return false;
    }

    // Stop the service
    SERVICE_STATUS status = {};
    ControlService(hService, SERVICE_CONTROL_STOP, &status);

    // Disable startup
    bool success = ChangeServiceConfig(
        hService,
        SERVICE_NO_CHANGE,
        SERVICE_DISABLED,
        SERVICE_NO_CHANGE,
        nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr,
        nullptr
    );

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return success;
}

int main() {
    cout << "Windows Optimizer Script\n\n---------------------------------------\nEnsure that you are running this as an administrator.\n";
    cout << "Are you sure you want to run this? (Press 1 to start, anything else will quit the program)\n";
    int wait;
    cin >> wait;
    if (wait != 1) {
        cout << "Exited!\n";
        return 1;
    }

    cout << "Disabling animations\n";
    SetVisualEffect(false);
    cout << "Disabling unneccessary services on startup...\n";

    wifstream file(L"services.txt");
    if (!file) {
        std::cerr << "Error: File could not be opened!" << std::endl;
        return 1;
    }

    vector<wstring> services;

    wstring line;
    while (getline(file, line)) {
        wstringstream wss(line);
        wstring service;
        wss >> service;
        //wcout << service << '\n';
        services.push_back(service);
    }

    file.close(); // Close the file

    // Open connection to services (for some reason it's like with databases, you first open connection)
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        std::cerr << "Failed to open SCM: " << GetLastError() << std::endl;
        if (GetLastError() == 5) {
            std::cout << "You must run this file with administrative privileges for it to work.\n\n\n";
        }
        return 1;
    }

    for (int i = 0; i < services.size(); i++) {
        DisableServiceOnStartup(scm, services[i]);
    }

    // Disable telementary
    cout << "Disabling telemetry\n";
    DisableTelemetryRegistry();
    DisableTask(L"Microsoft\\Windows\\Application Experience\\ProgramDataUpdater");
    DisableTask(L"Microsoft\\Windows\\Autochk\\Proxy");
    DisableTask(L"Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator");
    DisableTask(L"Microsoft\\Windows\\Customer Experience Improvement Program\\KernelCeipTask");
    DisableTask(L"Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip");
    // Location
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors' -Name 'DisableLocation' -Value 1 -Type DWord");
    // App tracking
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' -Name 'Start_TrackProgs' -Value 0 -Type DWord");
    // Ink/type
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Input\\TIPC' -Name 'Enabled' -Value 0 -Type DWord");
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Personalization\\Settings' -Name 'AcceptedPrivacyPolicy' -Value 0 -Type DWord");
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\InputPersonalization\\TrainedDataStore' -Name 'HarvestContacts' -Value 0 -Type DWord");
    // Lock screen camera
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization' -Name 'NoLockScreenCamera' -Value 1 -Type DWord");
    // Camera indicator
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Privacy' -Name 'TailoredExperiencesWithDiagnosticDataEnabled' -Value 0 -Type DWord");
    // Speech
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Speech_OneCore\\Settings\\OnlineSpeechPrivacy' -Name 'HasAccepted' -Value 0 -Type DWord");
    // Errors
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting' -Name 'Disabled' -Value 1 -Type DWord");

    // Disable windows defender
    cout << "Disabling windows defender\n";
    DisableDefenderRegistry();
    SC_HANDLE service = OpenService(scm, L"WinDefend", SERVICE_CHANGE_CONFIG);
    ChangeServiceConfig(service, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    CloseServiceHandle(service);

    // Disable hibernation
    cout << "Disabling hibernation\n";
    if (!DisableHibernation()) {
        std::cerr << "Operation failed. Make sure to run as Administrator." << std::endl;
        return 1;
    }

    // Disable transparency
    cout << "Disabling transparency\n";
    DisableTransparency();

    // Remove bloatware
    cout << "Removing bloatware\n";
    // Remove Microsoft Store apps
    RunPowerShellCommand(L"Get-AppxPackage *solitairecollection* | Remove-AppxPackage");
    RunPowerShellCommand(L"Get-AppxPackage *candycrush* | Remove-AppxPackage");
    RunPowerShellCommand(L"Get-AppxPackage *tiktok* | Remove-AppxPackage");
    RunPowerShellCommand(L"Get-AppxPackage *roblox* | Remove-AppxPackage");
    RunPowerShellCommand(L"Get-AppxPackage *spotify* | Remove-AppxPackage");

    // Remove Dell-specific software (if installed via MSI)
    RunPowerShellCommand(L"Get-WmiObject Win32_Product | Where-Object { $_.Name -like '*Dell*' } | ForEach-Object { $_.Uninstall() }");

    // Optional: Kill background Dell processes
    RunPowerShellCommand(L"Stop-Process -Name SupportAssistAgent -Force");
    RunPowerShellCommand(L"Stop-Process -Name DellUpdate -Force");

    // Disable Startup Folder Apps
    cout << "Disabling startup apps\n";
    CleanStartupFolder();

    // Disable App Relaunch
    cout << "Disabling app relaunch\n";
    DisableARSO();

    // Disable background apps
    cout << "Disabling background apps\n";
    DisableBackgroundApps();

    // Disable app updates
    cout << "Disabling app updates\n";
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsStore' -Name 'AutoDownload' -Value 2 -Type DWord");

    // Disable web search results
    cout << "Disabling start menu web search results\n";
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKCU:\\Software\\Policies\\Microsoft\\Windows\\Explorer' -Name 'DisableSearchBoxSuggestions' -Value 1 -Type DWord");
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Search' -Name 'BingSearchEnabled' -Value 0 -Type DWord");

    // Disable autoinstall
    cout << "Disabling auto updates of microsoft apps\n";
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager' -Name 'SilentInstalledAppsEnabled' -Value 0 -Type DWord");
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager' -Name 'SubscribedContent-338388Enabled' -Value 0 -Type DWord");

    // Disable account notfications
    cout << "Disabling account notifications\n";
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' -Name 'Start_AccountNotifications' -Value 0 -Type DWord");

    // Disable preview pane
    cout << "Disabling preview pane\n";
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' -Name 'ShowPreviewHandlers' -Value 0");

    // Show file extensions
    cout << "Showing file extensions\n";
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' -Name 'HideFileExt' -Value 0");

    // Show hidden files
    cout << "Showing hidden files\n";
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' -Name 'Hidden' -Value 1");
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' -Name 'ShowSuperHidden' -Value 1");

    // Disable gallery
    cout << "Disabling gallery\n";
    RunPowerShellCommand(L"Remove-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}' -Force");

    // Remove onedrive
    cout << "Removing onedrive\n";
    RunPowerShellCommand(L"Stop-Process -Name OneDrive -Force");
    RunPowerShellCommand(L"Set-Service -Name OneDrive -StartupType Disabled");
    RunPowerShellCommand(L"Remove-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Force");
    
    // Add end task
    cout << "Adding ability to end task from taskbar\n";
    RunPowerShellCommand(L"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\TaskbarDeveloperSettings' -Name 'TaskbarEndTask' -Value 1 -Type DWord");

    // Disable superfetch
    int points = 0;
    // Check if disk is SSD (Then, superfetch is unneccessary)
    vector<wstring> physicalDisks = ListPhysicalDrives();
    for (wstring drivePath : physicalDisks) {
        string type = (IsDriveSSD(drivePath.c_str()) ? "SSD" : "HDD");
        cout << "You have a " << type << " drive\n";
        if (type == "SSD") {
            points++;
        }
    }
    // Check if RAM is lower than 8gb (Then, superfetch is unneccessary)
    if (IsRamLessThan8GB()) {
        points++;
        cout << "Your ram is less than 8gb" << '\n';
    }
    else {
        cout << "You ram is not less than 8gb" << '\n';
    }
    // Gamers should probably disable superfetch (?)
    cout << "Are you a gamer (1 if you are, 0 if you are not)";
    cin >> wait;
    if (wait == 1) {
        points++;
    }
    cout << (points >= 2 ? "You should probably disable superfetch. Proceed? (1 to proceed)" : "You can choose whether to keep superfetch (1 to remove it, otherwise it won't be disabled)");
    cin >> wait;
    if (wait == 1) {
        if (DisableSuperfetch(scm)) {
            std::cout << "Superfetch (SysMain) disabled successfully." << std::endl;
        }
        else {
            std::cout << "Failed to disable Superfetch." << std::endl;
        }
    }

    // Disable system restore
    DisableSystemRestore();
    cout << "It's recommended that you delete the old system restore points manually. It's not put in this code because it seems like there isn't a good way to do it without any risks.\n";

    // Disable visual studio telementary
    // Disable homegroup
    // Disable chrome telementary
    // Disable error reporting
    // Disable news and interests
    // Disable last accessed file timestamps (NTFS timestamps)
    const char* command = "fsutil behavior set disablelastaccess 1";

    int result = system(command);

    if (result == 0) {
        std::cout << "Successfully disabled NTFS last access timestamps.\n";
    }
    else {
        std::cerr << "Failed to disable timestamps. Error code: " << result << "\n";
    }
    // Disable SMB1, SMB2 protocols


    // End
    cout << "Success! No errors occured. Please restart your PC\n";
    cin >> wait;
    CloseServiceHandle(scm);
    return 0;
}
