// Injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <iomanip>
#include <string>
#include <map>
#include <unordered_set>
#include <algorithm>
#include <Windows.h>
#include <TlHelp32.h>
#include <AclAPI.h>

using std::cout;
using std::cerr;
using std::endl;

const std::wstring hideDllName{ L"./Hide.scare" };
const std::wstring unhideDllName{ L"./Unhide.scare" };

const std::wstring exeName{ L"./Scare.exe" };
const std::wstring title{ L"SCARE\n" };

void showHelp(const wchar_t* argZero) {
    std::wcout << "Scare - Scare windows so only YOU can see them.\n"
        "\n"
        "Usage: " << argZero << " [--hide | --unhide] PID_OR_PROCESS_NAME ...\n"
        "\n"
        "  -h, --hide      Hide the specified applications. This is default.\n"
        "  -u, --unhide    Unhide the applications specified.\n"
        "      --help      Show this help menu.\n"
        "\n"
        "  PID_OR_PROCESS_NAME The process id or the process name to hide.\n"
        "\n"
        "Examples:\n"
        << argZero << " 89203\n"
        << argZero << " firefox.exe\n"
        << argZero << " --unhide discord.exe obs64.exe\n";
}

std::unordered_set<int> getPIDsFromProcName(std::wstring& searchTerm) {
    std::unordered_set<int> pids;
    std::transform(searchTerm.begin(), searchTerm.end(), searchTerm.begin(), ::towlower);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot) {
        PROCESSENTRY32 pe32{};
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                std::wstring exeFile{ pe32.szExeFile };
                std::transform(exeFile.begin(), exeFile.end(), exeFile.begin(), ::towlower);
                if (searchTerm == exeFile)
                    pids.insert(pe32.th32ProcessID);
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return pids;
}

std::map<std::wstring, std::unordered_set<int>> getProcList() {
    std::map<std::wstring, std::unordered_set<int>> pList;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot) {
        PROCESSENTRY32 pe32{};
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                pList[pe32.szExeFile].insert(pe32.th32ProcessID);
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return pList;
}

bool isValidPID(const std::wstring& arg) {
    if (arg.empty()) return false;
    return std::all_of(arg.begin(), arg.end(), isdigit);
}

bool FileExists(const std::wstring& filePath)
{
    DWORD dwAttrib = GetFileAttributes(filePath.c_str());
    return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
        !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

std::wstring getFullFilePath(const std::wstring& filename) {
    wchar_t fullPath[MAX_PATH];
    GetFullPathName(filename.c_str(), MAX_PATH, fullPath, NULL);
    std::wstring strFullPath{ fullPath };
    if (!FileExists(strFullPath)) {
        return std::wstring{};
    }
    return strFullPath;
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
    std::wstring hideDllPath{ getFullFilePath(hideDllName) }, unhideDllPath{ getFullFilePath(unhideDllName) };

    auto inject = [&](DWORD pid, std::wstring& dllFullPath) -> void {
        if (!dllFullPath.empty()) {
            size_t dllPathLen = (dllFullPath.length() + 1) * sizeof(wchar_t);
            if (HANDLE procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pid); procHandle) {
                cerr << "Scared the pid " << pid << endl;

                if (HMODULE libHandle; GetModuleHandleEx(0, L"kernel32.dll", &libHandle)) {
                    if (LPVOID libAddr = GetProcAddress(libHandle, "LoadLibraryW"); libAddr) {
                        if (LPVOID mem = VirtualAllocEx(procHandle, NULL, dllPathLen, MEM_COMMIT, PAGE_READWRITE); mem) {
                            if (WriteProcessMemory(procHandle, mem, dllFullPath.c_str(), dllPathLen, NULL)) {
                                if (HANDLE remoteThread = CreateRemoteThreadEx(procHandle, NULL, 0, static_cast<LPTHREAD_START_ROUTINE>(libAddr), mem, 0, NULL, NULL); remoteThread) {
                                    if (CloseHandle(remoteThread) and CloseHandle(procHandle))
                                        cerr << "" << endl;
                                    else cerr << "Injected Dll, but failed to close handles" << endl;
                                }
                                else cerr << "Failed to create remote thread" << endl;
                            }
                            else cerr << "Failed to write to allocated memory" << endl;
                        }
                        else cerr << "Failed to allocate memory" << endl;
                    }
                    else cerr << "Failed to get address of LoadLibraryW" << endl;
                }
                else cerr << "Failed to acquire handle on kernel32.dll" << endl;
            }
            else cerr << "Failed to acquire handle on process " << pid << endl;
        }
    };

    if (argc > 1) {
        bool hide = true;
        for (int i = 1; i < argc; i++) {
            std::wstring arg{ argv[i] };
            std::transform(arg.begin(), arg.end(), arg.begin(), ::towlower);
            if ((arg == L"-h" && argc == 2) || arg == L"--help" || arg == L"/?") {
                showHelp(argv[0]);
                return 0;
            }
            else if (arg == L"-h" || arg == L"--hide") {
                hide = true;
            }
            else if (arg == L"-u" || arg == L"--unhide") {
                hide = false;
            }
            else if (isValidPID(arg)) {
                inject(std::stoi(arg), hide ? hideDllPath : unhideDllPath);
            }
            else {
                auto pids = getPIDsFromProcName(arg);
                if (pids.empty()) pids = getPIDsFromProcName(arg.append(L".exe"));
                if (pids.empty())
                    std::wcerr << L"No process found with the name " << argv[i] << endl;
                for (auto& pid : pids)
                    inject(pid, hide ? hideDllPath : unhideDllPath);
            }
        }
        return 0;
    }

    std::wcout << title << endl;
    std::wcout << "Hey I'm Scare, with me you will scare windows so only YOU can see them" << endl;
    std::wcout << "Type `help` to get started." << endl;

    int enterPressed{};
    while (true) {
        std::wstring input;
        cout << "> ";
        std::getline(std::wcin, input);
        if (input.empty()) {
            if (enterPressed++) {
                cout << "Cya";
                return 0;
            }
            cout << "Press Enter again to exit" << endl;
        }
        else {
            enterPressed = 0;
            auto delimPos = input.find(L" ");
            std::wstring command = input.substr(0, delimPos);
            if (command == L"help" || command == L"`help`") {
                std::cout << "Available commands: \n"
                    "\n"
                    "  hide PROCESS_ID_OR_NAME       Hides the specified application\n"
                    "  unhide PROCESS_ID_OR_NAME     Unhides the specified application\n"
                    "  list                          Lists all applications\n"
                    "  help                          Shows this help menu\n"
                    "  exit                          Exit\n"
                    "\n"
                    "Examples:\n"
                    "hide notepad.exe\n"
                    "list\n"
                    "unhide discord.exe\n";
            }
            else if (command == L"list") {
                std::wcout << std::setw(35) << std::left << "Process name" << "PID" << endl;
                for (auto& [pName, pIDs] : getProcList()) {
                    std::wcout << std::setw(35) << std::left << pName;
                    for (auto& pID : pIDs) std::cout << pID << " ";
                    cout << endl;
                }
            }
            else if (command == L"hide" || command == L"unhide") {
                if (delimPos == std::wstring::npos) {
                    std::wcout << "Usage: " << command << " PROCESS_ID_OR_NAME\n";
                    continue;
                }
                std::wstring arg = input.substr(delimPos + 1);
                if (isValidPID(arg)) {
                    inject(std::stoi(arg), command == L"hide" ? hideDllPath : unhideDllPath);
                }
                else {
                    auto pids = getPIDsFromProcName(arg);
                    if (pids.empty()) pids = getPIDsFromProcName(arg.append(L".exe"));
                    if (pids.empty())
                        std::wcerr << L"No process found with the name " << input.substr(delimPos + 1) << endl;
                    for (auto& pid : pids)
                        inject(pid, command == L"hide" ? hideDllPath : unhideDllPath);
                }
            }
            else if (command == L"exit" || command == L"quit") {
                cout << "Cya\n";
                return 0;
            }
            else {
                cout << "Invalid command. Type `help` for help." << endl;
            }
        }
    }

    return 0;
}
