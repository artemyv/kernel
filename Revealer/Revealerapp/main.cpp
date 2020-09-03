#include <iostream>
#include <string>
#include <vector>

#include <Windows.h>
#include <psapi.h>
// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1

#include "../Revealerdriver/Common.h"

static void ShowProcessInfo(HANDLE hProcess);

int main(int argc, const char* argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: " << argv[0] << " <pid>\n";
        return 0;
    }

    auto device = CreateFileW(LR"(\\.\revealer)", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (!device)
    {
        std::cerr << "Failed to oped driver " << GetLastError() << '\n';
        return 1;
    }

    ProcessDataIn in{ std::stoul(argv[1]) };
    //todo - try to print dll list using OpenProcess
    auto hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, in.pId);
    if (NULL == hProcess)
    {
        std::cerr << "Failed to oped process in user space " << GetLastError() << '\n';
    }
    else
    {
        std::cout << "User space:\n";
        ShowProcessInfo(hProcess);
        CloseHandle(hProcess);
    }

    ProcessDataOut out{};

    DWORD bytesReturned;
    if (!DeviceIoControl(device,
        (DWORD)REVEALER_SIOCTL_OPEN_PROCESS,
        &in,
        (DWORD)sizeof(in),
        &out,
        sizeof(out),
        &bytesReturned,
        nullptr))
    {
        std::cerr << "Failed to call DeviceIoControl " << GetLastError() << '\n';
    }
    else
    {
        hProcess = out.hProcess;
        std::cout << "Kernel space:\n";
        ShowProcessInfo(hProcess);
        CloseHandle(hProcess);
    }
    CloseHandle(device);//todo use RAII
    return 0;
}

void ShowProcessInfo(HANDLE hProcess)
{
    // Get a list of all the modules in this process.
    std::vector<HMODULE> hMods(1024);
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods.data(), (DWORD)hMods.size(), &cbNeeded))
    {
        if (cbNeeded / sizeof(HMODULE) > hMods.size())
        {
            hMods.resize(cbNeeded / sizeof(HMODULE));
            EnumProcessModules(hProcess, hMods.data(), (DWORD)hMods.size(), &cbNeeded);
        }
        if (cbNeeded / sizeof(HMODULE) < hMods.size())
        {
            hMods.resize(cbNeeded / sizeof(HMODULE));
        }

        for (auto& h : hMods)
        {
            wchar_t szModName[MAX_PATH];

            // Get the full path to the module's file.

            if (GetModuleFileNameExW(hProcess, h, szModName,
                sizeof(szModName) / sizeof(wchar_t)))
            {
                // Print the module name and handle value.

                std::wcout << L"\t0x" << std::hex << h << L"\t" << szModName <<  L"\n";
            }
        }
    }
}
