#include <iostream>
#include <string>
#include <Windows.h>
#include "../Revealerdriver/Common.h"
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

    ProcessData d{ std::stoul(argv[1]) };
    //todo - try to print dll list using OpenProcess

    DWORD bytesReturned;
    if (!DeviceIoControl(device,
        (DWORD)REVEALER_SIOCTL_OPEN_PROCESS,
        &d,
        (DWORD)sizeof(d),
        nullptr,
        0,
        &bytesReturned,
        nullptr))
    {
        std::cerr << "Failed to call DeviceIoControl " << GetLastError() << '\n';
    }
    else
    {
        std::cout << "Success!\n";
        //todo - try to print dll list using handle received from driver
    }
    CloseHandle(device);//todo use RAII
    return 0;
}

