// vartdriverdriver.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <Windows.h>
#include "../vartdriver/Common.h"
int main(int argc, const char* argv[])
{
    if (argc < 3)
    {
        std::cout << "Usage: " << argv[0] << " <tid> <priority>\n";
        return 0;
    }

    auto device = CreateFileW(LR"(\\.\vartdriver)", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (!device)
    {
        std::cerr << "Failed to oped driver " << GetLastError() << '\n';
        return 1;
    }

    ThreadData d{ std::stoul(argv[1]), std::stoi(argv[2]) };
    DWORD bytesReturned;
    if (!DeviceIoControl(device,
        (DWORD)VARTDRIVER_SIOCTL_SET_PRIORITY,
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
    }
    CloseHandle(device);//todo use RAII
    return 0;
}

