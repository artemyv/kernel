#include <iostream>
#include <string>
#include <vector>

#include <Windows.h>

#include "../nulldevdriver/Common.h"

int main()
{
    auto device = CreateFileW(LR"(\\.\zero)", GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (!device)
    {
        std::cerr << "Failed to oped driver " << GetLastError() << '\n';
        return 1;
    }

    //todo  - read/write

    std::vector<BYTE> buffer(1024,0xff);
    DWORD read;
    auto res = ReadFile(device, buffer.data(), (DWORD)buffer.size(), &read, nullptr);
    if (!res)
    {
        std::cerr << "Failed to read from driver " << GetLastError() << '\n';
    }
    else
    {
        std::cout << "Read " << read << " bytes\n";
        for (auto val:buffer)
        {
            if (val != 0)
            {
                std::cerr << "Found non-zero value\n";
                break;
            }
        }
    }
    DWORD written;
    res = WriteFile(device, buffer.data(), (DWORD)buffer.size(), &written, NULL);
    if(!res)
    {
        std::cerr << "Failed to write to driver " << GetLastError() << '\n';
    }
    else
    {
        std::cout << "Written " << written << " bytes\n";
    }
    CloseHandle(device);//todo use RAII
    return 0;
}

