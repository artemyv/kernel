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

    
    StatsDataOut data{};
    DWORD bytesReturned;
    if (!DeviceIoControl(device,
        (DWORD)ZERO_SIOCTL_GETSTATS,
        nullptr,
        0,
        &data,
        sizeof(data),
        &bytesReturned,
        nullptr))
    {
        std::cerr << "Failed to call DeviceIoControl " << GetLastError() << '\n';
    }
    else
    {
        std::cout << "Before read=" << data.read << ", written=" << data.written << "\n";
    }

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

    if (!DeviceIoControl(device,
        (DWORD)ZERO_SIOCTL_GETSTATS,
        nullptr,
        0,
        &data,
        sizeof(data),
        &bytesReturned,
        nullptr))
    {
        std::cerr << "Failed to call DeviceIoControl " << GetLastError() << '\n';
    }
    else
    {
        std::cout << "After Read read=" << data.read << ", written=" << data.written << "\n";
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

    if (!DeviceIoControl(device,
        (DWORD)ZERO_SIOCTL_GETSTATS,
        nullptr,
        0,
        &data,
        sizeof(data),
        &bytesReturned,
        nullptr))
    {
        std::cerr << "Failed to call DeviceIoControl " << GetLastError() << '\n';
    }
    else
    {
        std::cout << "After Write read=" << data.read << ", written=" << data.written << "\n";
    }

    DeviceIoControl(device,
        (DWORD)ZERO_SIOCTL_RESETSTATS,
        nullptr,
        0,
        0,
        0,
        &bytesReturned,
        nullptr);
    if (!DeviceIoControl(device,
        (DWORD)ZERO_SIOCTL_GETSTATS,
        nullptr,
        0,
        &data,
        sizeof(data),
        &bytesReturned,
        nullptr))
    {
        std::cerr << "Failed to call DeviceIoControl " << GetLastError() << '\n';
    }
    else
    {
        std::cout << "After reset read=" << data.read << ", written=" << data.written << "\n";
    }

    CloseHandle(device);//todo use RAII
    return 0;
}

