#include <iostream>
#include <string>
#include <Windows.h>
#include "../ProcessProtectDriver/Common.h"
int main()
{
    auto device = CreateFileW(LR"(\\.\ProcessProtect)", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (!device)
    {
        std::cerr << "Failed to oped driver " << GetLastError() << '\n';
        return 1;
    }

    CloseHandle(device);
    return 0;
}

