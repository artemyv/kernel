#include <iostream>
#include <string>
#include <Windows.h>
#include "../ProcessProtectDriver/Common.h"

void Usage(const char* prog)
{
    std::cout << "Usage:\n"
        << prog << " add <pid> [<pid2> ...]\n"
        << prog << " remove <pid> [<pid2> ...]\n"
        << prog << " clear\n";
}
int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        Usage(argv[0]);
        return 0;
    }
    enum class Command
    {
        add,
        remove,
        clear
    }cmd;
    std::string command{ argv[1] };
    if (command == "clear")
    {
        cmd = Command::clear;
    }
    else if (command == "add")
    {
        cmd = Command::add;
    }
    else if (command == "remove")
    {
        cmd = Command::remove;
    }
    else
    {
        Usage(argv[0]);
        return 0;
    }

    if ((cmd == Command::add || cmd == Command::remove) && argc < 3)
    {
        Usage(argv[0]);
        return 0;
    }

    auto device = CreateFileW(LR"(\\.\ProcessProtect)", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (!device)
    {
        std::cerr << "Failed to oped driver " << GetLastError() << '\n';
        return 1;
    }
    DWORD bytesReturned;
    if (cmd == Command::clear)
    {
        if (!DeviceIoControl(device,
            (DWORD)IOCTL_PROCESS_PROTECT_CLEAR,
            nullptr,
            0,
            nullptr,
            0,
            &bytesReturned,
            nullptr))
        {
            std::cerr << "Failed to call DeviceIoControl " << GetLastError() << '\n';
        }
        else
        {
            std::cout << "Protected process list cleared\n";
        }
    }
    else
    {
        for (int index = 2; index < argc; index++)
        {
            std::string pid = argv[index];
            PPProcessInfoIn in{ std::stoi(pid) };
            DWORD control = (cmd == Command::add) ? IOCTL_PROCESS_PROTECT_BY_PID : IOCTL_PROCESS_UNPROTECT_BY_PID;
            if (!DeviceIoControl(device,
                control,
                &in,
                (DWORD)sizeof(in),
                nullptr,
                0,
                &bytesReturned,
                nullptr))
            {
                std::cerr << "Failed to call DeviceIoControl " << GetLastError() << '\n';
            }
            else
            {
                std::cout << "PID " << pid << ' ' << ((cmd == Command::add)?"added":"removed") << "\n";
            }
        }
    }

    CloseHandle(device);
    return 0;
}

