#include <iostream>
#include <string>
#include <Windows.h>
#include "../SysMonDriver/Common.h"
#include <fmt/format.h>

void DisplayTime(ULONGLONG time) {
	SYSTEMTIME st;
	FILETIME local;
	FileTimeToLocalFileTime((FILETIME*)&time, &local);
	FileTimeToSystemTime(&local, &st);
	fmt::print("{:02d}:{:02d}:{:02d}.{:03d}", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}


static void DisplayEvents(const BYTE* buffer, DWORD size) {
	while (size > 0) {
		auto header = (EventHeader*)buffer;
		DisplayTime(header->TimeStamp.QuadPart);
		fmt::print(" ");
		switch (header->Type) {
		case EventType::ProcessExit:
		{
			auto data = (ProcessExitEvent*)header;
			fmt::print("Process exited: PID={}\n", data->ProcessId);
			break;
		}
		case EventType::ProcessCreate:
		{
			auto data = (ProcessCreateEvent*)header;
			fmt::print(L"Process created: PID={} PPID={} CommandLine={}\n",
				data->ProcessId, data->ParentProcessId,
				std::wstring((PCWSTR)(buffer + data->CommandLineOffset), data->CommandLineLength));
			break;
		}
		case EventType::ThreadCreate:
		case EventType::ThreadExit:
		{
			auto data = (ThreadCreateExitEvent*)header;
			fmt::print("Thread {}: PID={} TID={}\n",
				header->Type == EventType::ThreadCreate ? "create" : "exit",
				data->ProcessId, data->ThreadId);
			break;
		}

		case EventType::RegistrySetValue:
		{
			auto data = (RegistrySetValueEvent*)header;
			fmt::print(L"Reg set value: PID={} TID={} Key={} Value={} Type={} Size={} ",
				data->ProcessId, data->ThreadId, data->KeyName, data->ValueName, data->DataType, data->DataSize);
			auto value = (BYTE*)(data + 1);
			for (ULONG i = 0; i < /*data->BufferSize*/16; i++)
				fmt::print("{:02x} ", value[i]);
			fmt::print("\n");
			break;
		}
		}
		buffer += header->Size;
		size -= header->Size;
	}
}

int main()
{
	auto hDevice = CreateFileW(L"\\\\.\\SysMon", GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE) {
		fmt::print("Error opening device err={}\n", GetLastError());
		return 1;
	}

	fmt::print("Device opened\n");
    static BYTE buffer[1 << 16];//making static to avoid buffer allocation on stack
    for (;;) {
        DWORD bytes;
		if (!ReadFile(hDevice, buffer, sizeof(buffer), &bytes, nullptr))
		{
			fmt::print("Failed to read from device err={}\n", GetLastError());
			break;
		}
        DisplayEvents(buffer, bytes);
        Sleep(500);
    }

    CloseHandle(hDevice);
	fmt::print("Device closed\n");
	return 0;
}

