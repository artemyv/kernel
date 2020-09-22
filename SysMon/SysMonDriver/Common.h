#pragma once
enum class EventType
{
    ProcessCreate,
    ProcessExit,
    ThreadCreate,
    ThreadExit,
    RegistrySetValue
};
struct EventHeader
{
    LARGE_INTEGER TimeStamp;
    EventType     Type;
    USHORT        Size;
};

struct ProcessCreateEvent : EventHeader
{
    ULONG ProcessId;
    ULONG ParentProcessId;
    USHORT CommandLineLength;
    USHORT CommandLineOffset;
};

struct ProcessExitEvent : EventHeader
{
    ULONG ProcessId;
};

struct ThreadCreateExitEvent : EventHeader
{
    ULONG ProcessId;
    ULONG ThreadId;
};

struct RegistrySetValueEvent : EventHeader {
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG DataType;	// REG_xxx
    ULONG DataSize;
    ULONG BufferSize;
    WCHAR KeyName[256];
    WCHAR ValueName[256];
    // data follows here
};
