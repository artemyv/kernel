#pragma once
//
// Device type           -- in the "User Defined" range."
//
#define SYSMON_TYPE 40000
//
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
//
#define SYSMON_TYPE_SIOCTL_GETINFO \
    CTL_CODE( PROCESSPROTECT_TYPE, 0x900, METHOD_NEITHER, FILE_ANY_ACCESS  )


//No 32 app ->64bit driver support planned
//No C App support planned
enum class EventType
{
    ProcessStart,
    ProcessEnd,
    ThreadStart,
    ThreadEnd
};
struct EventHeader
{
    size_t    size;
    EventType type;
    ULONG64   timestamp;
};

struct ProcessStartEvent : EventHeader
{
    INT32 pid;
    size_t processNamelen;
    wchar_t processName[1]; //Array extends beyond the struct - has to be last member
};

struct ProcessEndEvent : EventHeader
{
    INT32 pid;
};
