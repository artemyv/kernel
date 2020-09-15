#pragma once
//
// Device type           -- in the "User Defined" range."
//
#define PROCESSPROTECT_TYPE 40000
//
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
//
#define IOCTL_PROCESS_PROTECT_BY_PID  \
    CTL_CODE( PROCESSPROTECT_TYPE, 0x900, METHOD_NEITHER, FILE_ANY_ACCESS  )

#define IOCTL_PROCESS_UNPROTECT_BY_PID  \
    CTL_CODE( PROCESSPROTECT_TYPE, 0x901, METHOD_NEITHER, FILE_ANY_ACCESS  )

#define IOCTL_PROCESS_PROTECT_CLEAR   \
    CTL_CODE( PROCESSPROTECT_TYPE, 0x902, METHOD_NEITHER, FILE_ANY_ACCESS  )

struct PPProcessInfoIn
{
    INT32 pid;
};