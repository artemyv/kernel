#pragma once
//
// Device type           -- in the "User Defined" range."
//
#define REVEALERDRIVER_TYPE 40000
//
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
//
#define REVEALER_SIOCTL_OPEN_PROCESS \
    CTL_CODE( REVEALERDRIVER_TYPE, 0x900, METHOD_NEITHER, FILE_ANY_ACCESS  )

extern "C" struct ProcessData
{
    unsigned long pId;
    HANDLE        hProcess;
};