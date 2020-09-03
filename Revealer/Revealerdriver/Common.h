#pragma once
//
// Device type           -- in the "User Defined" range."
//
#define VARTDRIVER_TYPE 40000
//
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
//
#define VARTDRIVER_SIOCTL_SET_PRIORITY \
    CTL_CODE( VARTDRIVER_TYPE, 0x900, METHOD_NEITHER, FILE_ANY_ACCESS  )

extern "C" struct ThreadData
{
    unsigned long threadId;
    int           threadPriority;
};