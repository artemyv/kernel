#pragma once
//
// Device type           -- in the "User Defined" range."
//
#define PROCESSPROTECT_TYPE 40000
//
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
//
#define PROCESSPROTECT_SIOCTL_GETINFO \
    CTL_CODE( PROCESSPROTECT_TYPE, 0x900, METHOD_NEITHER, FILE_ANY_ACCESS  )

