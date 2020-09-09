#pragma once
//
// Device type           -- in the "User Defined" range."
//
#define NULLDEV_DRIVER_TYPE 40000
//
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
//
#define ZERO_SIOCTL_GETSTATS \
    CTL_CODE( NULLDEV_DRIVER_TYPE, 0x900, METHOD_NEITHER, FILE_ANY_ACCESS  )
#define ZERO_SIOCTL_RESETSTATS \
    CTL_CODE( NULLDEV_DRIVER_TYPE, 0x901, METHOD_NEITHER, FILE_ANY_ACCESS  )

extern "C" struct StatsDataOut
{
    unsigned long read;
    unsigned long written;
};
