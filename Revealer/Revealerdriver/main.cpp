#include <Ntifs.h>
#include <Ntddk.h>
#include "StringWrapper.h"
#include "Common.h"

extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" DRIVER_UNLOAD RevealerDriverUnload;
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
extern "C" DRIVER_DISPATCH RevealerDriverCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
extern "C" DRIVER_DISPATCH RevealerDriverDeviceControl;

#define LINK_NAME L"\\??\\revealer"

#define FUNCTION_TYPE_FROM_CTL_CODE(ctrlCode)     (((ULONG)(ctrlCode & 0x3FFC)) >> 2)

static NTSTATUS AddOsVersionToReg(PUNICODE_STRING  RegistryPath)
{
    RTL_OSVERSIONINFOW info;
    RUN_TEST_NTSTATUS( RtlGetVersion(&info));

    StringWrapper str;
    RUN_TEST_NTSTATUS(str.Format(L"OS Version %u.%u.%u Platform %u", (unsigned)info.dwMajorVersion, (unsigned)info.dwMinorVersion, (unsigned)info.dwBuildNumber, (unsigned)info.dwPlatformId));
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO  Revealer.sys: OS_DETAILS=%S\r\n", str.str()));

    StringWrapper path;
    RUN_TEST_NTSTATUS( path.Format(L"%wZ", RegistryPath));
    RUN_TEST_NTSTATUS(RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, path.str(), L"OS_DETAILS", REG_SZ, str.str(), (ULONG)str.getBytes()));
    return STATUS_SUCCESS;
}
_Use_decl_annotations_
extern "C"  NTSTATUS
DriverEntry(
    struct _DRIVER_OBJECT* DriverObject,
    PUNICODE_STRING  RegistryPath
)
{
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,    "INFO  Revealer.sys: DriverEntry Registry path %wZ\r\n", RegistryPath));

    RUN_TEST_NTSTATUS(AddOsVersionToReg(RegistryPath));

    UNICODE_STRING  ntUnicodeString = RTL_CONSTANT_STRING(L"\\Device\\revealer");
    PDEVICE_OBJECT  deviceObject = nullptr;    // ptr to device object

    RUN_TEST_NTSTATUS(IoCreateDevice(DriverObject, 0,&ntUnicodeString,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE,&deviceObject));                

    UNICODE_STRING  ntWin32NameString = RTL_CONSTANT_STRING(LINK_NAME);

    auto res = IoCreateSymbolicLink(&ntWin32NameString, &ntUnicodeString);

    if (!NT_SUCCESS(res))
    {
        //
        // Delete everything that this routine has allocated.
        //
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR Revealer.sys: Couldn't create symbolic link 0x%x\r\n", res)); \
        IoDeleteDevice(deviceObject);
        return res;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = RevealerDriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = RevealerDriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RevealerDriverDeviceControl;
    DriverObject->DriverUnload = RevealerDriverUnload;
    return STATUS_SUCCESS;
}


extern "C" void RevealerDriverUnload(
    _DRIVER_OBJECT* DriverObject
)
{
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO  Revealer.sys: Unload\r\n"));
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;

    PAGED_CODE();
    UNICODE_STRING  ntWin32NameString = RTL_CONSTANT_STRING(LINK_NAME);
 
    //
    // Delete the link from our device name to a name in the Win32 namespace.
    //

    IoDeleteSymbolicLink(&ntWin32NameString);

    if (deviceObject != NULL)
    {
        IoDeleteDevice(deviceObject);
    }
}

extern "C" NTSTATUS
RevealerDriverCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
/*++

Routine Description:

    This routine is called by the I/O system when the SIOCTL is opened or
    closed.

    No action is performed other than completing the request successfully.

Arguments:

    DeviceObject - a pointer to the object that represents the device
    that I/O is to be done on.

    Irp - a pointer to the I/O Request Packet for this request.

Return Value:

    NT status code

--*/

{
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO  Revealer.sys: CreateClose\r\n"));
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


extern "C" NTSTATUS
RevealerDriverDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)

/*++

Routine Description:

    This routine is called by the I/O system to perform a device I/O
    control function.

Arguments:

    DeviceObject - a pointer to the object that represents the device
        that I/O is to be done on.

    Irp - a pointer to the I/O Request Packet for this request.

Return Value:

    NT status code

--*/

{
    NTSTATUS            ntStatus = STATUS_INVALID_DEVICE_REQUEST;

    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    auto& dioc = irpSp->Parameters.DeviceIoControl;
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO  Revealer.sys: DeviceControl %u:0x%x\r\n", DEVICE_TYPE_FROM_CTL_CODE(dioc.IoControlCode), FUNCTION_TYPE_FROM_CTL_CODE(dioc.IoControlCode)));

    switch (dioc.IoControlCode)
    {
    case REVEALER_SIOCTL_OPEN_PROCESS:
        if (dioc.Type3InputBuffer == nullptr)
        {
            ntStatus = STATUS_INVALID_PARAMETER;
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "INFO  Revealer.sys: Type3InputBuffer is null\r\n"));
            break;
        }
        if (dioc.InputBufferLength < sizeof(ProcessData))
        {
            ntStatus = STATUS_BUFFER_TOO_SMALL;
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "INFO  Revealer.sys: TypeInputBufferLegnth is %u less than %u\r\n", 
                unsigned(dioc.InputBufferLength), unsigned(sizeof(ProcessData))));
            break;
        }
        auto data = (ProcessData*)dioc.Type3InputBuffer;
 
        //todo - open process and pass handle to caller
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO  Revealer.sys: opening pid=%u\r\n", (unsigned)data->pId));

        break;
    }

    //
    // Finish the I/O operation by simply completing the packet and returning
    // the same status as in the packet itself.
    //

    Irp->IoStatus.Status = ntStatus;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return ntStatus;
}