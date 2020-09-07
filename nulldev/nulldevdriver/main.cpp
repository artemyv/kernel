#include <Ntifs.h>
#include <Ntddk.h>
#include "StringWrapper.h"
#include "Common.h"

extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" DRIVER_UNLOAD ZeroDriverUnload;
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
extern "C" DRIVER_DISPATCH ZeroDriverCreateClose;
_Dispatch_type_(IRP_MJ_READ)
extern "C" DRIVER_DISPATCH ZeroDriverRead;
_Dispatch_type_(IRP_MJ_WRITE)
extern "C" DRIVER_DISPATCH ZeroDriverWrite;

#define LINK_NAME L"\\??\\zero"

#define FUNCTION_TYPE_FROM_CTL_CODE(ctrlCode)     (((ULONG)(ctrlCode & 0x3FFC)) >> 2)

_Use_decl_annotations_
extern "C"  NTSTATUS
DriverEntry(
    struct _DRIVER_OBJECT* DriverObject,
    PUNICODE_STRING  RegistryPath
)
{
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,    "INFO  nulldev.sys: DriverEntry Registry path %wZ\r\n", RegistryPath));

    UNICODE_STRING  ntUnicodeString = RTL_CONSTANT_STRING(L"\\Device\\zero");
    PDEVICE_OBJECT  deviceObject = nullptr;    // ptr to device object

    RUN_TEST_NTSTATUS(IoCreateDevice(DriverObject, 0,&ntUnicodeString,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE,&deviceObject));                

    UNICODE_STRING  ntWin32NameString = RTL_CONSTANT_STRING(LINK_NAME);

    auto res = IoCreateSymbolicLink(&ntWin32NameString, &ntUnicodeString);

    if (!NT_SUCCESS(res))
    {
        //
        // Delete everything that this routine has allocated.
        //
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR nulldev.sys: Couldn't create symbolic link 0x%x\r\n", res)); \
        IoDeleteDevice(deviceObject);
        return res;
    }

    deviceObject->Flags |= DO_DIRECT_IO;


    DriverObject->MajorFunction[IRP_MJ_CREATE] = ZeroDriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = ZeroDriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_READ] = ZeroDriverRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = ZeroDriverWrite;
    DriverObject->DriverUnload = ZeroDriverUnload;
    return STATUS_SUCCESS;
}


extern "C" void ZeroDriverUnload(
    _DRIVER_OBJECT* DriverObject
)
{
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO nulldev.sys: Unload\r\n"));
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

extern "C" NTSTATUS ZeroDriverCreateClose(
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
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO  nulldev.sys: Create/Close\r\n"));
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


extern "C" NTSTATUS ZeroDriverRead(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO  nulldev.sys: Read\r\n"));
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    auto bytes = irpSp->Parameters.Read.Length;
    Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
    if (irpSp && Irp->MdlAddress)
    {
        auto pReadDataBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

        if (pReadDataBuffer && bytes > 0)
        {
            /*
             * We use "RtlCopyMemory" in the kernel instead
             * of memcpy.
             * RtlCopyMemory *IS* memcpy, however it's best
             * to use the
             * wrapper in case this changes in the future.
             */
            RtlZeroMemory(pReadDataBuffer, bytes);
            Irp->IoStatus.Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = bytes;
        }
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

extern "C" NTSTATUS ZeroDriverWrite(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO  nulldev.sys: Write\r\n"));
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = irpSp->Parameters.Write.Length;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}
