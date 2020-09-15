#include <Ntifs.h>
#include <Ntddk.h>
#include "StringWrapper.h"
#include "Common.h"

extern "C" DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD SysMonUnload;
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH SysMonCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH SysMonDeviceControl;

void PcreateProcessNotifyRoutineEx(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
);

#define LINK_NAME L"\\??\\SysMon"

#define FUNCTION_TYPE_FROM_CTL_CODE(ctrlCode)     (((ULONG)(ctrlCode & 0x3FFC)) >> 2)

_Use_decl_annotations_
extern "C"  NTSTATUS
DriverEntry(
    struct _DRIVER_OBJECT* DriverObject,
    PUNICODE_STRING  RegistryPath
)
{
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,    "INFO  SysMon.sys: DriverEntry Registry path %wZ\r\n", RegistryPath));

    UNICODE_STRING  ntUnicodeString = RTL_CONSTANT_STRING(L"\\Device\\SysMon");

    struct State
    {
        PDEVICE_OBJECT  deviceObject = nullptr;
        NTSTATUS status = STATUS_SUCCESS;
        bool SymbolicLinkCreated = false;
        bool RegisteredToCreateCB = false;
        ~State()
        {
            if (!NT_SUCCESS(status))
            {
                if(deviceObject)
                    IoDeleteDevice(deviceObject);

                if (SymbolicLinkCreated)
                {
                    UNICODE_STRING  ntWin32NameString = RTL_CONSTANT_STRING(LINK_NAME);
                    IoDeleteSymbolicLink(&ntWin32NameString);
                }
                if (RegisteredToCreateCB)
                {
                    PsSetCreateProcessNotifyRoutineEx(PcreateProcessNotifyRoutineEx, TRUE);
                }
            }
        }

    } state;

    state.status = IoCreateDevice(DriverObject, 0, &ntUnicodeString, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &state.deviceObject);
    if(!NT_SUCCESS(state.status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR SysMon.sys: Couldn't create Device 0x%x\r\n", state.status));
        return state.status;
    }

    UNICODE_STRING  ntWin32NameString = RTL_CONSTANT_STRING(LINK_NAME);

    state.status = IoCreateSymbolicLink(&ntWin32NameString, &ntUnicodeString);

    if (!NT_SUCCESS(state.status))
    {
        //
        // Delete everything that this routine has allocated.
        //
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR SysMon.sys: Couldn't create symbolic link 0x%x\r\n", state.status));
        return state.status;
    }
    state.SymbolicLinkCreated = true;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = SysMonCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = SysMonCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SysMonDeviceControl;
    DriverObject->DriverUnload = SysMonUnload;

    state.status = PsSetCreateProcessNotifyRoutineEx(PcreateProcessNotifyRoutineEx,FALSE);
    if (!NT_SUCCESS(state.status))
    {
        //
        // Delete everything that this routine has allocated.
        //
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR SysMon.sys: PsSetCreateProcessNotifyRoutine failed 0x%x\r\n", state.status));
        return state.status;
    }
    state.RegisteredToCreateCB = true;


    return state.status;
}


void SysMonUnload(
    _DRIVER_OBJECT* DriverObject
)
{
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO  SysMon.sys: Unload\r\n"));
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;

    PAGED_CODE();
    UNICODE_STRING  ntWin32NameString = RTL_CONSTANT_STRING(LINK_NAME);
 
    //
    // Delete the link from our device name to a name in the Win32 namespace.
    //

    IoDeleteSymbolicLink(&ntWin32NameString);
    IoDeleteDevice(deviceObject);

    PsSetCreateProcessNotifyRoutineEx(PcreateProcessNotifyRoutineEx, TRUE);
}

NTSTATUS SysMonCreateClose(
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
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO  SysMon.sys: CreateClose\r\n"));
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


NTSTATUS SysMonDeviceControl(
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
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO  SysMon.sys: DeviceControl %u:0x%x\r\n", DEVICE_TYPE_FROM_CTL_CODE(dioc.IoControlCode), FUNCTION_TYPE_FROM_CTL_CODE(dioc.IoControlCode)));

    //switch (dioc.IoControlCode)
    //{

    //    break;
    //}

    Irp->IoStatus.Status = ntStatus;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return ntStatus;
}

void PcreateProcessNotifyRoutineEx(
    PEPROCESS /*Process*/,
    HANDLE /*ProcessId*/,
    PPS_CREATE_NOTIFY_INFO /*CreateInfo*/
)
{
}