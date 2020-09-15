#include <Ntifs.h>
#include <Ntddk.h>
#include "StringWrapper.h"
#include "Common.h"

extern "C" DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD ProcessProtectUnload;
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH ProcessProtectCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH ProcessProtectDeviceControl;

OB_PREOP_CALLBACK_STATUS PobPreOperationCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);

#define LINK_NAME L"\\??\\ProcessProtect"

#define FUNCTION_TYPE_FROM_CTL_CODE(ctrlCode)     (((ULONG)(ctrlCode & 0x3FFC)) >> 2)
#define CB_PROCESS_TERMINATE 0x0001


struct Protected
{
    HANDLE pid;
};

constexpr size_t max_len = 1024;
struct Data
{
    Protected pids[max_len];
    size_t len;
    FAST_MUTEX m;

    PVOID pCBRegistrationHandle = NULL;

    bool IsProtectedProcess(POB_PRE_OPERATION_INFORMATION OperationInformation) 
    { 
        if (OperationInformation->ObjectType != *PsProcessType)
            return false;

        auto process = (PEPROCESS)OperationInformation->Object;
        HANDLE h = PsGetProcessId(process);
        bool found = false;
        ExAcquireFastMutex(&m);
        for (size_t index = 0; index < len; ++index)
        {
            if (h == pids[index].pid)
            {
                found = true;
                break;
            }
        }
        ExReleaseFastMutex(&m);
        return found;
    }

    NTSTATUS clear()
    {
        ExAcquireFastMutex(&m);
        len = 0;
        ExReleaseFastMutex(&m);
        return STATUS_SUCCESS;
    }
    NTSTATUS unprotect(HANDLE pid)
    {
        NTSTATUS result = STATUS_NOT_FOUND;
        ExAcquireFastMutex(&m);
        for (size_t index = 0; index < len; ++index)
        {
            if (pid == pids[index].pid)
            {
                pids[index] = pids[len -1];
                len--;
                result = STATUS_SUCCESS;
                break;
            }
        }
        ExReleaseFastMutex(&m);
        return result;
    }
    NTSTATUS protect(HANDLE pid)
    {
        NTSTATUS result = STATUS_SUCCESS;
        ExAcquireFastMutex(&m);
        for (size_t index = 0; index < len; ++index)
        {
            if (pid == pids[index].pid)
            {
                result = STATUS_ALREADY_REGISTERED;
                break;
            }
        }
        if (result == STATUS_SUCCESS)
        {
            if (len < max_len)
            {
                pids[len].pid = pid;
                ++len;
            }
            else
            {
                result = STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        ExReleaseFastMutex(&m);
        return result;
    }
};
_Use_decl_annotations_
extern "C"  NTSTATUS
DriverEntry(
    struct _DRIVER_OBJECT* DriverObject,
    PUNICODE_STRING  RegistryPath
)
{
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,    "INFO  ProcessProtect.sys: DriverEntry Registry path %wZ\r\n", RegistryPath));

    UNICODE_STRING  ntUnicodeString = RTL_CONSTANT_STRING(L"\\Device\\ProcessProtect");

    struct State
    {
        PDEVICE_OBJECT  deviceObject = nullptr;
        NTSTATUS status = STATUS_SUCCESS;
        bool SymbolicLinkCreated = false;

        ~State()
        {
            if (!NT_SUCCESS(status))
            {
                if (deviceObject)
                {
                    auto data = (Data*)deviceObject->DeviceExtension;
                    if (data && data->pCBRegistrationHandle)
                    {
                        ObUnRegisterCallbacks(data->pCBRegistrationHandle);
                    }
                    IoDeleteDevice(deviceObject);
                }
                if (SymbolicLinkCreated)
                {
                    UNICODE_STRING  ntWin32NameString = RTL_CONSTANT_STRING(LINK_NAME);
                    IoDeleteSymbolicLink(&ntWin32NameString);
                }
            }
        }

    } state;

    state.status = IoCreateDevice(DriverObject, sizeof(Data), &ntUnicodeString, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &state.deviceObject);
    if(!NT_SUCCESS(state.status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR ProcessProtect.sys: Couldn't create Device 0x%x\r\n", state.status));
        return state.status;
    }
    auto data = (Data*)state.deviceObject->DeviceExtension;
    ExInitializeFastMutex(&data->m);
    data->len = 0;

    UNICODE_STRING  ntWin32NameString = RTL_CONSTANT_STRING(LINK_NAME);

    state.status = IoCreateSymbolicLink(&ntWin32NameString, &ntUnicodeString);

    if (!NT_SUCCESS(state.status))
    {
        //
        // Delete everything that this routine has allocated.
        //
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR ProcessProtect.sys: Couldn't create symbolic link 0x%x\r\n", state.status));
        return state.status;
    }
    state.SymbolicLinkCreated = true;


    // Setup the Ob Registration calls
    //  The following are for setting up callbacks for Process and Thread filtering

    OB_CALLBACK_REGISTRATION  CBObRegistration = { 0 };
    OB_OPERATION_REGISTRATION CBOperationRegistrations[1] = { { 0 } };
    UNICODE_STRING CBAltitude = { 0 };

    CBOperationRegistrations[0].ObjectType = PsProcessType;
    CBOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_CREATE;
    CBOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
    CBOperationRegistrations[0].PreOperation = PobPreOperationCallback;
    CBOperationRegistrations[0].PostOperation = nullptr;

    RtlInitUnicodeString(&CBAltitude, L"1000");

    CBObRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    CBObRegistration.OperationRegistrationCount = 1;
    CBObRegistration.Altitude = CBAltitude;
    CBObRegistration.RegistrationContext = data;
    CBObRegistration.OperationRegistration = CBOperationRegistrations;


    state.status = ObRegisterCallbacks(
        &CBObRegistration,
        &data->pCBRegistrationHandle       // save the registration handle to remove callbacks later
    );

    if (!NT_SUCCESS(state.status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR ProcessProtect.sys: installing OB callbacks failed  status 0x%x\n", state.status));
        return state.status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = ProcessProtectCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = ProcessProtectCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ProcessProtectDeviceControl;
    DriverObject->DriverUnload = ProcessProtectUnload;
    return state.status;
}


void ProcessProtectUnload(
    _DRIVER_OBJECT* DriverObject
)
{
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO  ProcessProtect.sys: Unload\r\n"));
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;

    PAGED_CODE();
    UNICODE_STRING  ntWin32NameString = RTL_CONSTANT_STRING(LINK_NAME);
 
    //
    // Delete the link from our device name to a name in the Win32 namespace.
    //

    IoDeleteSymbolicLink(&ntWin32NameString);
    auto data = (Data*)deviceObject->DeviceExtension;
    if (data && data->pCBRegistrationHandle)
    {
        ObUnRegisterCallbacks(data->pCBRegistrationHandle);
    }

    IoDeleteDevice(deviceObject);
}

NTSTATUS ProcessProtectCreateClose(
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
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO  ProcessProtect.sys: CreateClose\r\n"));
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


NTSTATUS ProcessProtectDeviceControl(
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

    PAGED_CODE();

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    auto& dioc = irpSp->Parameters.DeviceIoControl;
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO  ProcessProtect.sys: DeviceControl %u:0x%x\r\n", DEVICE_TYPE_FROM_CTL_CODE(dioc.IoControlCode), FUNCTION_TYPE_FROM_CTL_CODE(dioc.IoControlCode)));
    auto data = (Data*)DeviceObject->DeviceExtension;
    switch (dioc.IoControlCode)
    {
    case IOCTL_PROCESS_PROTECT_BY_PID :
    case IOCTL_PROCESS_UNPROTECT_BY_PID:
    {
        if (dioc.Type3InputBuffer == nullptr)
        {
            ntStatus = STATUS_INVALID_PARAMETER;
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "INFO  ProcessProtect.sys: Type3InputBuffer is null\r\n"));
            break;
        }
        if (dioc.InputBufferLength < sizeof(PPProcessInfoIn))
        {
            ntStatus = STATUS_BUFFER_TOO_SMALL;
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "INFO  ProcessProtect.sys: TypeInputBufferLegnth is %u less than %u\r\n",
                unsigned(dioc.InputBufferLength), unsigned(sizeof(PPProcessInfoIn))));
            break;
        }
        auto dataIn = (PPProcessInfoIn*)dioc.Type3InputBuffer;
        //todo - open process and pass handle to caller
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO  ProcessProtect.sys: %s pid=%d\r\n", 
            (dioc.IoControlCode == IOCTL_PROCESS_PROTECT_BY_PID)?"adding":"removing",
            dataIn->pid));

        CLIENT_ID process{   };
        auto h = IntToPtr(dataIn->pid);

        if(dioc.IoControlCode == IOCTL_PROCESS_PROTECT_BY_PID)
            ntStatus = data->protect(h);
        else
            ntStatus = data->unprotect(h);

    }
        break;

    case IOCTL_PROCESS_PROTECT_CLEAR :
        ntStatus = data->clear();
        break;
    }



    Irp->IoStatus.Status = ntStatus;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return ntStatus;
}

OB_PREOP_CALLBACK_STATUS PobPreOperationCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    auto data = (Data*)RegistrationContext;
    if (data->IsProtectedProcess(OperationInformation))
    {
        switch (OperationInformation->Operation) {
        case OB_OPERATION_HANDLE_CREATE:
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~CB_PROCESS_TERMINATE;
            break;

        case OB_OPERATION_HANDLE_DUPLICATE:
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~CB_PROCESS_TERMINATE;
            break;
        }
    }

    return OB_PREOP_SUCCESS;
}