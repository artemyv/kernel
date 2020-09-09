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
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
extern "C" DRIVER_DISPATCH ZeroDriverDeviceControl;


#define LINK_NAME L"\\??\\zero"

#define FUNCTION_TYPE_FROM_CTL_CODE(ctrlCode)     (((ULONG)(ctrlCode & 0x3FFC)) >> 2)

struct Statictics
{
    LONG volatile readBytes;
    LONG volatile writtenBytes;
    UNICODE_STRING  RegistryPath;
};
static NTSTATUS InitStats(Statictics*, PUNICODE_STRING  RegistryPath);
static NTSTATUS FlushStats(Statictics*);
static NTSTATUS ReadDwordFromRegistry(
    IN PUNICODE_STRING KeyName,
    IN PUNICODE_STRING ValueName,
    IN OUT PULONG Value
);
static NTSTATUS
WriteDwordToRegistry(
    IN PUNICODE_STRING KeyName,
    IN PUNICODE_STRING ValueName,
    IN ULONG           Value
);


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

    RUN_TEST_NTSTATUS(IoCreateDevice(DriverObject, sizeof(Statictics),&ntUnicodeString,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE,&deviceObject));

    UNICODE_STRING  ntWin32NameString = RTL_CONSTANT_STRING(LINK_NAME);

    auto res = IoCreateSymbolicLink(&ntWin32NameString, &ntUnicodeString);

    if (!NT_SUCCESS(res))
    {
        //
        // Delete everything that this routine has allocated.
        //
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR nulldev.sys: Couldn't create symbolic link 0x%x\r\n", res));
        IoDeleteDevice(deviceObject);
        return res;
    }

    deviceObject->Flags |= DO_DIRECT_IO;

    auto stats = (Statictics*)deviceObject->DeviceExtension;
    res = InitStats(stats, RegistryPath);
    if (!NT_SUCCESS(res))
    {
        //
        // Delete everything that this routine has allocated.
        //
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR nulldev.sys: Couldn't InitStats\r\n", res));
        IoDeleteDevice(deviceObject);
        IoDeleteSymbolicLink(&ntWin32NameString);
        return res;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = ZeroDriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = ZeroDriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_READ] = ZeroDriverRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = ZeroDriverWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ZeroDriverDeviceControl;
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
        auto stats = (Statictics*)deviceObject->DeviceExtension;
        FlushStats(stats);
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
    auto stats = (Statictics*)DeviceObject->DeviceExtension;

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

            auto result = InterlockedExchangeAdd(&stats->readBytes, bytes);
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO  nulldev.sys: Read %u bytes, total read %u bytes\r\n", bytes, bytes+result));
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
    auto stats = (Statictics*)DeviceObject->DeviceExtension;

    PAGED_CODE();
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = irpSp->Parameters.Write.Length;
    auto result = InterlockedExchangeAdd(&stats->writtenBytes, irpSp->Parameters.Write.Length);
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO  nulldev.sys: Written %u bytes, total written %u bytes\r\n", irpSp->Parameters.Write.Length, irpSp->Parameters.Write.Length+result));

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS InitStats(Statictics*stats, PUNICODE_STRING  RegistryPath)
{

    stats->readBytes = 0;
    stats->writtenBytes = 0;
    stats->RegistryPath.Buffer = nullptr;
    stats->RegistryPath.Length = 0;
    stats->RegistryPath.MaximumLength = 0;

    UNICODE_STRING  ValueName = RTL_CONSTANT_STRING(L"Read");
    ULONG read;
    RUN_TEST_NTSTATUS(ReadDwordFromRegistry(RegistryPath, &ValueName, &read));
    UNICODE_STRING  ValueName2 = RTL_CONSTANT_STRING(L"Written");
    ULONG written;
    RUN_TEST_NTSTATUS(ReadDwordFromRegistry(RegistryPath, &ValueName2, &written));

    stats->readBytes = read;
    stats->writtenBytes = written;

    stats->RegistryPath.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, stats->RegistryPath.MaximumLength, POOLTAG_VART);
    if (stats->RegistryPath.Buffer == nullptr)
    {
        return STATUS_NO_MEMORY;
    }
    stats->RegistryPath.MaximumLength = RegistryPath->MaximumLength;
    RtlCopyUnicodeString(&stats->RegistryPath, RegistryPath);
    return STATUS_SUCCESS;
}

NTSTATUS FlushStats(Statictics* stats)
{
    UNICODE_STRING  ValueName = RTL_CONSTANT_STRING(L"Read");
    ULONG read = stats->readBytes;
    auto res = WriteDwordToRegistry(&stats->RegistryPath, &ValueName, read);
    if (!NT_SUCCESS(res))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR nulldev.sys:Failed to write read=%u to %wZ\r\n", read, &stats->RegistryPath));
    }
    UNICODE_STRING  ValueName2 = RTL_CONSTANT_STRING(L"Written");
    ULONG written = stats->writtenBytes;
    res = WriteDwordToRegistry(&stats->RegistryPath, &ValueName2, written);
    if (!NT_SUCCESS(res))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR nulldev.sys:Failed to write written=%u to %wZ\r\n", written, &stats->RegistryPath));
    }

    if (stats->RegistryPath.Buffer)
        ExFreePoolWithTag(stats->RegistryPath.Buffer, POOLTAG_VART);
    stats->RegistryPath.Buffer = nullptr;
    stats->RegistryPath.Length = 0;
    stats->RegistryPath.MaximumLength = 0;
    return STATUS_SUCCESS;
}

NTSTATUS
ReadDwordFromRegistry(
    IN PUNICODE_STRING KeyName,
    IN PUNICODE_STRING ValueName,
    IN OUT PULONG Value
)

/*++

Routine Description:

    Given a unicode value name this routine will go into the registry
    location for the Chicago compatibilitymode information and get the
    value.

Arguments:

    ValueName - the unicode name for the registry value located in the registry.
    Value   - a pointer to the ULONG for the result.

Return Value:

    NTSTATUS

    If STATUS_SUCCESSFUL is returned, the location *Value will be
    updated with the DWORD value from the registry.  If any failing
    status is returned, this value is untouched.

--*/

{
    constexpr auto KEY_WORK_AREA = ((sizeof(KEY_VALUE_FULL_INFORMATION) + sizeof(ULONG)) + 64);

    HANDLE Handle;
    NTSTATUS Status;
    ULONG RequestLength;
    ULONG ResultLength;
    UCHAR Buffer[KEY_WORK_AREA];
    OBJECT_ATTRIBUTES ObjectAttributes;
    PKEY_VALUE_FULL_INFORMATION KeyValueInformation;


    InitializeObjectAttributes(&ObjectAttributes,
        KeyName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    Status = ZwOpenKey(&Handle,
        KEY_READ,
        &ObjectAttributes);

    if (!NT_SUCCESS(Status)) {

        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR nulldev.sys: ZwOpenKey(READ, %wZ) failed 0x%x\r\n", KeyName, Status));
        return Status;
    }

    RequestLength = KEY_WORK_AREA;

    KeyValueInformation = (PKEY_VALUE_FULL_INFORMATION)Buffer;

    while (1) {

        Status = ZwQueryValueKey(Handle,
            ValueName,
            KeyValueFullInformation,
            KeyValueInformation,
            RequestLength,
            &ResultLength);

        NT_ASSERT(Status != STATUS_BUFFER_OVERFLOW);

        if (Status == STATUS_BUFFER_OVERFLOW) {

            //
            // Try to get a buffer big enough.
            //

            if (KeyValueInformation != (PKEY_VALUE_FULL_INFORMATION)Buffer) {

                ExFreePoolWithTag(KeyValueInformation, POOLTAG_VART);
            }

            RequestLength += 256;

            KeyValueInformation = (PKEY_VALUE_FULL_INFORMATION)
                ExAllocatePoolWithTag(PagedPool,
                    RequestLength,
                    POOLTAG_VART);

            if (!KeyValueInformation) {

                ZwClose(Handle);
                return STATUS_NO_MEMORY;
            }

        }
        else {

            break;
        }
    }

    ZwClose(Handle);

    if (NT_SUCCESS(Status)) {

        if (KeyValueInformation->DataLength != 0) {

            PULONG DataPtr;

            //
            // Return contents to the caller.
            //

            DataPtr = (PULONG)
                ((PUCHAR)KeyValueInformation + KeyValueInformation->DataOffset);
            *Value = *DataPtr;

        }
        else {

            //
            // Treat as if no value was found
            //

            Status = STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }
    else
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR nulldev.sys: ZwQueryValueKey(%wZ) failed 0x%x\r\n", KeyName, Status));
    }

    if (KeyValueInformation != (PKEY_VALUE_FULL_INFORMATION)Buffer) {

        ExFreePoolWithTag(KeyValueInformation, POOLTAG_VART);
    }
    if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
    {
        //missing value is not an error - return 0
        *Value = 0;
        Status = STATUS_SUCCESS;
    }
    if (NT_SUCCESS(Status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Info nulldev.sys: Read %wZ\\%wZ => %u\r\n", KeyName, ValueName, *Value));
    }
    return Status;
}

NTSTATUS
WriteDwordToRegistry(
    IN PUNICODE_STRING KeyName,
    IN PUNICODE_STRING ValueName,
    IN ULONG           Value
)

/*++

Routine Description:

    Given a unicode value name this routine will go into the registry
    location for the Chicago compatibilitymode information and get the
    value.

Arguments:

    ValueName - the unicode name for the registry value located in the registry.
    Value   - a pointer to the ULONG for the result.

Return Value:

    NTSTATUS

    If STATUS_SUCCESSFUL is returned, the location *Value will be
    updated with the DWORD value from the registry.  If any failing
    status is returned, this value is untouched.

--*/

{
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes,
        KeyName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    HANDLE Handle;
    auto Status = ZwOpenKey(&Handle,
        KEY_WRITE,
        &ObjectAttributes);

    if (!NT_SUCCESS(Status)) {

        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR nulldev.sys: ZwOpenKey(WRITE, %wZ) failed 0x%x\r\n", KeyName, Status));
        return Status;
    }

    Status = ZwSetValueKey(Handle,
        ValueName,
        0,
        REG_DWORD,
        &Value,
        sizeof(Value));

    if (!NT_SUCCESS(Status)) {

        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR nulldev.sys: ZwSetValueKey(%wZ) failed 0x%x\r\n", KeyName, Status));
    }
    else
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Info nulldev.sys: Set %wZ\\%wZ = %u\r\n", KeyName, ValueName, Value));
    }
    ZwClose(Handle);

    return Status;
}

extern "C" NTSTATUS
ZeroDriverDeviceControl(
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

    auto stats = (Statictics*)DeviceObject->DeviceExtension;

    PAGED_CODE();

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    auto& dioc = irpSp->Parameters.DeviceIoControl;
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO  Zero.sys: DeviceControl %u:0x%x\r\n", DEVICE_TYPE_FROM_CTL_CODE(dioc.IoControlCode), FUNCTION_TYPE_FROM_CTL_CODE(dioc.IoControlCode)));

    switch (dioc.IoControlCode)
    {
    case ZERO_SIOCTL_GETSTATS:
        if (dioc.OutputBufferLength < sizeof(StatsDataOut))
        {
            ntStatus = STATUS_BUFFER_TOO_SMALL;
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "INFO  Zero.sys: OutputBufferLength is %u less than %u\r\n",
                unsigned(dioc.OutputBufferLength), unsigned(sizeof(StatsDataOut))));
            break;
        }
        {
            auto out = (StatsDataOut*)Irp->UserBuffer;

            out->read = InterlockedCompareExchange(&stats->readBytes, 0, 0);
            out->written = InterlockedCompareExchange(&stats->writtenBytes, 0, 0);
            Irp->IoStatus.Information = sizeof(StatsDataOut);
            ntStatus = STATUS_SUCCESS;
        }
        break;

    case ZERO_SIOCTL_RESETSTATS:
        InterlockedExchange(&stats->readBytes, 0);
        InterlockedExchange(&stats->writtenBytes, 0);
        ntStatus = STATUS_SUCCESS;
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