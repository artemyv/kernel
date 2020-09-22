#include <Ntifs.h>
#include <Ntddk.h>
#include "StringWrapper.h"
#include "Common.h"
#include "FastMutex.h"
#include "AutoLocker.h"

extern "C" DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD SysMonUnload;
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH SysMonCreateClose;
NTSTATUS SysMonRead(PDEVICE_OBJECT, PIRP Irp);

void OnProcessNotify(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
);

void OnThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);
NTSTATUS OnRegistryNotify(PVOID, PVOID arg1, PVOID arg2);


#define LINK_NAME L"\\??\\SysMon"

#define FUNCTION_TYPE_FROM_CTL_CODE(ctrlCode)     (((ULONG)(ctrlCode & 0x3FFC)) >> 2)

struct Globals {
    LIST_ENTRY EventsHead;
    ULONG EventsCount;
    FastMutex Lock;
    LARGE_INTEGER RegCookie;
    IO_REMOVE_LOCK RemoveLock;

    void Init()
    {
        InitializeListHead(&EventsHead);
        EventsCount = 0;
        Lock.Init();
        IoInitializeRemoveLock(&RemoveLock, DRIVER_TAG, 0, 0);
    }
};
template<typename T>
struct EventData {
    LIST_ENTRY Entry;
    T Data;
};

PDEVICE_OBJECT  GlobalDeviceObject;

_Use_decl_annotations_
extern "C"  NTSTATUS
DriverEntry(
    struct _DRIVER_OBJECT* DriverObject,
    PUNICODE_STRING  RegistryPath
)
{
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,    "INFO  SysMon.sys: DriverEntry Registry path %wZ\r\n", RegistryPath));


    struct State
    {
        PDEVICE_OBJECT  deviceObject = nullptr;
        NTSTATUS status = STATUS_SUCCESS;
        bool SymbolicLinkCreated = false;
        bool processNotifyCreated = false;
        bool threadNotifyCreated = false;
        bool regNotifyCreated = false;
        ~State()
        {
            if (!NT_SUCCESS(status))
            {
                if (regNotifyCreated)
                {
                    auto data = (Globals*)deviceObject->DeviceExtension;
                    CmUnRegisterCallback(data->RegCookie);
                }
                if (threadNotifyCreated)
                {
                    PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);
                }
                if (processNotifyCreated)
                {
                    PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
                }
                if (SymbolicLinkCreated)
                {
                    UNICODE_STRING  ntWin32NameString = RTL_CONSTANT_STRING(LINK_NAME);
                    IoDeleteSymbolicLink(&ntWin32NameString);
                }
                if(deviceObject)
                    IoDeleteDevice(deviceObject);
            }
        }

    } state;

    UNICODE_STRING  ntUnicodeString = RTL_CONSTANT_STRING(L"\\Device\\SysMon");
    state.status = IoCreateDevice(DriverObject, sizeof(Globals), &ntUnicodeString, FILE_DEVICE_UNKNOWN, 0, TRUE, &state.deviceObject);
    if(!NT_SUCCESS(state.status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR SysMon.sys: Couldn't create Device 0x%x\r\n", state.status));
        return state.status;
    }
    state.deviceObject->Flags |= DO_DIRECT_IO;
    auto data = (Globals*)state.deviceObject->DeviceExtension;
    data->Init();

    GlobalDeviceObject = state.deviceObject; //Get access from CBs

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
    DriverObject->MajorFunction[IRP_MJ_READ] = SysMonRead;
    DriverObject->DriverUnload = SysMonUnload;

    state.status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
    if (!NT_SUCCESS(state.status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR SysMon.sys: PsSetCreateProcessNotifyRoutine failed 0x%x\r\n", state.status));
        return state.status;
    }
    state.processNotifyCreated = true;

    state.status = PsSetCreateThreadNotifyRoutine(OnThreadNotify);
    if (!NT_SUCCESS(state.status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR SysMon.sys: PsSetCreateThreadNotifyRoutine failed 0x%x\r\n", state.status));
        return state.status;
    }
    state.threadNotifyCreated = true;

    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"12345.1923");
    state.status = CmRegisterCallbackEx(OnRegistryNotify, &altitude, DriverObject, nullptr, &data->RegCookie, nullptr);
    if (!NT_SUCCESS(state.status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR SysMon.sys: CmRegisterCallbackEx failed 0x%x\r\n", state.status));
        return state.status;
    }
    state.regNotifyCreated = true;

    return state.status;
}


void SysMonUnload(
    _DRIVER_OBJECT* DriverObject
)
{
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO  SysMon.sys: Unload\r\n"));
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;

    PAGED_CODE();
    auto data = (Globals*)deviceObject->DeviceExtension;

    IoAcquireRemoveLock(&data->RemoveLock, nullptr);

    PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
    PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);
    CmUnRegisterCallback(data->RegCookie);

    IoReleaseRemoveLockAndWait(&data->RemoveLock, nullptr);
    GlobalDeviceObject = nullptr;

    UNICODE_STRING  ntWin32NameString = RTL_CONSTANT_STRING(LINK_NAME);
 
    //
    // Delete the link from our device name to a name in the Win32 namespace.
    //
    IoDeleteSymbolicLink(&ntWin32NameString);

    // free all data items in the list
    PLIST_ENTRY entry;
    while ((entry = RemoveHeadList(&data->EventsHead)) != &data->EventsHead) {
        auto item = CONTAINING_RECORD(entry, EventData<EventHeader>, Entry);
        ExFreePool(item);
    }

    IoDeleteDevice(deviceObject);
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

void PushItem(LIST_ENTRY* entry, Globals* globaldata) {
    AutoLocker locker(globaldata->Lock);
    if (globaldata->EventsCount > 1024) {
        auto headEntry = RemoveHeadList(&globaldata->EventsHead);
        ExFreePool(CONTAINING_RECORD(headEntry, EventData<EventHeader>, Entry));
        globaldata->EventsCount--;
    }
    InsertTailList(&globaldata->EventsHead, entry);
    globaldata->EventsCount++;
}


void OnProcessNotify(PEPROCESS /* Process */, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    auto globaldata = (Globals*)GlobalDeviceObject->DeviceExtension;

    if (IoAcquireRemoveLock(&globaldata->RemoveLock, nullptr) == STATUS_DELETE_PENDING)
        return;

    __try {
        if (CreateInfo) {
            // process created
            USHORT size = sizeof EventData<ProcessCreateEvent>;
            USHORT dataSize = sizeof ProcessCreateEvent;
            USHORT commandLineSize = 0;
            if (CreateInfo->CommandLine) {
                commandLineSize = CreateInfo->CommandLine->Length;
                size += commandLineSize;
                dataSize += commandLineSize;
            }
            auto evt = (EventData<ProcessCreateEvent>*)ExAllocatePoolWithTag(PagedPool, size, DRIVER_TAG);
            if (!evt) {
                KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR SysMon.sys: Failed to allocate %d bytes\r\n", (int)size));
                return;
            }
            // fill common members
            auto& data = evt->Data;
            KeQuerySystemTimePrecise(&data.TimeStamp);
            data.Size = dataSize;
            data.Type = EventType::ProcessCreate;
            data.ProcessId = HandleToULong(ProcessId);
            data.ParentProcessId = HandleToUlong(CreateInfo->ParentProcessId);
            data.CommandLineLength = commandLineSize / sizeof(WCHAR);
            data.CommandLineOffset = sizeof(ProcessCreateEvent);
            if (commandLineSize > 0)
                memcpy((UCHAR*)&data + data.CommandLineOffset, CreateInfo->CommandLine->Buffer, commandLineSize);
            PushItem(&evt->Entry, globaldata);
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO SysMon.sys: Process created %u\r\n", HandleToUlong(ProcessId)));
        }
        else {
            // process exited
            USHORT size = sizeof EventData<ProcessExitEvent>;
            auto evt = (EventData<ProcessExitEvent>*)ExAllocatePoolWithTag(PagedPool, size, DRIVER_TAG);
            if (!evt) {
                KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR SysMon.sys: Failed to allocate %d bytes\r\n", (int)size));
                return;
            }
            // fill common members
            auto& data = evt->Data;
            KeQuerySystemTimePrecise(&data.TimeStamp);
            data.Size = sizeof(ProcessExitEvent);
            data.Type = EventType::ProcessExit;

            // fill extras
            data.ProcessId = HandleToUlong(ProcessId);
            PushItem(&evt->Entry, globaldata);
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO SysMon.sys: Process exitted %u\r\n", HandleToUlong(ProcessId)));
        }
    }
    __finally {
        IoReleaseRemoveLock(&globaldata->RemoveLock, nullptr);
    }
}

void OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
    auto globaldata = (Globals*)GlobalDeviceObject->DeviceExtension;

    if (IoAcquireRemoveLock(&globaldata->RemoveLock, nullptr) == STATUS_DELETE_PENDING)
        return;

    __try {
        const auto size = sizeof(EventData<ThreadCreateExitEvent>);
        auto evt = (EventData<ThreadCreateExitEvent>*)ExAllocatePoolWithTag(PagedPool,
            size, DRIVER_TAG);
        if (!evt) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR SysMon.sys: Failed to allocate %d bytes\r\n", (int)size));
            return;
        }

        auto& data = evt->Data;
        KeQuerySystemTimePrecise(&data.TimeStamp);
        data.Size = sizeof(ThreadCreateExitEvent);
        data.Type = Create ? EventType::ThreadCreate : EventType::ThreadExit;
        data.ProcessId = HandleToUlong(ProcessId);
        data.ThreadId = HandleToUlong(ThreadId);
        PushItem(&evt->Entry, globaldata);
    }
    __finally {
        IoReleaseRemoveLock(&globaldata->RemoveLock, nullptr);
    }
}
NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR information = 0) {
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
NTSTATUS SysMonRead(PDEVICE_OBJECT device, PIRP Irp) {
    auto stack = IoGetCurrentIrpStackLocation(Irp);
    auto len = stack->Parameters.Read.Length;
    ULONG size = 0;
    NT_ASSERT(Irp->MdlAddress);

    auto buffer = (UCHAR*)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
    if (buffer == nullptr)
        return CompleteIrp(Irp, STATUS_INSUFFICIENT_RESOURCES);

    auto status = STATUS_SUCCESS;

    {
        auto globaldata = (Globals*)device->DeviceExtension;
        AutoLocker locker(globaldata->Lock);
        while (globaldata->EventsCount > 0) {
            auto entry = RemoveHeadList(&globaldata->EventsHead);
            NT_ASSERT(entry != &globaldata->EventsHead);
            if (entry == &globaldata->EventsHead)
                break;

            auto item = CONTAINING_RECORD(entry, EventData<EventHeader>, Entry);
            auto itemSize = item->Data.Size;
            if (itemSize > len) {
                // remaining buffer size is too small
                InsertHeadList(&globaldata->EventsHead, entry);
                if (size == 0)
                {
                    //we have events - but buffer too small even for one event
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                break;
            }
            memcpy(buffer, &item->Data, itemSize);
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO SysMon.sys: Event data copied(size = %u)\r\n", (unsigned)itemSize));

            globaldata->EventsCount--;
            size += itemSize;
            buffer += itemSize;
            len -= itemSize;
            ExFreePool(item);
        }
    }

    return CompleteIrp(Irp, status, size);
}

NTSTATUS OnRegistryNotify(PVOID, PVOID arg1, PVOID arg2) {
    auto globaldata = (Globals*)GlobalDeviceObject->DeviceExtension;

    if (IoAcquireRemoveLock(&globaldata->RemoveLock, nullptr) == STATUS_DELETE_PENDING)
        return STATUS_SUCCESS;

    __try {
        switch ((REG_NOTIFY_CLASS)(ULONG_PTR)arg1) {
        case RegNtSetValueKey:
            auto info = (REG_SET_VALUE_KEY_INFORMATION*)arg2;
            auto valueSize = info->DataSize > 256 ? 256 : info->DataSize;
            auto totalSize = valueSize + sizeof EventData<RegistrySetValueEvent>;
            auto evt = (EventData<RegistrySetValueEvent>*)ExAllocatePoolWithTag(PagedPool, totalSize, DRIVER_TAG);
            if (!evt) {
                KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR SysMon.sys: Failed to allocate %d bytes\r\n", (int)totalSize));
                return STATUS_SUCCESS; // STATUS_INSUFFICIENT_RESOURCES; - do not want to prevent other drivers from handling the notification
            }

            RtlZeroMemory(evt, totalSize);
            auto& data = evt->Data;
            KeQuerySystemTimePrecise(&data.TimeStamp);
            data.ProcessId = HandleToUlong(PsGetCurrentProcessId());
            data.ThreadId = HandleToULong(PsGetCurrentThreadId());
            data.DataSize = info->DataSize;
            data.DataType = info->Type;
            data.Type = EventType::RegistrySetValue;
            data.Size = sizeof(RegistrySetValueEvent) + (USHORT)valueSize;
            data.BufferSize = valueSize;
            memcpy(data.ValueName, info->ValueName->Buffer, info->ValueName->Length);
            memcpy(evt + 1, info->Data, valueSize);
            PCUNICODE_STRING name;
            if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&globaldata->RegCookie, info->Object, nullptr, &name, 0))) {
                memcpy(data.KeyName, name->Buffer, name->Length);
                CmCallbackReleaseKeyObjectIDEx(name);
            }
            PushItem(&evt->Entry, globaldata);
            break;

        }
    }
    __finally {
        IoReleaseRemoveLock(&globaldata->RemoveLock, nullptr);
    }
    return STATUS_SUCCESS;
}
