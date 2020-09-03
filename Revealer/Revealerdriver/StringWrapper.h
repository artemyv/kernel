#pragma once

#include <ntstrsafe.h>
#include <wdm.h>
#define POOLTAG_VART 'vart'

#define RUN_TEST_NTSTATUS(x) \
{ auto res = x; if (!NT_SUCCESS(res)) {\
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ERROR VartDriver.sys: Call failed 0x%x: " #x "\r\n", res)); \
    return res;}}

class PoolGuard
{
public:
    explicit PoolGuard(PVOID p) :m_p(p) {}
    ~PoolGuard() {
        ExFreePoolWithTag(m_p, POOLTAG_VART);
    }
private:
    PoolGuard() = delete;
    PoolGuard(const PoolGuard&) = delete;
    PoolGuard(PoolGuard&&) = delete;
    PoolGuard& operator=(const PoolGuard&) = delete;
    PoolGuard& operator=(PoolGuard&&) = delete;
    PVOID m_p;
};
class StringWrapper
{
public:
    StringWrapper() = default;
    StringWrapper(const StringWrapper&) = delete;
    StringWrapper(StringWrapper&&) = delete;
    StringWrapper& operator=(const StringWrapper&) = delete;
    StringWrapper& operator=(StringWrapper&&) = delete;
    ~StringWrapper() {
        if(ptr)
            ExFreePoolWithTag(ptr, POOLTAG_VART);
    }

    template <typename... ARGS>
    NTSTATUS Format(NTSTRSAFE_PWSTR fmt ,ARGS... args)
    {
        size_t len = 1024 * sizeof(WCHAR);
        ptr = (NTSTRSAFE_PWSTR)ExAllocatePoolWithTag(PagedPool,
            len,
            POOLTAG_VART);
        if (!ptr)
        {
            KdPrintEx((DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL,"ERROR VartDriver.sys: failed to allocate temp buffer\r\n"));
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        size_t rest;
        RUN_TEST_NTSTATUS(RtlStringCchPrintfExW(ptr, len,&end,&rest,0, fmt, args...));
        return STATUS_SUCCESS;
    }
    NTSTRSAFE_PWSTR str() {
        return NTSTRSAFE_PWSTR(ptr);
    }
    size_t getChars() {
        if (ptr && end)
        {
            size_t len = end - ptr;
            if (len < 1024)
                return len;
        }
        return 0;
    }
    size_t getBytes()
    {
        size_t len = getChars();
        if (len > 0)
        {
            return len * sizeof(WCHAR) + 2;
        }
        return 0;
    }
private:
    NTSTRSAFE_PWSTR ptr = nullptr;
    NTSTRSAFE_PWSTR end = nullptr;
};