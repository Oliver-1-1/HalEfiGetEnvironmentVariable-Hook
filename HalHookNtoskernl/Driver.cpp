#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>
#include "structs.h"
extern "C" NTSTATUS ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);

//This will trigger patch-guard D:

namespace util {
    PVOID GetModuleBase(LPCSTR moduleName) {
        PVOID moduleBase = NULL;
        ULONG info = 0;
        NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, info, &info);

        if (!info) {
            return moduleBase;
        }

        PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, info, 'HEIL');
        status = ZwQuerySystemInformation(SystemModuleInformation, modules, info, &info);
        if (!NT_SUCCESS(status)) {
            return moduleBase;
        }
        PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
        if (modules->NumberOfModules > 0) {
            if (!moduleName) {
                moduleBase = modules->Modules[0].ImageBase;
            }
            else {
                for (auto i = 0; i < modules->NumberOfModules; i++) {
                    if (!strcmp((CHAR*)module[i].FullPathName, moduleName)) {
                        moduleBase = module[i].ImageBase;
                    }
                }
            }
        }

        if (modules) {
            ExFreePoolWithTag(modules, 'HELL');
        }

        return moduleBase;
    }
    PIMAGE_NT_HEADERS GetHeader(PVOID module) {
        return (PIMAGE_NT_HEADERS)((PBYTE)module + PIMAGE_DOS_HEADER(module)->e_lfanew);
    }

    PBYTE FindPattern(PVOID module, DWORD size, LPCSTR pattern, LPCSTR mask) {
        auto checkMask = [](PBYTE buffer, LPCSTR pattern, LPCSTR mask) -> BOOL
        {
            for (auto x = buffer; *mask; pattern++, mask++, x++) {
                auto addr = *(BYTE*)(pattern);
                if (addr != *x && *mask != '?')
                    return FALSE;
            }

            return TRUE;
        };

        for (auto x = 0; x < size - strlen(mask); x++) {

            auto addr = (PBYTE)module + x;
            if (checkMask(addr, pattern, mask))
                return addr;
        }

        return NULL;
    }

    PBYTE FindPattern(PVOID base, LPCSTR pattern, LPCSTR mask) {
        auto header = GetHeader(base);
        auto section = IMAGE_FIRST_SECTION(header);
        for (auto x = 0; x < header->FileHeader.NumberOfSections; x++, section++) {
            if (!memcmp(section->Name, ".text", 5) || !memcmp(section->Name, "PAGE", 4)) {
                auto addr = FindPattern((PBYTE)base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
                if (addr) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Found in Section -> [ %s ]", section->Name);
                    return addr;
                }
            }
        }

        return NULL;
    }
}
PVOID org_func = 0; 
__int64 NTAPI HalEfiGetEnvironmentVariableHook(__int64 v) { //retrived from IDA
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Function called\n");
    HalEfiGetEnvironmentVariable* f = (HalEfiGetEnvironmentVariable*)org_func;
    return f(v);
}

bool WriteToReadOnlyMemory(void* address, void* buffer, size_t size) {
    PMDL mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);
    if (!mdl)
        return false;

    MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    PVOID mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);

    memcpy(mapping, buffer, size);
    MmUnmapLockedPages(mapping, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);

    return true;
}
bool HookFunction(PVOID function, PVOID outfunction){
    unsigned char shell_code[] = { 0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xff, 0xe3, 0xb8,  0x01,  0x00,  0x00, 0xc0, 0xc3};
    auto hook_address = reinterpret_cast<uintptr_t>(outfunction);
    //place the hook address in the shellcode  64 bit. so replace 8 bytes.
    memcpy(shell_code + 2, &hook_address, sizeof(hook_address));
    return WriteToReadOnlyMemory(function, &shell_code, sizeof(shell_code));
}

VOID DriverUnload(struct _DRIVER_OBJECT* DriverObject){
    //InterlockedExchangePointer((PVOID*)gFunc, (PVOID)org_func);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Out!\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT  DriverObject, PUNICODE_STRING RegistryPath){
    DriverObject->DriverUnload = DriverUnload;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Entry!\n");
    auto base =  util::GetModuleBase(0);

    if (!base) {
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] ntoskrnl.exe -> 0x%x\n", base);

    auto addr = util::FindPattern(base,"\x40\x53\x48\x83\xEC\x30\x48\x8B\x05\x00\x00\x00\x00\x4D", "xxxxxxxxx????x");// HalEfiGetEnvironmentVariable pattern
    org_func = addr;

    if (!addr) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Unable to find signature!2\n");
        return STATUS_FAILED_DRIVER_ENTRY;
    }
    
    if (!HookFunction(addr, &HalEfiGetEnvironmentVariableHook)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] Not hoooked!2\n");
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    return STATUS_SUCCESS;
    
}
