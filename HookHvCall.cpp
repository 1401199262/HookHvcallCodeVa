#include "global.h"
#include "PhysicalMemory.h"
#include "HookHvCall.h"

#define HV_MMU_USE_HYPERCALL_FOR_ADDRESS_SWITCH 0x00001
#define HV_MMU_USE_HYPERCALL_FOR_LOCAL_FLUSH 0x00002
#define HV_MMU_USE_HYPERCALL_FOR_REMOTE_FLUSH 0x00004
#define HV_APIC_ENLIGHTENED 0x00010
#define HV_KE_USE_HYPERCALL_FOR_LONG_SPIN_WAIT 0x00040
#define HV_DEPRECATE_AUTO_EOI 0x01000

u32* HvlEnlightenments = 0;

using HvcallCodeVaFn = u64(*)(u64 CallType, u64 Param, u64);
HvcallCodeVaFn* pHvcallCodeVa = 0;

//u64 KeLoaderBlock = 0;
//using HvlpSetupBootProcessorEarlyHypercallPagesFn = NTSTATUS(*)(u64 LoaderBlock);
//HvlpSetupBootProcessorEarlyHypercallPagesFn HvlpSetupBootProcessorEarlyHypercallPages = 0;

using HvlpSetupCachedHypercallPagesFn = PSLIST_ENTRY(*)(PVOID Prcb);
HvlpSetupCachedHypercallPagesFn HvlpSetupCachedHypercallPages = 0;

u64 SwitchCnt = 0;
u64 HvCallback(u64 CallType, u64 Param, u64)
{	
	if (CallType == 0x10001i64) {
		
		if ((SwitchCnt++ % 0x10000) == 0)
			DbgPrintEx(0, 0, "[%p] Cr3 %p->%p, Cnt=%p\n", GetCurrentPid(), __readcr3(), Param, SwitchCnt);

		__writecr3(Param);
	}

	return 0x1000;
}

u32 HypercallCachedPagesOffset = 0;
NTSTATUS HvlpSetupBootProcessorEarlyHypercallPages()
{
	if (!HypercallCachedPagesOffset)
	{
		auto rva = FindPatternSect(EPtr(::NtBase), E(".text"), E("65 48 8B 04 25 20 00 00 00 40 F6 C5 01 ? ? 48 8B"));
		if (rva)
		{
			HypercallCachedPagesOffset = *(u32*)(rva + 18);
			DbgPrintEx(0, 0, "Prcb.HypercallCachedPages Offset=0x%x\n", HypercallCachedPagesOffset);
		}
	}


	PVOID CurrentPrcb; // rbx
	u64 AllocMem; // rax
	u64* PageAddr; // rcx
	u64 CurrentPhysical; // rax
	u64 LoopCount; // rdx
	u64 AllocPhysical; // [rsp+48h] [rbp+10h] BYREF

	AllocPhysical = 0i64;
	CurrentPrcb = KeGetCurrentPrcb();
	PHYSICAL_ADDRESS a; a.QuadPart = MAXULONG64;
	AllocMem = (u64)MmAllocateContiguousMemory(0x6000, a); // physical addr must be contigious
	if (!AllocMem)
		return 0xC000009Ai64;

	memset((pv)AllocMem, 0, 0x6000);

	AllocPhysical = MiGetPteAddress(AllocMem)->PageFrameNumber * 0x1000;
	*(pv*)((u64)CurrentPrcb + HypercallCachedPagesOffset) = (void*)AllocMem;

	PageAddr = (u64*)(AllocMem + 0x10);
	CurrentPhysical = AllocPhysical;
	LoopCount = 2i64;
	do
	{
		*PageAddr = CurrentPhysical;
		PageAddr += 0x200;
		CurrentPhysical = AllocPhysical + 0x1000;
		AllocPhysical += 0x1000i64;
		--LoopCount;
	} while (LoopCount);
	return 0i64;
}


void HookHvCall()
{
	if(IsKernelDebuggerPresent())
		__db();

	if (!HvlEnlightenments || !pHvcallCodeVa)
	{
		auto rva = FindPatternSect(EPtr(::NtBase), E(".text"), E("F7 05 ? ? ? ? 01 00 00 00 74 07 E8 ? ? ? ? EB ? 0F 22 D9"));
		if (!rva)
			__db();

		HvlEnlightenments = (u32*)(RVA(rva, 6) + 4);

		rva = FindPatternSect(EPtr(::NtBase), E(".text"), E("B9 87 00 00 00 C7 00 03 00 00 00 48 8B 05"));
		if (rva)
			pHvcallCodeVa = (HvcallCodeVaFn*)RVA(rva + 11, 7);
		else
		{
			rva = FindPatternSect(EPtr(::NtBase), E(".text"), E("4C 8B 42 08 48 8B 12 48 8B 05"));
			if (!rva)
				__db();
			pHvcallCodeVa = (HvcallCodeVaFn*)RVA(rva + 7, 7);
		}
				
		//rva = FindPatternSect(EPtr(::NtBase), E("PAGE"), E("E9 ? ? ? ? 48 8B CB E8 ? ? ? ? 85 C0 0F 88 ? ? ? ? C6 05"));
		//if (!rva)
		//	__db();
		//HvlpSetupBootProcessorEarlyHypercallPages = (HvlpSetupBootProcessorEarlyHypercallPagesFn)RVA(rva + 8, 5);

		rva = FindPatternSect(EPtr(::NtBase), E("PAGE"), E("49 83 EE 01 75 ? 48 8B CB E8 ? ? ? ? 90 E9"));
		if (!rva)
			__db();
		HvlpSetupCachedHypercallPages = (HvlpSetupCachedHypercallPagesFn)RVA(rva + 9, 5);

		ForEachProcessor([](PVOID) -> NTSTATUS
			{
				HvlpSetupBootProcessorEarlyHypercallPages();
				HvlpSetupCachedHypercallPages(KeGetCurrentPrcb());
				return 0;
			}
		, 0);

	}

	*pHvcallCodeVa = HvCallback;
	*HvlEnlightenments = (*HvlEnlightenments | HV_MMU_USE_HYPERCALL_FOR_ADDRESS_SWITCH);
}


