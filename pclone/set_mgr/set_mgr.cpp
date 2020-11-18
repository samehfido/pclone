#include "set_mgr.hpp"

namespace set_mgr
{
	auto get_setmgr_pethread(vdm::vdm_ctx& v_ctx)->PETHREAD
	{
		ULONG return_len = 0u;
		std::size_t alloc_size = 0x1000u;
		auto process_info = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(malloc(alloc_size));

		while (NtQuerySystemInformation
		(
			SystemProcessInformation,
			process_info,
			alloc_size,
			&return_len
		) == STATUS_INFO_LENGTH_MISMATCH)
			process_info = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(
				realloc(process_info, alloc_size += 0x1000));

		const auto og_ptr = process_info;
		while (process_info && process_info->UniqueProcessId != (HANDLE)4)
			process_info = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(
				reinterpret_cast<std::uintptr_t>(process_info) + process_info->NextEntryOffset);

		auto thread_info = reinterpret_cast<SYSTEM_THREAD_INFORMATION*>(
			reinterpret_cast<std::uintptr_t>(process_info) + sizeof SYSTEM_PROCESS_INFORMATION);

		static const auto ntoskrnl_base =
			util::get_kmodule_base("ntoskrnl.exe");

		const auto [ke_balance_um, ke_balance_rva] =
			util::memory::sig_scan(
				KE_BALANCE_SIG, KE_BALANCE_MASK);

		auto rip_rva = *reinterpret_cast<std::uint32_t*>(ke_balance_um + 19);
		const auto ke_balance_set = ntoskrnl_base + ke_balance_rva + 23 + rip_rva;

		const auto [suspend_in_um, suspend_rva] =
			util::memory::sig_scan(SUSPEND_THREAD_SIG, SUSPEND_THREAD_MASK);

		rip_rva = *reinterpret_cast<std::uint32_t*>(suspend_in_um + 1);
		const auto ps_suspend_thread = reinterpret_cast<void*>(ntoskrnl_base + rip_rva + 5 + suspend_rva);

		static const auto lookup_pethread =
			util::get_kmodule_export("ntoskrnl.exe", "PsLookupThreadByThreadId");

		for (auto idx = 0u; idx < process_info->NumberOfThreads; ++idx)
		{
			if (thread_info[idx].StartAddress == reinterpret_cast<void*>(ke_balance_set))
			{
				PETHREAD pethread;
				auto result = v_ctx.syscall<PsLookupThreadByThreadId>(
					lookup_pethread, thread_info[idx].ClientId.UniqueThread, &pethread);

				free(og_ptr);
				return pethread;
			}
		}

		free(og_ptr);
		return {};
	}

	auto stop_setmgr(vdm::vdm_ctx& v_ctx, PETHREAD pethread) -> NTSTATUS
	{
		static const auto ntoskrnl_base =
			util::get_kmodule_base("ntoskrnl.exe");

		const auto [suspend_in_um, suspend_rva] =
			util::memory::sig_scan(SUSPEND_THREAD_SIG, SUSPEND_THREAD_MASK);

		const auto rip_rva = *reinterpret_cast<std::uint32_t*>(suspend_in_um + 1);
		const auto ps_suspend_thread = reinterpret_cast<void*>(ntoskrnl_base + rip_rva + 5 + suspend_rva);
		return v_ctx.syscall<PsSuspendThread>(ps_suspend_thread, pethread, nullptr);
	}
}