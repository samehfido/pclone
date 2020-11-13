#include "pclone_ctx.hpp"

namespace nasa
{
	pclone_ctx::pclone_ctx(mem_ctx* clone_ctx)
		:
		clone_target_ctx(clone_ctx)
	{}

	auto pclone_ctx::clone() -> std::pair<std::uint32_t, HANDLE>
	{
		const auto runtime_broker_pid =
			util::start_runtime_broker();

		const auto runtime_broker_handle =
			OpenProcess(PROCESS_ALL_ACCESS, FALSE, runtime_broker_pid);

		const auto v_ctx = clone_target_ctx->v_ctx;
		// zombie the the process by incrementing an exit counter
		// then calling TerminateProcess so the process never closes...
		const auto runtime_broker_peproc =
			reinterpret_cast<std::uintptr_t>(
				v_ctx->get_peprocess(runtime_broker_pid));

		static const auto inc_ref_counter =
			util::get_kmodule_export(
				"ntoskrnl.exe",
				"PsAcquireProcessExitSynchronization"
			);

		const auto result =
			v_ctx->syscall<NTSTATUS(*)(std::uintptr_t)>(
				inc_ref_counter, runtime_broker_peproc);

		if (result != STATUS_SUCCESS)
			return { {}, {} };

		if (!TerminateProcess(runtime_broker_handle, NULL))
			return { {}, {} };

		// change the _KPROCESS.DirectoryTableBase to the
		// DirectoryTableBase of the process wanting to be 
		// cloned...
		const auto clone_target_peproc =
			reinterpret_cast<std::uintptr_t>(
				v_ctx->get_peprocess(clone_target_ctx->get_pid()));

		const auto clone_target_dirbase = 
			v_ctx->rkm<pte>(clone_target_peproc + 0x28);

		// change dirbase of runtime broker to the dirbase of the desired process...
		v_ctx->wkm<pte>(runtime_broker_peproc + 0x28, clone_target_dirbase);

		// get the peb offset inside dirbase...
		// .text:00000001403387B0                         public PsGetProcessPeb
		// .text:00000001403387B0                         PsGetProcessPeb proc near; 
		// .text:00000001403387B0 48 8B 81 50 05 00 00    mov     rax, [rcx + 550h] <==== + 3 bytes here...
		// .text:00000001403387B7 C3                      retn
		// .text:00000001403387B7                         PsGetProcessPeb endp
		const auto eprocess_peb_offset = 
			*reinterpret_cast<std::uint32_t*>(
				reinterpret_cast<std::uintptr_t>(
					GetProcAddress(GetModuleHandleA(
						"ntoskrnl.exe"), "PsGetProcessPeb")) + 0x3); // <==== + 3 bytes here...

		const auto clone_target_peb = 
			v_ctx->rkm<std::uintptr_t>(
				clone_target_peproc + eprocess_peb_offset);

		v_ctx->wkm<std::uintptr_t>(runtime_broker_peproc + eprocess_peb_offset, clone_target_peb);
		return { runtime_broker_pid, runtime_broker_handle };
	}
}