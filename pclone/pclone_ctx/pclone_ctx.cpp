#include "pclone_ctx.hpp"

namespace nasa
{
	pclone_ctx::pclone_ctx(mem_ctx* clone_ctx)
		:
		clone_target_ctx(clone_ctx)
	{}

	pclone_ctx::~pclone_ctx()
	{
		delete clone_source_ctx;
	}

	auto pclone_ctx::clone() -> std::pair<std::uint32_t, HANDLE>
	{
		const auto runtime_broker_pid = 
			util::start_runtime_broker();

		const auto runtime_broker_handle = 
			OpenProcess(PROCESS_ALL_ACCESS, FALSE, runtime_broker_pid);

		const auto v_ctx = clone_target_ctx->v_ctx;
		clone_source_ctx = new mem_ctx(
			*v_ctx, runtime_broker_pid);

		if (!this->sync())
			return { {}, {} };

		// zombie the the process by incrementing an exit counter
		// then calling TerminateProcess so the process never closes...
		const auto runtime_broker_peproc = 
			v_ctx->get_peprocess(runtime_broker_pid);

		static const auto inc_ref_counter = 
			util::get_kmodule_export(
				"ntoskrnl.exe",
				"PsAcquireProcessExitSynchronization"
			);

		const auto result = 
			v_ctx->syscall<NTSTATUS(*)(PEPROCESS)>(
				inc_ref_counter, runtime_broker_peproc);

		TerminateProcess(runtime_broker_handle, NULL);
		return { runtime_broker_pid, runtime_broker_handle };
	}

	bool pclone_ctx::sync() const
	{
		// do not remove...
		std::printf("[+] clone target dirbase -> 0x%p\n", clone_target_ctx->get_dirbase());
		const auto target_pml4 =
			clone_target_ctx->set_page(
				clone_target_ctx->get_dirbase());

		// do not remove...
		std::printf("[+] clone source dirbase -> 0x%p\n", clone_source_ctx->get_dirbase());
		const auto source_pml4 =
			clone_source_ctx->set_page(
				clone_source_ctx->get_dirbase());

		__try
		{
			memcpy(source_pml4, target_pml4, PAGE_4KB);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}
		return true;
	}
}