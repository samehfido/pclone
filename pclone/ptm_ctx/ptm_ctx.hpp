#pragma once
#include "../util/nt.hpp"
#include "../vdm_ctx/vdm_ctx.hpp"

namespace ptm
{
	class ptm_ctx
	{
	public:
		explicit ptm_ctx(vdm::vdm_ctx* v_ctx, std::uint32_t pid = GetCurrentProcessId());
		~ptm_ctx();

		auto get_pte(void* addr, bool use_hyperspace = false) -> std::pair<ppte, pte>;
		bool set_pte(void* addr, const ::pte& pte, bool use_hyperspace = false);

		auto get_pde(void* addr, bool use_hyperspace = false) -> std::pair<ppde, pde>;
		bool set_pde(void* addr, const ::pde& pde, bool use_hyperspace = false);

		auto get_pdpte(void* addr, bool use_hyperspace = false) -> std::pair<ppdpte, pdpte>;
		bool set_pdpte(void* addr, const ::pdpte& pdpte, bool use_hyperspace = false);

		auto get_pml4e(void* addr, bool use_hyperspace = false) -> std::pair<ppml4e, pml4e>;
		bool set_pml4e(void* addr, const ::pml4e& pml4e, bool use_hyperspace = false);
		static void* get_dirbase(vdm::vdm_ctx& v_ctx, DWORD pid);

		bool read_phys(void* buffer, void* addr, std::size_t size);
		bool write_phys(void* buffer, void* addr, std::size_t size);

		template <class T>
		__forceinline T read_phys(void* addr)
		{
			T buffer;
			read_phys((void*)&buffer, addr, sizeof(T));
			return buffer;
		}

		template <class T>
		__forceinline bool write_phys(void* addr, const T& data)
		{
			return write_phys((void*)&data, addr, sizeof(T));
		}

		auto read_virtual(void* buffer, void* addr, std::size_t size) -> std::pair<void*, void*>;
		auto write_virtual(void* buffer, void* addr, std::size_t size) -> std::pair<void*, void*>;

		template <class T>
		__forceinline T read_virtual(void* addr)
		{
			T buffer;
			read_virtual((void*)&buffer, addr, sizeof(T));
			return buffer;
		}

		template <class T>
		__forceinline void write_virtual(void* addr, const T& data)
		{
			write_virtual((void*)&data, addr, sizeof(T));
		}

		void* virt_to_phys(pt_entries& entries, void* addr);
		bool hyperspace_entries(pt_entries& entries, void* addr);

		void* set_page(void* addr);
		void* get_page() const;

		unsigned pid;
		void* dirbase;
		vdm::vdm_ctx* v_ctx;
	private:
		std::uint16_t pml4e_index, 
			pdpte_index,
			pde_index, 
			pte_index,
			page_offset;

		std::pair<ppdpte, ppdpte> new_pdpt;
		std::pair<ppde,ppde>      new_pd;
		std::pair<ppte, ppte>     new_pt;
	};
}