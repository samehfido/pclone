#include "ptm_ctx.hpp"

namespace ptm
{
	ptm_ctx::ptm_ctx(vdm::vdm_ctx* v_ctx, std::uint32_t pid)
		:
		v_ctx(v_ctx),
		dirbase(get_dirbase(*v_ctx, pid)),
		pid(pid)
	{
		// find an empty pml4e inside of current processes pml4...
		const auto current_pml4 =
			v_ctx->get_virtual(reinterpret_cast<std::uintptr_t>(
				get_dirbase(*v_ctx, GetCurrentProcessId())));

		for (auto idx = 100u; idx > 0u; --idx)
		{
			if (!v_ctx->rkm<pml4e>(current_pml4 + (idx * sizeof pml4e)).present)
			{
				this->pml4e_index = idx;
				break;
			}
		}

		// allocate a pdpt
		this->new_pdpt.second =
			reinterpret_cast<ppdpte>(
				VirtualAlloc(
					NULL,
					PAGE_4KB,
					MEM_COMMIT | MEM_RESERVE,
					PAGE_READWRITE
				));

		PAGE_IN(this->new_pdpt.second, PAGE_4KB);
		// get page table entries for new pdpt
		pt_entries new_pdpt_entries;
		hyperspace_entries(new_pdpt_entries, new_pdpt.second);

		this->new_pdpt.first = 
			reinterpret_cast<ppdpte>(
				new_pdpt_entries.pt.second.pfn << 12);

		// make a new pml4e that points to our new pdpt.
		new_pdpt_entries.pml4.second.pfn = new_pdpt_entries.pt.second.pfn;

		// set the pml4e to point to the new pdpt
		set_pml4e(reinterpret_cast<::ppml4e>(this->dirbase) +
			this->pml4e_index, new_pdpt_entries.pml4.second, true);

		// make a new pd
		this->new_pd.second =
			reinterpret_cast<ppde>(
				VirtualAlloc(
					NULL,
					PAGE_4KB,
					MEM_COMMIT | MEM_RESERVE,
					PAGE_READWRITE
				));

		PAGE_IN(this->new_pd.second, PAGE_4KB);

		// get paging table entries for pd
		pt_entries new_pd_entries;
		hyperspace_entries(new_pd_entries, this->new_pd.second);

		this->new_pd.first = 
			reinterpret_cast<ppde>(
				new_pd_entries.pt.second.pfn << 12);

		// make a new pt
		this->new_pt.second =
			reinterpret_cast<ppte>(
				VirtualAlloc(
					NULL,
					PAGE_4KB,
					MEM_COMMIT | MEM_RESERVE,
					PAGE_READWRITE
				));

		PAGE_IN(this->new_pt.second, PAGE_4KB);

		// get paging table entries for pt
		pt_entries new_pt_entries;
		hyperspace_entries(new_pt_entries, this->new_pt.second);

		this->new_pt.first = 
			reinterpret_cast<ppte>(
				new_pt_entries.pt.second.pfn << 12);
	}

	ptm_ctx::~ptm_ctx()
	{
		const auto pml4 = 
			reinterpret_cast<ppml4e>(
				set_page(dirbase))[pml4e_index] = pml4e{ NULL };
	}

	void* ptm_ctx::set_page(void* addr)
	{
		++pte_index;
		if (pte_index > 511)
		{
			++pde_index;
			pte_index = 0;
		}

		if (pde_index > 511)
		{
			++pdpte_index;
			pde_index = 0;
		}

		if (pdpte_index > 511)
			pdpte_index = 0;

		pdpte new_pdpte = { NULL };
		new_pdpte.present = true;
		new_pdpte.rw = true;
		new_pdpte.pfn = reinterpret_cast<std::uintptr_t>(new_pd.first) >> 12;
		new_pdpte.user_supervisor = true;

		// set pdpte entry
		*reinterpret_cast<pdpte*>(new_pdpt.second + pdpte_index) = new_pdpte;

		pde new_pde = { NULL };
		new_pde.present = true;
		new_pde.rw = true;
		new_pde.pfn = reinterpret_cast<std::uintptr_t>(new_pt.first) >> 12;
		new_pde.user_supervisor = true;

		// set pde entry
		*reinterpret_cast<pde*>(new_pd.second + pde_index) = new_pde;

		pte new_pte = { NULL };
		new_pte.present = true;
		new_pte.rw = true;
		new_pte.pfn = reinterpret_cast<std::uintptr_t>(addr) >> 12;
		new_pte.user_supervisor = true;

		// set pte entry
		*reinterpret_cast<pte*>(new_pt.second + pte_index) = new_pte;

		// set page offset
		this->page_offset = virt_addr_t{ addr }.offset;
		return get_page();
	}

	void* ptm_ctx::get_page() const
	{
		// builds a new address given the state of all table indexes
		virt_addr_t new_addr;
		new_addr.pml4_index = this->pml4e_index;
		new_addr.pdpt_index = this->pdpte_index;
		new_addr.pd_index = this->pde_index;
		new_addr.pt_index = this->pte_index;
		new_addr.offset = this->page_offset;

		// handle TLB issues, the TLB might need to be flushed for this entry...
		__try
		{
			*(std::uint8_t*)new_addr.value = *(std::uint8_t*)new_addr.value;
			return new_addr.value;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			// try again to access the page...
			__try
			{
				*(std::uint8_t*)new_addr.value = *(std::uint8_t*)new_addr.value;
				return new_addr.value;
			}
			// try one last time by yeilding execution...
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				while (!SwitchToThread())
					continue;
			}
		}
		return new_addr.value;
	}

	void* ptm_ctx::get_dirbase(vdm::vdm_ctx& v_ctx, DWORD pid)
	{
		const auto peproc =
			reinterpret_cast<std::uint64_t>(
				v_ctx.get_peprocess(pid));

		return reinterpret_cast<void*>(
			v_ctx.rkm<pte>(peproc + 0x28).pfn << 12);
	}

	bool ptm_ctx::hyperspace_entries(pt_entries& entries, void* addr)
	{
		if (!addr || !dirbase)
			return false;

		virt_addr_t virt_addr{ addr };
		entries.pml4.first = reinterpret_cast<ppml4e>(dirbase) + virt_addr.pml4_index;
		entries.pml4.second = v_ctx->rkm<pml4e>(
			v_ctx->get_virtual(reinterpret_cast<std::uintptr_t>(entries.pml4.first)));

		if (!entries.pml4.second.value)
			return false;

		entries.pdpt.first = reinterpret_cast<ppdpte>(entries.pml4.second.pfn << 12) + virt_addr.pdpt_index;
		entries.pdpt.second = v_ctx->rkm<pdpte>(
			v_ctx->get_virtual(reinterpret_cast<std::uintptr_t>(entries.pdpt.first)));

		if (!entries.pdpt.second.value)
			return false;

		entries.pd.first = reinterpret_cast<ppde>(entries.pdpt.second.pfn << 12) + virt_addr.pd_index;
		entries.pd.second = v_ctx->rkm<pde>(
			v_ctx->get_virtual(reinterpret_cast<std::uintptr_t>(entries.pd.first)));

		// if its a 2mb page
		if (entries.pd.second.large_page)
		{
			entries.pt.second.value = entries.pd.second.value;
			entries.pt.first = reinterpret_cast<ppte>(entries.pd.second.value);
			return true;
		}

		entries.pt.first = reinterpret_cast<ppte>(entries.pd.second.pfn << 12) + virt_addr.pt_index;
		entries.pt.second = v_ctx->rkm<pte>(
			v_ctx->get_virtual(reinterpret_cast<std::uintptr_t>(entries.pt.first)));

		if (!entries.pt.second.value)
			return false;

		return true;
	}

	auto ptm_ctx::get_pte(void* addr, bool use_hyperspace) -> std::pair<ppte, pte>
	{
		if (!dirbase || !addr)
			return { {}, {} };

		pt_entries entries;
		if ((use_hyperspace ? hyperspace_entries(entries, addr) : (bool)virt_to_phys(entries, addr)))
			return { entries.pt.first, entries.pt.second };

		return { {}, {} };
	}

	bool ptm_ctx::set_pte(void* addr, const ::pte& pte, bool use_hyperspace)
	{
		if (!dirbase || !addr)
			return false;

		if (use_hyperspace)
			return v_ctx->wkm(
				v_ctx->get_virtual(
					reinterpret_cast<std::uintptr_t>(addr)), pte);

		return write_phys(addr, pte);
	}

	auto ptm_ctx::get_pde(void* addr, bool use_hyperspace) -> std::pair<ppde, pde>
	{
		if (!dirbase || !addr)
			return { {}, {} };

		pt_entries entries;
		if ((use_hyperspace ? hyperspace_entries(entries, addr) : (bool)virt_to_phys(entries, addr)))
			return { entries.pd.first, entries.pd.second };
		return { {}, {} };
	}

	bool ptm_ctx::set_pde(void* addr, const ::pde& pde, bool use_hyperspace)
	{
		if (!dirbase || !addr)
			return false;

		if (use_hyperspace)
			return v_ctx->wkm(
				v_ctx->get_virtual(
					reinterpret_cast<std::uintptr_t>(addr)), pde);

		return write_phys(addr, pde);
	}

	auto ptm_ctx::get_pdpte(void* addr, bool use_hyperspace) -> std::pair<ppdpte, pdpte>
	{
		if (!dirbase || !addr)
			return { {}, {} };

		pt_entries entries;
		if ((use_hyperspace ? hyperspace_entries(entries, addr) : (bool)virt_to_phys(entries, addr)))
			return { entries.pdpt.first, entries.pdpt.second };

		return { {}, {} };
	}

	bool ptm_ctx::set_pdpte(void* addr, const ::pdpte& pdpte, bool use_hyperspace)
	{
		if (!dirbase || !addr)
			return false;

		if (use_hyperspace)
			return v_ctx->wkm(
				v_ctx->get_virtual(
					reinterpret_cast<std::uintptr_t>(addr)), pdpte);

		return write_phys(addr, pdpte);
	}

	auto ptm_ctx::get_pml4e(void* addr, bool use_hyperspace) -> std::pair<ppml4e, pml4e>
	{
		if (!dirbase || !addr)
			return { {}, {} };

		pt_entries entries;
		if ((use_hyperspace ? hyperspace_entries(entries, addr) : (bool)virt_to_phys(entries, addr)))
			return { entries.pml4.first, entries.pml4.second };

		return { {}, {} };
	}

	bool ptm_ctx::set_pml4e(void* addr, const ::pml4e& pml4e, bool use_hyperspace)
	{
		if (!dirbase || !addr)
			return false;

		if (use_hyperspace)
			return v_ctx->wkm(
				v_ctx->get_virtual(
					reinterpret_cast<std::uintptr_t>(addr)), pml4e);

		return write_phys(addr, pml4e);
	}

	auto ptm_ctx::read_virtual(void* buffer, void* addr, std::size_t size) -> std::pair<void*, void*>
	{
		if (!buffer || !addr || !size || !dirbase)
			return {};

		virt_addr_t virt_addr{ addr };
		if (size <= PAGE_4KB - virt_addr.offset)
		{
			pt_entries entries;
			read_phys
			(
				buffer,
				virt_to_phys(entries, addr),
				size
			);

			return 
			{
				reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(buffer) + size),
				reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(addr) + size)
			};
		}
		else
		{
			// cut remainder
			const auto [new_buffer_addr, new_addr] = read_virtual
			(
				buffer,
				addr,
				PAGE_4KB - virt_addr.offset
			);

			// forward work load
			return read_virtual
			(
				new_buffer_addr,
				new_addr,
				size - (PAGE_4KB - virt_addr.offset)
			);
		}
	}

	auto ptm_ctx::write_virtual(void* buffer, void* addr, std::size_t size) -> std::pair<void*, void*>
	{
		if (!buffer || !addr || !size || !dirbase)
			return {};

		virt_addr_t virt_addr{ addr };
		if (size <= PAGE_4KB - virt_addr.offset)
		{
			pt_entries entries;
			write_phys
			(
				buffer,
				virt_to_phys(entries, addr),
				size
			);

			return 
			{
				reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(buffer) + size),
				reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(addr) + size)
			};
		}
		else
		{
			// cut remainder
			const auto [new_buffer_addr, new_addr] = write_virtual
			(
				buffer,
				addr,
				PAGE_4KB - virt_addr.offset
			);

			// forward work load
			return write_virtual
			(
				new_buffer_addr,
				new_addr,
				size - (PAGE_4KB - virt_addr.offset)
			);
		}
	}

	bool ptm_ctx::read_phys(void* buffer, void* addr, std::size_t size)
	{
		if (!buffer || !addr || !size)
			return false;

		const auto temp_page = set_page(addr);
		__try
		{
			memcpy(buffer, temp_page, size);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}
		return true;
	}

	bool ptm_ctx::write_phys(void* buffer, void* addr, std::size_t size)
	{
		if (!buffer || !addr || !size)
			return false;

		const auto temp_page = set_page(addr);
		__try
		{
			memcpy(temp_page, buffer, size);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}
		return true;
	}

	void* ptm_ctx::virt_to_phys(pt_entries& entries, void* addr)
	{
		if (!addr || !dirbase)
			return {};

		const virt_addr_t virt_addr{ addr };

		// traverse paging tables
		auto pml4e = read_phys<::pml4e>(
			reinterpret_cast<ppml4e>(this->dirbase) + virt_addr.pml4_index);

		entries.pml4.first = reinterpret_cast<ppml4e>(this->dirbase) + virt_addr.pml4_index;
		entries.pml4.second = pml4e;

		if (!pml4e.value)
			return NULL;

		auto pdpte = read_phys<::pdpte>(
			reinterpret_cast<ppdpte>(pml4e.pfn << 12) + virt_addr.pdpt_index);

		entries.pdpt.first = reinterpret_cast<ppdpte>(pml4e.pfn << 12) + virt_addr.pdpt_index;
		entries.pdpt.second = pdpte;

		if (!pdpte.value)
			return NULL;

		auto pde = read_phys<::pde>(
			reinterpret_cast<ppde>(pdpte.pfn << 12) + virt_addr.pd_index);

		entries.pd.first = reinterpret_cast<ppde>(pdpte.pfn << 12) + virt_addr.pd_index;
		entries.pd.second = pde;

		if (!pde.value)
			return NULL;

		auto pte = read_phys<::pte>(
			reinterpret_cast<ppte>(pde.pfn << 12) + virt_addr.pt_index);

		entries.pt.first = reinterpret_cast<ppte>(pde.pfn << 12) + virt_addr.pt_index;
		entries.pt.second = pte;

		if (!pte.value)
			return NULL;

		return reinterpret_cast<void*>((pte.pfn << 12) + virt_addr.offset);
	}
}