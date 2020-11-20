#include "vad.hpp"

namespace vad
{
	auto get_vad_offset(vdm::vdm_ctx& v_ctx)->std::uint32_t
	{
		const auto [um_addr, base_offset] =
			util::memory::sig_scan(VAD_OFFSET_SIG, VAD_OFFSET_MASK);

		return *reinterpret_cast<std::uint32_t*>(um_addr + 3);
	}

	auto get_vad_root(vdm::vdm_ctx& v_ctx, PEPROCESS process)->std::uintptr_t
	{
		static const auto vad_offset = 
			vad::get_vad_offset(v_ctx);

		return v_ctx.rkm<std::uintptr_t>(
			reinterpret_cast<std::uintptr_t>(process) + vad_offset);
	}

	auto set_vad_root(vdm::vdm_ctx& v_ctx, PEPROCESS process, std::uintptr_t vad_root)->void
	{
		static const auto vad_offset =
			vad::get_vad_offset(v_ctx);

		v_ctx.wkm<std::uintptr_t>(
			reinterpret_cast<std::uintptr_t>(process) + vad_offset, vad_root);
	}
}