#include "../vdm_ctx/vdm_ctx.hpp"

#define VAD_OFFSET_SIG "\x48\x8B\x00\x00\x00\x00\x00\x48\xC1\xEB\x0C\xEB"
#define VAD_OFFSET_MASK "xx?????xxxxx"

namespace vad
{
	auto get_vad_offset(vdm::vdm_ctx& v_ctx)->std::uint32_t;
	auto get_vad_root(vdm::vdm_ctx& v_ctx, PEPROCESS process)->std::uintptr_t;
	auto set_vad_root(vdm::vdm_ctx& v_ctx, PEPROCESS process, std::uintptr_t vad_root)->void;
}