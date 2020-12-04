#include "../ptm_ctx/ptm_ctx.hpp"

namespace nasa
{
	class pclone_ctx
	{
		friend class mem_ctx;
	public:
		explicit pclone_ctx(ptm::ptm_ctx* clone_ctx);
		auto clone() -> std::pair<std::uint32_t, HANDLE>;
	private:
		ptm::ptm_ctx* clone_target_ctx;
	};
}