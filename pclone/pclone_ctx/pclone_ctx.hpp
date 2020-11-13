#include "../mem_ctx/mem_ctx.hpp"

namespace nasa
{
	class pclone_ctx
	{
		friend class mem_ctx;
	public:
		explicit pclone_ctx(mem_ctx* clone_ctx);
		auto clone() -> std::pair<std::uint32_t, HANDLE>;
	private:
		mem_ctx* clone_target_ctx;
	};
}