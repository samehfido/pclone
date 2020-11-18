#pragma once
#include "../vdm_ctx/vdm_ctx.hpp"

using PETHREAD = PVOID;
using PsSuspendThread = NTSTATUS(*)(PETHREAD, PULONG);
using PsLookupThreadByThreadId = NTSTATUS(*)(HANDLE, PETHREAD*);

#define KE_BALANCE_SIG "\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x48\x8B\x88\x00\x00\x00\x00\x48\x8D\x05"
#define KE_BALANCE_MASK "xxxxx????xxx????xxx"

#define SUSPEND_THREAD_SIG "\xE8\x00\x00\x00\x00\x8B\xF8\xBA\x50\x73\x53\x75"
#define SUSPEND_THREAD_MASK "x????xxxxxxx"

namespace set_mgr
{
	auto get_setmgr_pethread(vdm::vdm_ctx& v_ctx)->PETHREAD;
	auto stop_setmgr(vdm::vdm_ctx& v_ctx, PETHREAD pethread)->NTSTATUS;
}