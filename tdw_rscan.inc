/** ======================================================================== **\
	Recursion scanner

| Description:
	A library for detecting recursions.

| Version:
	1.1.0

| Dependencies:
	- AMX Assembly (https://github.com/Zeex/amx_assembly)

| License:
	Copyright (c) 2017 Double V

	This software is provided 'as-is', without any express or implied
	warranty. In no event will the authors be held liable for any damages
	arising from the use of this software.

	Permission is granted to anyone to use this software for any purpose,
	including commercial applications, and to alter it and redistribute it
	freely, subject to the following restrictions:

	1.	The origin of this software must not be misrepresented; you must not
		claim that you wrote the original software. If you use this software
		in a product, an acknowledgement in the product documentation would be
		appreciated but is not required.
	2.	Altered source versions must be plainly marked as such, and must not be
		misrepresented as being the original software.
	3.	This notice may not be removed or altered from any source distribution.
\** ======================================================================== **/

#if defined _inc_tdw_rscan
	#undef _inc_tdw_rscan
#endif

#if defined _TDW_RSCAN
	#endinput
#endif

#define _TDW_RSCAN

#include "amx\disasm"
#include "amx\frame_info"

#if !defined addressofex
	#define addressofex(%1) (RScan_GetNextCallAddress_()?(((%1),TDW_gRscan@CallAddressRet_)?1:2):(TDW_gRscan@CallAddressRet_))
#endif

#if !defined RSCAN_MAX_NESTED_LEVEL
	#define RSCAN_MAX_NESTED_LEVEL (32)
#else
	#assert (0 < RSCAN_MAX_NESTED_LEVEL < 128)
#endif

const
	RSCAN_MAX_FUNC_NAME    = 32,
	RSCAN_STATE_SKIP_FUNC  = 1;

static stock const
	TDW_g_sMessageSeparator[] = " <- ";

static stock
	TDW_g_sHdr[AMX_HDR],
	TDW_g_sDisasmContexts[RSCAN_MAX_NESTED_LEVEL][DisasmContext],
	TDW_g_sCurrentFunction,
	TDW_g_sMessage[(sizeof TDW_g_sMessageSeparator + RSCAN_MAX_FUNC_NAME) * RSCAN_MAX_NESTED_LEVEL + RSCAN_MAX_FUNC_NAME];

stock
	TDW_gRscan@CallAddressRet_;


stock RScan_GetNextCallAddress_()
{
	new
		dctx[DisasmContext];
	DisasmInit(dctx, GetCurrentFrameReturn());
	while (DisasmNext(dctx)) {
		if (DisasmGetOpcode(dctx) == OP_CALL) {
			TDW_gRscan@CallAddressRet_ = DisasmGetOperandReloc(dctx);
			return false;
		}
	}
	return false;
}

stock RScan_Run(address = 0)
{
	new
		dctx[DisasmContext],
		current_addr,
		func_addr,
		parse_state,
		nested_level,
		name[RSCAN_MAX_FUNC_NAME];
	GetAmxHeader(TDW_g_sHdr);
	DisasmInit(dctx, address);
	TDW_g_sCurrentFunction = 0;
	while (RScan_NextCallAddress(dctx, current_addr, func_addr)) {
		if (TDW_g_sCurrentFunction != func_addr) {
			if (address != 0 && TDW_g_sCurrentFunction != 0)
				break;
			TDW_g_sCurrentFunction = func_addr;
			parse_state = TDW_g_sMessage[0] = 0;
			RScan_AddEntryToMessage(func_addr);
		}
		if (parse_state == RSCAN_STATE_SKIP_FUNC)
			continue;
		if (current_addr == func_addr) {
			printf("recursion detected: function %s indirectly calls itself", TDW_g_sMessage);
			parse_state = RSCAN_STATE_SKIP_FUNC;
		} else if (RScan_ScanNestedFunction(current_addr, parse_state, nested_level)) {
			strcat(TDW_g_sMessage, TDW_g_sMessageSeparator);
			if (_:GetPublicNameFromAddress(func_addr, name) == 0)
				valstr(name, address);
			strcat(TDW_g_sMessage, name);
			printf("recursion detected: function %s indirectly calls itself:\n%s", name, TDW_g_sMessage);
		}
	}
}

static stock RScan_ScanNestedFunction(call_func_address, &parse_state, &nested_level)
{
	new addr, func_addr, ret;
	addr = func_addr = ret = 0;
	++nested_level;
	if (nested_level < RSCAN_MAX_NESTED_LEVEL) {
		DisasmInit(TDW_g_sDisasmContexts[nested_level], call_func_address);
		while (RScan_NextCallAddress(TDW_g_sDisasmContexts[nested_level], addr, func_addr)) {
			if (func_addr != call_func_address)
				break;
			if (addr == TDW_g_sCurrentFunction) {
				strcat(TDW_g_sMessage, TDW_g_sMessageSeparator);
				RScan_AddEntryToMessage(func_addr);
				ret = 1;
				parse_state = RSCAN_STATE_SKIP_FUNC;
				break;
			}
			if (RScan_ScanNestedFunction(addr, parse_state, nested_level)) {
				strcat(TDW_g_sMessage, TDW_g_sMessageSeparator);
				RScan_AddEntryToMessage(func_addr);
				ret = 1;
				parse_state = RSCAN_STATE_SKIP_FUNC;
				break;
			}
		}
	}
	return
		--nested_level,
		ret;
}

static stock RScan_NextCallAddress(dctx[DisasmContext], &ret_addr, &func)
{
	while (DisasmNext(dctx)) {
		switch (DisasmGetOpcode(dctx)) {
			case OP_PROC: {
				func = DisasmGetCurIp(dctx) - TDW_g_sHdr[AMX_HDR_COD] + TDW_g_sHdr[AMX_HDR_DAT];
			}
			case OP_CALL: {
				ret_addr = DisasmGetOperandReloc(dctx);
				return true;
			}
		}
	}
	return false;
}

static stock RScan_AddEntryToMessage(address)
{
	static value[RSCAN_MAX_FUNC_NAME];
	if (_:GetPublicNameFromAddress(address, value) == 0)
		valstr(value, address);
	strcat(TDW_g_sMessage, value);
}
