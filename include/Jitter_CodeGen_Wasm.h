#pragma once

#include <stack>
#include "Jitter_CodeGen.h"
#include "MemStream.h"

class CWasmModuleBuilder;

namespace Jitter
{
	class CWasmFunctionRegistry
	{
	public:
		struct WASM_FUNCTION_INFO
		{
			int32 id = 0;
			std::string signature;
		};

		static void RegisterFunction(uintptr_t, const char*, const char*);
		static const WASM_FUNCTION_INFO* FindFunction(uintptr_t);

	private:
		static std::map<uintptr_t, WASM_FUNCTION_INFO> m_functions;
	};

	class CCodeGen_Wasm : public CCodeGen
	{
	public:
		CCodeGen_Wasm();

		void GenerateCode(const StatementList&, unsigned int) override;
		void SetStream(Framework::CStream*) override;
		void RegisterExternalSymbols(CObjectFile*) const override;

		unsigned int GetAvailableRegisterCount() const override;
		unsigned int GetAvailableMdRegisterCount() const override;
		bool CanHold128BitsReturnValueInRegisters() const override;
		uint32 GetPointerSize() const override;

	private:
		enum LABEL_FLOW
		{
			LABEL_FLOW_IF,
			LABEL_FLOW_ELSE,
			LABEL_FLOW_END,
		};

		typedef void (CCodeGen_Wasm::*ConstCodeEmitterType)(const STATEMENT&);

		typedef std::function<void(void)> ParamEmitterFunction;
		typedef std::stack<ParamEmitterFunction> ParamStack;

		struct CONSTMATCHER
		{
			OPERATION op;
			MATCHTYPE dstType;
			MATCHTYPE src1Type;
			MATCHTYPE src2Type;
			MATCHTYPE src3Type;
			ConstCodeEmitterType emitter;
		};

		static CONSTMATCHER g_constMatchers[];

		void BuildLabelFlows(const StatementList&);
		void PrepareSignatures(CWasmModuleBuilder&, const StatementList&);
		void RegisterSignature(CWasmModuleBuilder&, std::string);

		void PushContext();

		void PushRelativeAddress(CSymbol*);
		void PushRelative(CSymbol*);

		void PushTemporary(CSymbol*);
		void PullTemporary(CSymbol*);

		void PushRelativeRefAddress(CSymbol*);
		void PushRelativeRef(CSymbol*);

		void PushTemporaryRef(CSymbol*);
		void PullTemporaryRef(CSymbol*);

		void PrepareSymbolUse(CSymbol*);
		void PrepareSymbolDef(CSymbol*);
		void CommitSymbol(CSymbol*);

		void MarkLabel(const STATEMENT&);

		void Emit_Mov_VarAny(const STATEMENT&);

		void Emit_RelToRef_VarCst(const STATEMENT&);

		void Emit_AddRef_AnyAnyAny(const STATEMENT&);
		void Emit_IsRefNull_VarVar(const STATEMENT&);

		void Emit_LoadFromRef_VarVar(const STATEMENT&);
		void Emit_LoadFromRef_Ref_VarVar(const STATEMENT&);
		void Emit_Load8FromRef_MemVar(const STATEMENT&);
		void Emit_Load16FromRef_MemVar(const STATEMENT&);

		void Emit_StoreAtRef_VarAny(const STATEMENT&);
		void Emit_Store8AtRef_VarAny(const STATEMENT&);
		void Emit_Store16AtRef_VarAny(const STATEMENT&);

		void Emit_Param_Ctx(const STATEMENT&);
		void Emit_Param_Any(const STATEMENT&);

		void Emit_Call(const STATEMENT&);
		void Emit_RetVal_Tmp(const STATEMENT&);

		void Emit_ExternJmp(const STATEMENT&);

		void Emit_Jmp(const STATEMENT&);
		void Emit_CondJmp_AnyAny(const STATEMENT&);

		void Emit_Cmp_AnyAnyAny(const STATEMENT&);

		void Emit_Sll_AnyAnyAny(const STATEMENT&);
		void Emit_Srl_AnyAnyAny(const STATEMENT&);
		void Emit_Sra_AnyAnyAny(const STATEMENT&);

		void Emit_And_AnyAnyAny(const STATEMENT&);
		void Emit_Or_AnyAnyAny(const STATEMENT&);
		void Emit_Xor_AnyAnyAny(const STATEMENT&);

		void Emit_Add_AnyAnyAny(const STATEMENT&);
		void Emit_Sub_AnyAnyAny(const STATEMENT&);

		Framework::CStream* m_stream = nullptr;
		Framework::CMemStream m_functionStream;
		std::map<uint32, LABEL_FLOW> m_labelFlows;
		std::map<std::string, uint32> m_signatures;
		ParamStack m_params;
	};
}