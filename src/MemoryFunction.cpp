#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <algorithm>
#include <cstdint>
#include "AlignedAlloc.h"
#include "MemoryFunction.h"

#define BLOCK_ALIGN 0x10

#ifdef _WIN32
	#define MEMFUNC_USE_WIN32
#endif

#ifdef __APPLE__
	#include "TargetConditionals.h"
	#include <libkern/OSCacheControl.h>

	#if TARGET_OS_OSX
		#define MEMFUNC_USE_MMAP
		#define MEMFUNC_MMAP_ADDITIONAL_FLAGS (MAP_JIT)
		#if TARGET_CPU_ARM64
			#define MEMFUNC_MMAP_REQUIRES_JIT_WRITE_PROTECT
		#endif
	#else
		#define MEMFUNC_USE_MACHVM
		#if TARGET_OS_IPHONE
			#define MEMFUNC_MACHVM_STRICT_PROTECTION
		#endif
	#endif
#endif

#if defined(__ANDROID__) || defined(__linux__) || defined(__FreeBSD__)
	#define MEMFUNC_USE_MMAP
#endif

#if defined(__EMSCRIPTEN__)
	#include <emscripten.h>
	#define MEMFUNC_USE_WASM
#endif

#if defined(SWITCH)
	#define MEMFUNC_USE_LIBNX_JIT
#endif

#if defined(MEMFUNC_USE_WIN32)
#include <windows.h>
#elif defined(MEMFUNC_USE_MACHVM)
#include <mach/mach_init.h>
#include <mach/vm_map.h>
#elif defined(MEMFUNC_USE_MMAP)
#include <sys/mman.h>
#include <pthread.h>
#elif defined(MEMFUNC_USE_WASM)
EM_JS(int, WasmCreateFunction, (uintptr_t code, uintptr_t size),
{
	//var fs = require('fs');
	let moduleBytes = HEAP8.subarray(code, code + size);
	//fs.writeFileSync('module.wasm', moduleBytes);
	//{
	//	let bytesCopy = new Uint8Array(moduleBytes);
	//	let blob = new Blob([bytesCopy], { type: "binary/octet-stream" });
	//	let url = URL.createObjectURL(blob);
	//	console.log(url);
	//}
	let module = new WebAssembly.Module(moduleBytes);
	let moduleInstance = new WebAssembly.Instance(module, {
		env: {
			memory: wasmMemory,
			fctTable : Module.codeGenImportTable
		}
	});
	let fct = moduleInstance.exports.codeGenFunc;
	let fctId = addFunction(fct, 'vi');
	return fctId;
});
EM_JS(void, WasmDeleteFunction, (int fctId),
{
	removeFunction(fctId);
});
#elif defined(MEMFUNC_USE_LIBNX_JIT)
#include <switch.h>
#include <cstdio>
extern void switch_jit_alloc(size_t size, void **rw_addr, void **rx_addr);
extern void switch_jit_transition_to_writable();
extern void switch_jit_transition_to_executable();
#else
#error "No API to use for CMemoryFunction"
#endif

CMemoryFunction::CMemoryFunction()
: m_code_rx(nullptr)
, m_code_rw(nullptr)
, m_size(0)
{

}

CMemoryFunction::CMemoryFunction(const void* code, size_t size)
: m_code_rx(nullptr)
, m_code_rw(nullptr)
{
#if defined(MEMFUNC_USE_WIN32)
	m_size = size;
	m_code_rx = m_code_rw = framework_aligned_alloc(size, BLOCK_ALIGN);
	memcpy(m_code, code, size);

	DWORD oldProtect = 0;
	BOOL result = VirtualProtect(m_code_rw, size, PAGE_EXECUTE_READWRITE, &oldProtect);
	assert(result == TRUE);
#elif defined(MEMFUNC_USE_MACHVM)
	vm_size_t page_size = 0;
	host_page_size(mach_task_self(), &page_size);
	unsigned int allocSize = ((size + page_size - 1) / page_size) * page_size;
	vm_allocate(mach_task_self(), reinterpret_cast<vm_address_t*>(&m_code_rw), allocSize, TRUE);
	memcpy(m_code_rw, code, size);
	vm_prot_t protection =
	#ifdef MEMFUNC_MACHVM_STRICT_PROTECTION
		VM_PROT_READ | VM_PROT_EXECUTE;
	#else
		VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
	#endif
	kern_return_t result = vm_protect(mach_task_self(), reinterpret_cast<vm_address_t>(m_code_rw), size, 0, protection);
	assert(result == 0);
	m_size = allocSize;
	m_code_rx = m_code_rw;
#elif defined(MEMFUNC_USE_MMAP)
	uint32 additionalMapFlags = 0;
	#ifdef MEMFUNC_MMAP_ADDITIONAL_FLAGS
		additionalMapFlags = MEMFUNC_MMAP_ADDITIONAL_FLAGS;
	#endif
	m_size = size;
	m_code_rx = m_code_rw = mmap(nullptr, size, PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | additionalMapFlags, -1, 0);
	assert(m_code_rx != MAP_FAILED);
#ifdef MEMFUNC_MMAP_REQUIRES_JIT_WRITE_PROTECT
	pthread_jit_write_protect_np(false);
#endif
	memcpy(m_code_rw, code, size);
#ifdef MEMFUNC_MMAP_REQUIRES_JIT_WRITE_PROTECT
	pthread_jit_write_protect_np(true);
#endif
#elif defined(MEMFUNC_USE_WASM)
	m_size = size;
	m_code_rx = m_code_rw = reinterpret_cast<void*>(WasmCreateFunction(reinterpret_cast<uintptr_t>(code), size));
#elif defined(MEMFUNC_USE_LIBNX_JIT)
	switch_jit_alloc((size + (BLOCK_ALIGN - 1)) & ~(BLOCK_ALIGN - 1), &m_code_rw, &m_code_rx);
	switch_jit_transition_to_writable();
	memcpy(m_code_rw, code, size);
	switch_jit_transition_to_executable();
	m_size = size;
#endif
	ClearCache();
#if !defined(MEMFUNC_USE_WASM)
	assert((reinterpret_cast<uintptr_t>(m_code_rx) & (BLOCK_ALIGN - 1)) == 0);
#endif
}

CMemoryFunction::~CMemoryFunction()
{
	Reset();
}

void CMemoryFunction::ClearCache()
{
#ifdef __APPLE__
	sys_icache_invalidate(m_code_rx, m_size);
#elif defined(__ANDROID__) || defined(__linux__) || defined(__FreeBSD__)
	#if defined(__arm__) || defined(__aarch64__)
		__clear_cache(m_code_rx, reinterpret_cast<uint8*>(m_code_rx) + m_size);
	#endif
#endif
}

void CMemoryFunction::Reset()
{
	if(m_code_rx != nullptr)
	{
#if defined(MEMFUNC_USE_WIN32)
		framework_aligned_free(m_code_rx);
#elif defined(MEMFUNC_USE_MACHVM)
		vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(m_code_rx), m_size);
#elif defined(MEMFUNC_USE_MMAP)
		munmap(m_code_rx, m_size);
#elif defined(MEMFUNC_USE_WASM)
		WasmDeleteFunction(reinterpret_cast<int>(m_code_rx));
#endif
	}
	m_code_rx = m_code_rw = nullptr;
	m_size = 0;
}

bool CMemoryFunction::IsEmpty() const
{
	return m_code_rx == nullptr;
}

CMemoryFunction& CMemoryFunction::operator =(CMemoryFunction&& rhs)
{
	Reset();
	std::swap(m_code_rx, rhs.m_code_rx);
	std::swap(m_code_rw, rhs.m_code_rw);
	std::swap(m_size, rhs.m_size);
	return (*this);
}

void CMemoryFunction::operator()(void* context)
{
	typedef void (*FctType)(void*);
	auto fct = reinterpret_cast<FctType>(m_code_rx);
	fct(context);
}

const void* CMemoryFunction::GetCodeRx() const
{
	return m_code_rx;
}

void* CMemoryFunction::GetCodeRw() const
{
	return m_code_rw;
}

size_t CMemoryFunction::GetSize() const
{
	return m_size;
}

void CMemoryFunction::BeginModify()
{
#if defined(MEMFUNC_USE_MACHVM) && defined(MEMFUNC_MACHVM_STRICT_PROTECTION)
	kern_return_t result = vm_protect(mach_task_self(), reinterpret_cast<vm_address_t>(m_code_rx), m_size, 0, VM_PROT_READ | VM_PROT_WRITE);
	assert(result == 0);
#elif defined(MEMFUNC_USE_MMAP) && defined(MEMFUNC_MMAP_REQUIRES_JIT_WRITE_PROTECT)
	pthread_jit_write_protect_np(false);
#elif defined(MEMFUNC_USE_LIBNX_JIT)
	switch_jit_transition_to_writable();
#endif
}

void CMemoryFunction::EndModify()
{
#if defined(MEMFUNC_USE_MACHVM) && defined(MEMFUNC_MACHVM_STRICT_PROTECTION)
	kern_return_t result = vm_protect(mach_task_self(), reinterpret_cast<vm_address_t>(m_code_rx), m_size, 0, VM_PROT_READ | VM_PROT_EXECUTE);
	assert(result == 0);
#elif defined(MEMFUNC_USE_MMAP) && defined(MEMFUNC_MMAP_REQUIRES_JIT_WRITE_PROTECT)
	pthread_jit_write_protect_np(true);
#elif defined(MEMFUNC_USE_LIBNX_JIT)
	switch_jit_transition_to_executable();
#endif
	ClearCache();
}
