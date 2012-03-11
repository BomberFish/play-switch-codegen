#ifndef _CALL64TEST_H_
#define _CALL64TEST_H_

#include "Test.h"
#include "MemoryFunction.h"

class CCall64Test : public CTest
{
public:
						CCall64Test();
	virtual				~CCall64Test();

	void				Compile(Jitter::CJitter&);
	void				Run();

private:
	struct uint128
	{
		float v[4];
	};

	struct CONTEXT
	{
		uint64			value0;
		uint64			value1;

		uint64			result;
	};

	static uint64		Add64(uint64, uint64);

	CMemoryFunction*	m_function;
};

#endif