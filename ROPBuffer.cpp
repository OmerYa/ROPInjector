
#include "ROPBuffer.h"

ROPBuffer::ROPBuffer(ULONGLONG Rsp, SIZE_T ROPBufferEntries)
{
	TargetRsp = Rsp;
	CurrentPosition = 0;
	DataPosition = (ULONG)ROPBufferEntries - 1;
	Buffer = NULL;
	Buffer = new ULONGLONG[ROPBufferEntries];
	BufferSize = ROPBufferEntries * sizeof(ULONGLONG);
	ZeroMemory(Buffer, BufferSize);
}

ROPBuffer::~ROPBuffer()
{
	if (NULL != Buffer)
		delete[] Buffer;
	Buffer = NULL;
}

ULONGLONG ROPBuffer::SetRip(ULONGLONG Address)
{
	TargetRip = Address;
	return TargetRip;
}

ULONGLONG ROPBuffer::InsertRopValue(ULONGLONG Value)
{
#ifdef _DEBUG
	if (CurrentPosition >= DataPosition)
		throw; // ROP Buffer too small
#endif

	Buffer[CurrentPosition] = Value;
	++CurrentPosition;

	return Value;
}

ULONGLONG ROPBuffer::InsertRopDataPointer(ULONGLONG Data)
{
	ULONGLONG Value;

#ifdef _DEBUG
	if (DataPosition <= CurrentPosition)
		throw; // ROP Buffer too small
#endif

	Buffer[DataPosition] = Data;

	Value = TargetRsp + sizeof(ULONGLONG) * DataPosition;
	
	--DataPosition;

	return InsertRopValue(Value);
}

ULONGLONG* ROPBuffer::GetBuffer()
{
	return Buffer;
}

SIZE_T ROPBuffer::GetBufferSize()
{
	return BufferSize;
}

ULONGLONG ROPBuffer::GetRip()
{
	return TargetRip;
}

ULONGLONG ROPBuffer::GetRsp()
{
	return TargetRsp;
}
