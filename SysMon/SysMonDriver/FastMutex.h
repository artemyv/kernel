#pragma once
#include <Wdm.h>

struct FastMutex {
	void Init();

	void Lock();
	void Unlock();

private:
	FAST_MUTEX _mutex;
};

