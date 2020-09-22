#pragma once
#include <Wdm.h>
struct FastMutexLocker {
	FastMutexLocker(PFAST_MUTEX mutex) : _mutex(mutex) {
		ExAcquireFastMutex(mutex);
	}

	~FastMutexLocker() {
		ExReleaseFastMutex(_mutex);
	}

private:
	PFAST_MUTEX _mutex;
};
