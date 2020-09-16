#pragma once

#include <Wdm.h>

template<typename TLock>
struct AutoLocker {
	AutoLocker(TLock& lock) : _lock(lock) {
		lock.Lock();
	}

	~AutoLocker() {
		_lock.Unlock();
	}

private:
	TLock& _lock;
};

template<typename TLock>
struct AutoSharedLocker {
	AutoSharedLocker(TLock& lock) : _lock(lock) {
		lock.LockShared();
	}

	~AutoSharedLocker() {
		_lock.UnlockShared();
	}

private:
	TLock& _lock;
};


struct ExecutiveResource {
	void Init();
	void Lock();
	void Unlock();
	void LockShared();
	void UnlockShared() {
		Unlock();
	}

private:
	ERESOURCE _er;
};
