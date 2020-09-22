#pragma once

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

