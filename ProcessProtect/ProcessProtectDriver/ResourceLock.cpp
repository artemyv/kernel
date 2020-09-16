#include "ResourceLock.h"

void ExecutiveResource::Init() {
	ExInitializeResourceLite(&_er);
}

void ExecutiveResource::Lock() {
	ExAcquireResourceExclusiveLite(&_er, TRUE);
}

void ExecutiveResource::Unlock() {
	ExReleaseResourceLite(&_er);
}

void ExecutiveResource::LockShared() {
	ExAcquireResourceSharedLite(&_er, TRUE);
}
