LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := hook
LOCAL_SRC_FILES := hook.c
LOCAL_LDLIBS:=-L$(SYSROOT)/usr/lib -llog
LOCAL_LDFLAGS += -shared

include $(BUILD_SHARED_LIBRARY)
