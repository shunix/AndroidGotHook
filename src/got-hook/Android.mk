LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := got-hook
LOCAL_SRC_FILES := elf_utils.c injector.c main.c ptrace.c utils.c
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_LDFLAGS += -pie

include $(BUILD_EXECUTABLE)
