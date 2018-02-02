LOCAL_PATH := $(call my-dir)
TOP_LOCAL_PATH := $(LOCAL_PATH)

MUPDF_ROOT := ../..
SSL_BUILD := true
ifdef NDK_PROFILER
include android-ndk-profiler.mk
endif


include $(CLEAR_VARS)
PLATFORM=arm
LOCAL_MODULE := crypto
LOCAL_SRC_FILES := pre-compiled-${PLATFORM}/libcrypto.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := ssl 
LOCAL_SRC_FILES := pre-compiled-${PLATFORM}/libssl.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := guomiSDK 
LOCAL_SRC_FILES := pre-compiled-${PLATFORM}/libguomiSDK.so
include $(PREBUILT_SHARED_LIBRARY)


include $(TOP_LOCAL_PATH)/Core.mk
include $(TOP_LOCAL_PATH)/ThirdParty.mk

include $(CLEAR_VARS)

LOCAL_C_INCLUDES := \
	jni/andprof \
	$(MUPDF_ROOT)/include \
	$(MUPDF_ROOT)/source/fitz \
	$(MUPDF_ROOT)/source/pdf

LOCAL_CFLAGS :=
LOCAL_MODULE    := mupdf
LOCAL_SRC_FILES := mupdf.c
LOCAL_STATIC_LIBRARIES := mupdfcore mupdfthirdparty

ifdef NDK_PROFILER
LOCAL_CFLAGS += -pg -DNDK_PROFILER
LOCAL_STATIC_LIBRARIES += andprof
endif
ifdef SUPPORT_GPROOF
LOCAL_CFLAGS += -DSUPPORT_GPROOF
endif

LOCAL_LDLIBS    := -lm -llog -ljnigraphics
ifdef SSL_BUILD
LOCAL_STATIC_LIBRARIES += crypto ssl 
LOCAL_SHARED_LIBRARIES := guomiSDK
endif

include $(BUILD_SHARED_LIBRARY)
