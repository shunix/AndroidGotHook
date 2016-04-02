#include <android/log.h>
#include <stdarg.h>
#include <stdio.h>
#define TAG "Hook Library"

int my_printf(const char *format, ...) {
  va_list args;
  va_start(args, format);
  int ret = __android_log_vprint(ANDROID_LOG_DEBUG, TAG, format, args);
  va_end(args);
  return ret;
}
