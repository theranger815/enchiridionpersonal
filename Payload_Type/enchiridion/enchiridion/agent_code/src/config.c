#include "config.h"

#if defined(_WIN32) || defined(_WIN64)
const char *OS = "Windows";
#elif defined(__linux__)
const char *OS = "Linux";
#else
const char *OS = "Unknown";
#endif
