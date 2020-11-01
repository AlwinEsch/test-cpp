#pragma once

#include "StringUtils.h"

#define LOGDEBUG   0
#define LOGINFO    1
#define LOGWARNING 2
#define LOGERROR   3
#define LOGFATAL   4
#define LOGNONE    5

class CLog
{
public:
  static inline void Log(int loglevel, const char* format, ...)
  {
    char buffer[16384];
    va_list args;
    va_start(args, format);
    vsprintf(buffer, format, args);
    va_end(args);

    time_t rawtime;
    time(&rawtime);
    std::string time = ctime(&rawtime);
    StringUtils::RemoveCRLF(time);

    std::string logMessage = StringUtils::Format("%05i - %i: %s\n", time.c_str(), loglevel, buffer);
    fprintf(stderr, "KODIChromium - %s", logMessage.c_str());
  }
};
