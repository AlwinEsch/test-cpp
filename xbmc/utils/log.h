#pragma once

#include "StringUtils.h"

#define LOG_LEVEL_NONE         -1 // nothing at all is logged
#define LOG_LEVEL_NORMAL        0 // shows notice, error, severe and fatal
#define LOG_LEVEL_DEBUG         1 // shows all
#define LOG_LEVEL_DEBUG_FREEMEM 2 // shows all + shows freemem on screen
#define LOG_LEVEL_MAX           LOG_LEVEL_DEBUG_FREEMEM

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

    std::string logMessage = StringUtils::Format("%s - %i: %s\n", time.c_str(), loglevel, buffer);
    fprintf(stderr, "KODIChromium - %s", logMessage.c_str());
  }
};
