/*
 *  Copyright (C) 2005-2018 Team Kodi
 *  This file is part of Kodi - https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSES/README.md for more information.
 */

#include "AppParamParser.h"

// #include "CompileInfo.h"
// #include "FileItem.h"
// #include "ServiceBroker.h"
// #include "settings/AdvancedSettings.h"
#include "utils/StringUtils.h"
// #include "utils/SystemInfo.h"
#include "utils/log.h"

#include <iostream>
#include <stdlib.h>
#include <string>
#include <vector>

class CFileItemList
{
public:
  CFileItemList() = default;
};

#if defined(TARGET_LINUX)
namespace
{
std::vector<std::string> availableWindowSystems;
} // namespace
#endif

CAppParamParser::CAppParamParser()
: m_logLevel(LOG_LEVEL_NORMAL)
{
}

CAppParamParser::~CAppParamParser() = default;

void CAppParamParser::Parse(const char* const* argv, int nArgs)
{
  if (nArgs > 1)
  {
    for (int i = 1; i < nArgs; i++)
      ParseArg(argv[i]);

  }
}

void CAppParamParser::DisplayVersion()
{
  printf("%s Media Center %s\n", "1.0.0", "kodi");
  printf("Copyright (C) %s Team %s - http://kodi.tv\n",
         "2020", "kodi");
  exit(0);
}

void CAppParamParser::DisplayHelp()
{
  std::string lcAppName = "kodi";
  StringUtils::ToLower(lcAppName);
  printf("Usage: %s [OPTION]... [FILE]...\n\n", lcAppName.c_str());
  printf("Arguments:\n");
  printf("  -fs\t\t\tRuns %s in full screen\n", "kodi");
  printf("  --standalone\t\t%s runs in a stand alone environment without a window \n", "kodi");
  printf("\t\t\tmanager and supporting applications. For example, that\n");
  printf("\t\t\tenables network settings.\n");
  printf("  -p or --portable\t%s will look for configurations in install folder instead of ~/.%s\n", "kodi", lcAppName.c_str());
  printf("  --debug\t\tEnable debug logging\n");
  printf("  --version\t\tPrint version information\n");
  printf("  --test\t\tEnable test mode. [FILE] required.\n");
  printf("  --settings=<filename>\t\tLoads specified file after advancedsettings.xml replacing any settings specified\n");
  printf("  \t\t\t\tspecified file must exist in special://xbmc/system/\n");
#if defined(TARGET_LINUX)
  printf("  --windowing=<system>\tSelect which windowing method to use.\n");
  printf("  \t\t\t\tAvailable window systems are:");
  for (const auto& windowSystem : availableWindowSystems)
    printf(" %s", windowSystem.c_str());
  printf("\n");
#endif
  exit(0);
}

void CAppParamParser::ParseArg(const std::string &arg)
{
  if (arg == "-fs" || arg == "--fullscreen")
    m_startFullScreen = true;
  else if (arg == "-h" || arg == "--help")
    DisplayHelp();
  else if (arg == "-v" || arg == "--version")
    DisplayVersion();
  else if (arg == "--standalone")
    m_standAlone = true;
  else if (arg == "-p" || arg  == "--portable")
    m_platformDirectories = false;
  else if (arg == "--debug")
    m_logLevel = LOG_LEVEL_DEBUG;
  else if (arg == "--test")
    m_testmode = true;
  else if (arg.substr(0, 11) == "--settings=")
    m_settingsFile = arg.substr(11);
  else if (arg.substr(0, 10) == "--sandbox=")
  {
    std::string sandboxName = arg.substr(10);
    if (sandboxName == "main")
    {
      m_sandBox = Sandbox::Main;
    }
    else
    {
      fprintf(stderr, "FATAL: Invalid sandbox type '%s' used on start\n", sandboxName.c_str());
      exit(RETURN_INVALID_SANDBOX);
    }
  }
  else if (arg.substr(0, 16) == "--restart-count=")
  {
    m_restartCnt = std::stoi(arg.substr(16));
  }
#if defined(TARGET_LINUX)
  else if (arg.substr(0, 12) == "--windowing=")
  {
    if (std::find(availableWindowSystems.begin(), availableWindowSystems.end(), arg.substr(12)) !=
        availableWindowSystems.end())
      m_windowing = arg.substr(12);
    else
    {
      std::cout << "Selected window system not available: " << arg << std::endl;
      std::cout << "    Available window systems:";
      for (const auto& windowSystem : availableWindowSystems)
        std::cout << " " << windowSystem;
      std::cout << std::endl;
      exit(0);
    }
  }
#endif
}

void CAppParamParser::SetAdvancedSettings(CAdvancedSettings& advancedSettings) const
{
}

const CFileItemList& CAppParamParser::GetPlaylist() const
{
  return *m_playlist;
}
