/*
 *  Copyright (C) 2005-2018 Team Kodi
 *  This file is part of Kodi - https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSES/README.md for more information.
 */

#pragma once

#include <memory>
#include <string>

#define RETURN_OK 0
#define RETURN_RESTART 80
#define RETURN_INVALID_SANDBOX 81
#define RETURN_BAD_SANDBOX_START 82

class CAdvancedSettings;
class CFileItemList;

enum class Sandbox
{
  Initial,
  Main,
};

class CAppParamParser
{
public:
  CAppParamParser();
  ~CAppParamParser();

  void Parse(const char* const* argv, int nArgs);
  void SetAdvancedSettings(CAdvancedSettings& advancedSettings) const;

  const CFileItemList& GetPlaylist() const;

  Sandbox m_sandBox = Sandbox::Initial;
  int m_restartCnt = 0;
  int m_logLevel;
  bool m_startFullScreen = false;
  bool m_platformDirectories = true;
  bool m_testmode = false;
  bool m_standAlone = false;
  std::string m_windowing;

private:
  void ParseArg(const std::string &arg);
  void DisplayHelp();
  void DisplayVersion();

  std::string m_settingsFile;
  std::unique_ptr<CFileItemList> m_playlist;
};
