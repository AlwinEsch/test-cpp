/*
 *  Copyright (C) 2005-2018 Team Kodi
 *  This file is part of Kodi - https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSES/README.md for more information.
 */

#include "AppParamParser.h"
#include "utils/log.h"

#include <unistd.h>

extern "C" int XBMC_Run(bool renderGUI, const CAppParamParser &params)
{
  int status = -1;

  sleep(3);

  char* a = NULL;
  a[0] = 0;
  if (params.m_restartCnt < 10)
    return RETURN_RESTART;

  return status;
}
