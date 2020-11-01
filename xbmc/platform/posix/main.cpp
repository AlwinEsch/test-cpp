/*
 *  Copyright (C) 2005-2018 Team Kodi
 *  This file is part of Kodi - https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSES/README.md for more information.
 */

#include "AppParamParser.h"
#include "debug/StackTrace.h"
#include "platform/xbmc.h"
#include "utils/log.h"

#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <cstring>
#include <locale.h>
#include <unistd.h>

static pid_t masterPid = 0;

int main(int argc, char *argv[])
{
#if defined(_DEBUG)
  struct rlimit rlim;
  rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
  if (setrlimit(RLIMIT_CORE, &rlim) == -1)
    CLog::Log(LOGDEBUG, "Failed to set core size limit (%s)", strerror(errno));
#endif

  setlocale(LC_NUMERIC, "C");

  CAppParamParser appParamParser;
  appParamParser.Parse(argv, argc);

  if (appParamParser.m_sandBox == Sandbox::Initial)
  {
    int restartCnt = 0;
    if (masterPid > 0 && masterPid != getpid())
    {
      CLog::Log(LOGFATAL, "Sandbox subprocess try to start initial init");
      exit(RETURN_BAD_SANDBOX_START);
    }

    masterPid = getpid();

    // For possible future use-
    // To allow in case where parent process access is needed. GL rendering?
    bool startInside = false;

    CLog::Log(LOGINFO, "Starting Sandbox::Initial (pid : %i)", masterPid);

    while (1)
    {
      /* Start initial runner */
      char** argvChild = new char*[argc+3]();
      for (int i = 0; i < argc; i++)
        argvChild[i] = argv[i];
      argvChild[argc] = strdup("--sandbox=main");
      argvChild[argc+1] = strdup(std::string("--restart-count=" + std::to_string(restartCnt++)).c_str());

      pid_t pid;
      if ((pid = fork()) == 0)
      {
        int ret;
        if (startInside)
        {
          ret = main(argc+2, argvChild);
        }
        else
        {
          execvp(argv[0], argvChild);
          CLog::Log(LOGERROR, "Sandbox::Initial: failed to execvp: %s", argv[0]);
          ret = 127;
        }

        // _exit() instead of exit(), because fork() was called.
        _exit(ret);
      }

      free(argvChild[argc]);
      delete[] argvChild;

      /* Wait and check about his return on exit */
      if (pid > 0)
      {
        /* the parent process calls waitpid() on the child */
        int status;
        if (waitpid(pid, &status, 0) > 0)
        {
          if (WIFSIGNALED(status))
          {
            int sig = WTERMSIG(status);
            CLog::Log(LOGERROR, "Sandbox::Initial: intermediate process terminated by signal %d (%s)%s", sig, strsignal(sig), WCOREDUMP(status) ? " (core dumped)" : "");
          }
          else if (!WIFEXITED(status))
          {
            CLog::Log(LOGERROR, "Sandbox::Initial: intermediate process: unknown termination 0x%x", status);
          }
          else if (WIFEXITED(status) && WEXITSTATUS(status))
          {
            if (WEXITSTATUS(status) == 127)
            {
              /* execl() failed */
            }
            else if (WEXITSTATUS(status) == RETURN_RESTART)
            {
              CLog::Log(LOGERROR, "Sandbox::Initial: Restart triggered from initial sandbox process");
              continue;
            }
          }
          else
          {
            /* the program terminated normally and executed successfully */
            CLog::Log(LOGERROR, "Sandbox::Initial: Initial sandbox process finished and exited %i", masterPid);
          }
        }
        else
        {
          /* waitpid() failed */
        }

        break;
      }
      else
      {
        /* failed to fork() */
        CLog::Log(LOGERROR, "Sandbox::Initial: Failed to create initial sandbox process");
        break;
      }
    }
  }
  else if (appParamParser.m_sandBox == Sandbox::Main)
  {
    KODI::DEBUG::EnableInProcessStackDumping();

    CLog::Log(LOGINFO, "Starting Sandbox::Main (restart qty: %i) (pid : %i)", appParamParser.m_restartCnt, getpid());

    return XBMC_Run(true, appParamParser);
  }

  return 0;
}
