#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <thread>

#include "debug/stack_trace.h"

enum class Sandbox
{
  Initial,
  Main,
};

Sandbox m_sandbox = Sandbox::Initial;
int m_restartCnt = 0;

#define RETURN_OK 0
#define RETURN_RESTART 80
#define RETURN_INVALID_SANDBOX 81
#define RETURN_BAD_SANDBOX_START 82

void ParseArg(const std::string &arg)
{
  if (arg.substr(0, 10) == "--sandbox=")
  {
    std::string sandboxName = arg.substr(10);
    if (sandboxName == "main")
    {
      m_sandbox = Sandbox::Main;
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
}

void Parse(const char* const* argv, int nArgs)
{
  if (nArgs > 1)
  {
    for (int i = 1; i < nArgs; i++)
      ParseArg(argv[i]);
  }
}

static pid_t masterPid = 0;

int main(int argc, char *argv[])
{
  Parse(argv, argc);

  if (m_sandbox == Sandbox::Initial)
  {
    pid_t pid;
    int restartCnt = 0;
    if (masterPid > 0 && masterPid != getpid())
    {
      fprintf(stderr, "FATAL: Sandbox subprocess try to start initial init\n");
      exit(RETURN_BAD_SANDBOX_START);
    }

    masterPid = getpid();

    while (1)
    {
      /* Start initial runner */
      char** argvChild = new char*[argc+3]();
      for (int i = 0; i < argc; i++)
        argvChild[i] = argv[i];
      argvChild[argc] = strdup("--sandbox=main");
      argvChild[argc+1] = strdup(std::string("--restart-count=" + std::to_string(restartCnt++)).c_str());

      if ((pid = fork()) == 0)
      {
        int ret = main(argc+2, argvChild);
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
            fprintf(stderr, "%s: intermediate process terminated by signal %d (%s)%s \n", argv[0], sig, strsignal(sig), WCOREDUMP(status) ? " (core dumped)" : "");
          }
          else if (!WIFEXITED(status))
          {
            fprintf(stderr, "%s: intermediate process: unknown termination 0x%x", argv[0], status);
          }
          else if (WIFEXITED(status) && WEXITSTATUS(status))
          {
            if (WEXITSTATUS(status) == 127)
            {
              /* execl() failed */
            }
            else if (WEXITSTATUS(status) == RETURN_RESTART)
            {
              fprintf(stderr, "%s: Restart triggered from initial sandbox process\n", argv[0]);
              continue;
            }
          }
          else
          {
            /* the program terminated normally and executed successfully */
            fprintf(stderr, "%s: Initial sandbox process finished and exited %i\n", argv[0], masterPid);
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
        fprintf(stderr, "%s: Failed to create initial sandbox process\n", argv[0]);
        break;
      }
    }
  }
  else if (m_sandbox == Sandbox::Main)
  {
    if (masterPid == 0)
    {
      fprintf(stderr, "FATAL: Sandbox started without parent present\n");
      exit(RETURN_BAD_SANDBOX_START);
    }

    KODI::DEBUG::EnableInProcessStackDumping();

    fprintf(stderr, "--> %s: Sandbox::Main %i %i\n", __PRETTY_FUNCTION__, m_restartCnt, getpid());

    sleep(3);

    char* a = NULL;
    a[0] = 0;
    if (m_restartCnt < 10)
      return RETURN_RESTART;
  }

  return 0;
}
