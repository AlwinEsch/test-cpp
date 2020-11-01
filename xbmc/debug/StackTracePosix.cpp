// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Slightly adapted for inclusion in V8.
// Copyright 2016 the V8 project authors. All rights reserved.

#include "StackTrace.h"

#include "symbolize/symbolize.h"
#include "utils/log.h"
#include "utils/StringUtils.h"
#include "utils/Utils.h"
#include "system.h"

#include <map>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <vector>

#include <cxxabi.h>
#include <execinfo.h>
#include <fcntl.h>

namespace KODI
{
namespace DEBUG
{

class CBacktraceOutputHandler
{
 public:
  virtual void HandleOutput(const char* output) = 0;

 protected:
  virtual ~CBacktraceOutputHandler() = default;
};

}  // namespace DEBUG
}  // namespace KODI

namespace
{

// Describes a region of mapped memory and the path of the file mapped.
struct MappedMemoryRegion
{
  enum Permission
  {
    READ = 1 << 0,
    WRITE = 1 << 1,
    EXECUTE = 1 << 2,
    PRIVATE = 1 << 3,  // If set, region is private, otherwise it is shared.
  };

  // The address range [start,end) of mapped memory.
  uintptr_t start;
  uintptr_t end;

  // Byte offset into |path| of the range mapped into memory.
  unsigned long long offset;

  // Image base, if this mapping corresponds to an ELF image.
  uintptr_t base;

  // Bitmask of read/write/execute/private/shared permissions.
  uint8_t permissions;

  // Name of the file mapped into memory.
  //
  // NOTE: path names aren't guaranteed to point at valid files. For example,
  // "[heap]" and "[stack]" are used to represent the location of the process'
  // heap and stack, respectively.
  std::string path;
};

// NOTE: code from sandbox/linux/seccomp-bpf/demo.cc.
char* itoa_r(intptr_t i, char* buf, size_t sz, int base, size_t padding)
{
  // Make sure we can write at least one NUL byte.
  size_t n = 1;
  if (n > sz) return nullptr;

  if (base < 2 || base > 16)
  {
    buf[0] = '\0';
    return nullptr;
  }

  char* start = buf;

  uintptr_t j = i;

  // Handle negative numbers (only for base 10).
  if (i < 0 && base == 10)
  {
    // This does "j = -i" while avoiding integer overflow.
    j = static_cast<uintptr_t>(-(i + 1)) + 1;

    // Make sure we can write the '-' character.
    if (++n > sz)
    {
      buf[0] = '\0';
      return nullptr;
    }
    *start++ = '-';
  }

  // Loop until we have converted the entire number. Output at least one
  // character (i.e. '0').
  char* ptr = start;
  do
  {
    // Make sure there is still enough space left in our output buffer.
    if (++n > sz)
    {
      buf[0] = '\0';
      return nullptr;
    }

    // Output the next digit.
    *ptr++ = "0123456789abcdef"[j % base];
    j /= base;

    if (padding > 0) padding--;
  } while (j > 0 || padding > 0);

  // Terminate the output with a NUL character.
  *ptr = '\0';

  // Conversion to ASCII actually resulted in the digits being in reverse
  // order. We can't easily generate them in forward order, as we can't tell
  // the number of characters needed until we are done converting.
  // So, now, we reverse the string (except for the possible "-" sign).
  while (--ptr > start)
  {
    char ch = *ptr;
    *ptr = *start;
    *start++ = ch;
  }
  return buf;
}

void PrintToStderr(const char* output)
{
  // NOTE: This code MUST be async-signal safe (it's used by in-process
  // stack dumping signal handler). NO malloc or stdio is allowed here.
  ssize_t return_val = write(STDERR_FILENO, output, strlen(output));
  USE(return_val);
}

void StackDumpSignalHandler(int signal, siginfo_t* info, void* void_context)
{
  // NOTE: This code MUST be async-signal safe.
  // NO malloc or stdio is allowed here.

//   if (BeingDebugged())
//     BreakDebugger();

  PrintToStderr("Received signal ");
  char buf[1024] = { 0 };
  itoa_r(signal, buf, sizeof(buf), 10, 0);
  PrintToStderr(buf);
  if (signal == SIGBUS)
  {
    if (info->si_code == BUS_ADRALN)
      PrintToStderr(" BUS_ADRALN ");
    else if (info->si_code == BUS_ADRERR)
      PrintToStderr(" BUS_ADRERR ");
    else if (info->si_code == BUS_OBJERR)
      PrintToStderr(" BUS_OBJERR ");
    else
      PrintToStderr(" <unknown> ");
  }
  else if (signal == SIGFPE)
  {
    if (info->si_code == FPE_FLTDIV)
      PrintToStderr(" FPE_FLTDIV ");
    else if (info->si_code == FPE_FLTINV)
      PrintToStderr(" FPE_FLTINV ");
    else if (info->si_code == FPE_FLTOVF)
      PrintToStderr(" FPE_FLTOVF ");
    else if (info->si_code == FPE_FLTRES)
      PrintToStderr(" FPE_FLTRES ");
    else if (info->si_code == FPE_FLTSUB)
      PrintToStderr(" FPE_FLTSUB ");
    else if (info->si_code == FPE_FLTUND)
      PrintToStderr(" FPE_FLTUND ");
    else if (info->si_code == FPE_INTDIV)
      PrintToStderr(" FPE_INTDIV ");
    else if (info->si_code == FPE_INTOVF)
      PrintToStderr(" FPE_INTOVF ");
    else
      PrintToStderr(" <unknown> ");
  }
  else if (signal == SIGILL)
  {
    if (info->si_code == ILL_BADSTK)
      PrintToStderr(" ILL_BADSTK ");
    else if (info->si_code == ILL_COPROC)
      PrintToStderr(" ILL_COPROC ");
    else if (info->si_code == ILL_ILLOPN)
      PrintToStderr(" ILL_ILLOPN ");
    else if (info->si_code == ILL_ILLADR)
      PrintToStderr(" ILL_ILLADR ");
    else if (info->si_code == ILL_ILLTRP)
      PrintToStderr(" ILL_ILLTRP ");
    else if (info->si_code == ILL_PRVOPC)
      PrintToStderr(" ILL_PRVOPC ");
    else if (info->si_code == ILL_PRVREG)
      PrintToStderr(" ILL_PRVREG ");
    else
      PrintToStderr(" <unknown> ");
  }
  else if (signal == SIGSEGV)
  {
    if (info->si_code == SEGV_MAPERR)
      PrintToStderr(" SEGV_MAPERR ");
    else if (info->si_code == SEGV_ACCERR)
      PrintToStderr(" SEGV_ACCERR ");
    else
      PrintToStderr(" <unknown> ");
  }
  if (signal == SIGBUS || signal == SIGFPE ||
      signal == SIGILL || signal == SIGSEGV)
  {
    itoa_r(reinterpret_cast<intptr_t>(info->si_addr),
            buf, sizeof(buf), 16, 12);
    PrintToStderr(buf);
  }
  PrintToStderr("\n");

  KODI::DEBUG::StackTrace().Print();

#if defined(TARGET_LINUX)
#if ARCH_CPU_X86_FAMILY

  ucontext_t* context = reinterpret_cast<ucontext_t*>(void_context);
  const struct {
    const char* label;
    greg_t value;
  } registers[] = {
#if ARCH_CPU_32_BITS
    { "  gs: ", context->uc_mcontext.gregs[REG_GS] },
    { "  fs: ", context->uc_mcontext.gregs[REG_FS] },
    { "  es: ", context->uc_mcontext.gregs[REG_ES] },
    { "  ds: ", context->uc_mcontext.gregs[REG_DS] },
    { " edi: ", context->uc_mcontext.gregs[REG_EDI] },
    { " esi: ", context->uc_mcontext.gregs[REG_ESI] },
    { " ebp: ", context->uc_mcontext.gregs[REG_EBP] },
    { " esp: ", context->uc_mcontext.gregs[REG_ESP] },
    { " ebx: ", context->uc_mcontext.gregs[REG_EBX] },
    { " edx: ", context->uc_mcontext.gregs[REG_EDX] },
    { " ecx: ", context->uc_mcontext.gregs[REG_ECX] },
    { " eax: ", context->uc_mcontext.gregs[REG_EAX] },
    { " trp: ", context->uc_mcontext.gregs[REG_TRAPNO] },
    { " err: ", context->uc_mcontext.gregs[REG_ERR] },
    { "  ip: ", context->uc_mcontext.gregs[REG_EIP] },
    { "  cs: ", context->uc_mcontext.gregs[REG_CS] },
    { " efl: ", context->uc_mcontext.gregs[REG_EFL] },
    { " usp: ", context->uc_mcontext.gregs[REG_UESP] },
    { "  ss: ", context->uc_mcontext.gregs[REG_SS] },
#elif ARCH_CPU_64_BITS
    { "  r8: ", context->uc_mcontext.gregs[REG_R8] },
    { "  r9: ", context->uc_mcontext.gregs[REG_R9] },
    { " r10: ", context->uc_mcontext.gregs[REG_R10] },
    { " r11: ", context->uc_mcontext.gregs[REG_R11] },
    { " r12: ", context->uc_mcontext.gregs[REG_R12] },
    { " r13: ", context->uc_mcontext.gregs[REG_R13] },
    { " r14: ", context->uc_mcontext.gregs[REG_R14] },
    { " r15: ", context->uc_mcontext.gregs[REG_R15] },
    { "  di: ", context->uc_mcontext.gregs[REG_RDI] },
    { "  si: ", context->uc_mcontext.gregs[REG_RSI] },
    { "  bp: ", context->uc_mcontext.gregs[REG_RBP] },
    { "  bx: ", context->uc_mcontext.gregs[REG_RBX] },
    { "  dx: ", context->uc_mcontext.gregs[REG_RDX] },
    { "  ax: ", context->uc_mcontext.gregs[REG_RAX] },
    { "  cx: ", context->uc_mcontext.gregs[REG_RCX] },
    { "  sp: ", context->uc_mcontext.gregs[REG_RSP] },
    { "  ip: ", context->uc_mcontext.gregs[REG_RIP] },
    { " efl: ", context->uc_mcontext.gregs[REG_EFL] },
    { " cgf: ", context->uc_mcontext.gregs[REG_CSGSFS] },
    { " erf: ", context->uc_mcontext.gregs[REG_ERR] },
    { " trp: ", context->uc_mcontext.gregs[REG_TRAPNO] },
    { " msk: ", context->uc_mcontext.gregs[REG_OLDMASK] },
    { " cr2: ", context->uc_mcontext.gregs[REG_CR2] },
#endif  // ARCH_CPU_32_BITS
  };

#if ARCH_CPU_32_BITS
  const int kRegisterPadding = 8;
#elif ARCH_CPU_64_BITS
  const int kRegisterPadding = 16;
#endif

  for (size_t i = 0; i < ARRAYSIZE(registers); i++)
  {
    PrintToStderr(registers[i].label);
    itoa_r(registers[i].value, buf, sizeof(buf),
                     16, kRegisterPadding);
    PrintToStderr(buf);

    if ((i + 1) % 4 == 0)
      PrintToStderr("\n");
  }
  PrintToStderr("\n");
#endif  // ARCH_CPU_X86_FAMILY
#endif  // defined(TARGET_LINUX)

  PrintToStderr("[end of stack trace]\n");

#ifdef TARGET_DARWIN
  if (::signal(signal, SIG_DFL) == SIG_ERR)
    _exit(1);
#else
  // Non-Mac OSes should probably reraise the signal as well, but the Linux
  // sandbox tests break on CrOS devices.
  // https://code.google.com/p/chromium/issues/detail?id=551681
  PrintToStderr("Calling _exit(1). Core file will not be generated.\n");
  _exit(1);
#endif  // !TARGET_DARWIN
}

void WarmUpBacktrace()
{
  // Warm up stack trace infrastructure. It turns out that on the first
  // call glibc initializes some internal data structures using pthread_once,
  // and even backtrace() can call malloc(), leading to hangs.
  //
  // Example stack trace snippet (with tcmalloc):
  //
  // #8  0x0000000000a173b5 in tc_malloc
  //             at ./third_party/tcmalloc/chromium/src/debugallocation.cc:1161
  // #9  0x00007ffff7de7900 in _dl_map_object_deps at dl-deps.c:517
  // #10 0x00007ffff7ded8a9 in dl_open_worker at dl-open.c:262
  // #11 0x00007ffff7de9176 in _dl_catch_error at dl-error.c:178
  // #12 0x00007ffff7ded31a in _dl_open (file=0x7ffff625e298 "libgcc_s.so.1")
  //             at dl-open.c:639
  // #13 0x00007ffff6215602 in do_dlopen at dl-libc.c:89
  // #14 0x00007ffff7de9176 in _dl_catch_error at dl-error.c:178
  // #15 0x00007ffff62156c4 in dlerror_run at dl-libc.c:48
  // #16 __GI___libc_dlopen_mode at dl-libc.c:165
  // #17 0x00007ffff61ef8f5 in init
  //             at ../sysdeps/x86_64/../ia64/backtrace.c:53
  // #18 0x00007ffff6aad400 in pthread_once
  //             at ../nptl/sysdeps/unix/sysv/linux/x86_64/pthread_once.S:104
  // #19 0x00007ffff61efa14 in __GI___backtrace
  //             at ../sysdeps/x86_64/../ia64/backtrace.c:104
  // #20 0x0000000000752a54 in base::debug::StackTrace::StackTrace
  //             at base/debug/stack_trace_posix.cc:175
  // #21 0x00000000007a4ae5 in
  //             base::(anonymous namespace)::StackDumpSignalHandler
  //             at base/process_util_posix.cc:172
  // #22 <signal handler called>
  KODI::DEBUG::StackTrace stack_trace;
}

// Scans |proc_maps| starting from |pos| returning true if the gate VMA was
// found, otherwise returns false.
static bool ContainsGateVMA(std::string* proc_maps, size_t pos)
{
#if defined(__aarch64__) || defined(__ARM_ARCH_7A__)
  // The gate VMA on ARM kernels is the interrupt vectors page.
  return proc_maps->find(" [vectors]\n", pos) != std::string::npos;
#elif defined(__i386__) || defined(__x86_64__)
  // The gate VMA on x86 64-bit kernels is the virtual system call page.
  return proc_maps->find(" [vsyscall]\n", pos) != std::string::npos;
#else
  // Otherwise assume there is no gate VMA in which case we shouldn't
  // get duplicate entires.
  return false;
#endif
}

bool ReadProcMaps(std::string* proc_maps)
{
  // seq_file only writes out a page-sized amount on each call. Refer to header
  // file for details.
  const long kReadSize = sysconf(_SC_PAGESIZE);

  int fd = open("/proc/self/maps", O_RDONLY);
  if (fd < 0)
  {
    close(fd);
    CLog::Log(LOGERROR, "Couldn't open /proc/self/maps");
    return false;
  }
  proc_maps->clear();

  while (true)
  {
    // To avoid a copy, resize |proc_maps| so read() can write directly into it.
    // Compute |buffer| afterwards since resize() may reallocate.
    size_t pos = proc_maps->size();
    proc_maps->resize(pos + kReadSize);
    void* buffer = &(*proc_maps)[pos];

    ssize_t bytes_read = read(fd, buffer, kReadSize);
    if (bytes_read < 0)
    {
      close(fd);
      CLog::Log(LOGERROR, "Couldn't read /proc/self/maps");
      proc_maps->clear();
      return false;
    }

    // ... and don't forget to trim off excess bytes.
    proc_maps->resize(pos + bytes_read);

    if (bytes_read == 0)
      break;

    // The gate VMA is handled as a special case after seq_file has finished
    // iterating through all entries in the virtual memory table.
    //
    // Unfortunately, if additional entries are added at this point in time
    // seq_file gets confused and the next call to read() will return duplicate
    // entries including the gate VMA again.
    //
    // Avoid this by searching for the gate VMA and breaking early.
    if (ContainsGateVMA(proc_maps, pos))
      break;
  }

  close(fd);

  return true;
}

bool ParseProcMaps(const std::string& input,
                   std::vector<MappedMemoryRegion>* regions_out)
{
  std::vector<MappedMemoryRegion> regions;

  // This isn't async safe nor terribly efficient, but it doesn't need to be at
  // this point in time.
  std::vector<std::string> entries
  { "\n" };
  std::vector<std::string> lines = StringUtils::Split(
      input, entries);

  for (size_t i = 0; i < lines.size(); ++i)
  {
    // Due to splitting on '\n' the last line should be empty.
    if (i == lines.size() - 1) {
      if (!lines[i].empty()) {
        CLog::Log(LOGWARNING, "Last line not empty");
        return false;
      }
      break;
    }

    MappedMemoryRegion region;
    const char* line = lines[i].c_str();
    char permissions[5] = {'\0'};  // Ensure NUL-terminated string.
    uint8_t dev_major = 0;
    uint8_t dev_minor = 0;
    long inode = 0;
    int path_index = 0;

    // Sample format from man 5 proc:
    //
    // address           perms offset  dev   inode   pathname
    // 08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm
    //
    // The final %n term captures the offset in the input string, which is used
    // to determine the path name. It *does not* increment the return value.
    // Refer to man 3 sscanf for details.
    if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4c %llx %hhx:%hhx %ld %n",
               &region.start, &region.end, permissions, &region.offset,
               &dev_major, &dev_minor, &inode, &path_index) < 7) {
      CLog::Log(LOGWARNING, "sscanf failed for line: %s", line);
      return false;
    }

    region.permissions = 0;

    if (permissions[0] == 'r')
      region.permissions |= MappedMemoryRegion::READ;
    else if (permissions[0] != '-')
      return false;

    if (permissions[1] == 'w')
      region.permissions |= MappedMemoryRegion::WRITE;
    else if (permissions[1] != '-')
      return false;

    if (permissions[2] == 'x')
      region.permissions |= MappedMemoryRegion::EXECUTE;
    else if (permissions[2] != '-')
      return false;

    if (permissions[3] == 'p')
      region.permissions |= MappedMemoryRegion::PRIVATE;
    else if (permissions[3] != 's' && permissions[3] != 'S')  // Shared memory.
      return false;

    // Pushing then assigning saves us a string copy.
    regions.push_back(region);
    regions.back().path.assign(line + path_index);
  }

  regions_out->swap(regions);
  return true;
}


// class SandboxSymbolizeHelper.
//
// The purpose of this class is to prepare and install a "file open" callback
// needed by the stack trace symbolization code
// (base/third_party/symbolize/symbolize.h) so that it can function properly
// in a sandboxed process.  The caveat is that this class must be instantiated
// before the sandboxing is enabled so that it can get the chance to open all
// the object files that are loaded in the virtual address space of the current
// process.
class SandboxSymbolizeHelper
{
 private:
  SandboxSymbolizeHelper()
      : is_initialized_(false)
      {
    Init();
  }

  ~SandboxSymbolizeHelper() {
    UnregisterCallback();
    CloseObjectFiles();
  }

 public:
  // Returns the singleton instance.
  static SandboxSymbolizeHelper* GetInstance()
  {
    static SandboxSymbolizeHelper sandbox;
    return &sandbox;
  }

  // Returns a O_RDONLY file descriptor for |file_path| if it was opened
  // successfully during the initialization.  The file is repositioned at
  // offset 0.
  // IMPORTANT: This function must be async-signal-safe because it can be
  // called from a signal handler (symbolizing stack frames for a crash).
  int GetFileDescriptor(const char* file_path)
  {
    int fd = -1;

#if !defined(OFFICIAL_BUILD) || !defined(NO_UNWIND_TABLES)
    if (file_path)
    {
      // The assumption here is that iterating over std::map<std::string, int>
      // using a const_iterator does not allocate dynamic memory, hense it is
      // async-signal-safe.
      std::map<std::string, int>::const_iterator it;
      for (it = modules_.begin(); it != modules_.end(); ++it)
      {
        if (strcmp((it->first).c_str(), file_path) == 0)
        {
          // POSIX.1-2004 requires an implementation to guarantee that dup()
          // is async-signal-safe.
          fd = dup(it->second);
          break;
        }
      }
      // POSIX.1-2004 requires an implementation to guarantee that lseek()
      // is async-signal-safe.
      if (fd >= 0 && lseek(fd, 0, SEEK_SET) < 0)
      {
        // Failed to seek.
        fd = -1;
      }
    }
#endif  // !defined(OFFICIAL_BUILD) || !defined(NO_UNWIND_TABLES)

    return fd;
  }

  // Searches for the object file (from /proc/self/maps) that contains
  // the specified pc.  If found, sets |start_address| to the start address
  // of where this object file is mapped in memory, sets the module base
  // address into |base_address|, copies the object file name into
  // |out_file_name|, and attempts to open the object file.  If the object
  // file is opened successfully, returns the file descriptor.  Otherwise,
  // returns -1.  |out_file_name_size| is the size of the file name buffer
  // (including the null terminator).
  // IMPORTANT: This function must be async-signal-safe because it can be
  // called from a signal handler (symbolizing stack frames for a crash).
  static int OpenObjectFileContainingPc(uint64_t pc, uint64_t& start_address,
                                        uint64_t& base_address, char* file_path,
                                        int file_path_size) {
    // This method can only be called after the singleton is instantiated.
    // This is ensured by the following facts:
    // * This is the only static method in this class, it is private, and
    //   the class has no friends (except for the DefaultSingletonTraits).
    //   The compiler guarantees that it can only be called after the
    //   singleton is instantiated.
    // * This method is used as a callback for the stack tracing code and
    //   the callback registration is done in the constructor, so logically
    //   it cannot be called before the singleton is created.
    SandboxSymbolizeHelper* instance = GetInstance();

    // Cannot use STL iterators here, since debug iterators use locks.
    // NOLINTNEXTLINE(modernize-loop-convert)
    for (size_t i = 0; i < instance->regions_.size(); ++i)
    {
      const MappedMemoryRegion& region = instance->regions_[i];
      if (region.start <= pc && pc < region.end)
      {
        start_address = region.start;
        base_address = region.base;
        if (file_path && file_path_size > 0)
        {
          strncpy(file_path, region.path.c_str(), file_path_size);
          // Ensure null termination.
          file_path[file_path_size - 1] = '\0';
        }
        return instance->GetFileDescriptor(region.path.c_str());
      }
    }
    return -1;
  }

  // Set the base address for each memory region by reading ELF headers in
  // process memory.
  void SetBaseAddressesForMemoryRegions()
  {
    int mem_fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (mem_fd < 0)
    {
      close(mem_fd);
      return;
    }

    auto safe_memcpy = [&mem_fd](void* dst, uintptr_t src, size_t size)
    {
      return pread(mem_fd, dst, size, src) == ssize_t(size);
    };

    uintptr_t cur_base = 0;
    for (auto& r : regions_)
    {
      ElfW(Ehdr) ehdr;
      static_assert(SELFMAG <= sizeof(ElfW(Ehdr)), "SELFMAG too large");
      if ((r.permissions & MappedMemoryRegion::READ) &&
          safe_memcpy(&ehdr, r.start, sizeof(ElfW(Ehdr))) &&
          memcmp(ehdr.e_ident, ELFMAG, SELFMAG) == 0) {
        switch (ehdr.e_type)
        {
          case ET_EXEC:
            cur_base = 0;
            break;
          case ET_DYN:
            // Find the segment containing file offset 0. This will correspond
            // to the ELF header that we just read. Normally this will have
            // virtual address 0, but this is not guaranteed. We must subtract
            // the virtual address from the address where the ELF header was
            // mapped to get the base address.
            //
            // If we fail to find a segment for file offset 0, use the address
            // of the ELF header as the base address.
            cur_base = r.start;
            for (unsigned i = 0; i != ehdr.e_phnum; ++i)
            {
              ElfW(Phdr) phdr;
              if (safe_memcpy(&phdr, r.start + ehdr.e_phoff + i * sizeof(phdr),
                              sizeof(phdr)) &&
                  phdr.p_type == PT_LOAD && phdr.p_offset == 0) {
                cur_base = r.start - phdr.p_vaddr;
                break;
              }
            }
            break;
          default:
            // ET_REL or ET_CORE. These aren't directly executable, so they
            // don't affect the base address.
            break;
        }
      }

      r.base = cur_base;
    }
  }

  // Parses /proc/self/maps in order to compile a list of all object file names
  // for the modules that are loaded in the current process.
  // Returns true on success.
  bool CacheMemoryRegions()
  {
    // Reads /proc/self/maps.
    std::string contents;
    if (!ReadProcMaps(&contents))
    {
      CLog::Log(LOGERROR, "Failed to read /proc/self/maps");
      return false;
    }

    // Parses /proc/self/maps.
    if (!ParseProcMaps(contents, &regions_))
    {
      CLog::Log(LOGERROR, "Failed to parse the contents of /proc/self/maps");
      return false;
    }

    SetBaseAddressesForMemoryRegions();

    is_initialized_ = true;
    return true;
  }

  // Opens all object files and caches their file descriptors.
  void OpenSymbolFiles()
  {
    // Pre-opening and caching the file descriptors of all loaded modules is
    // not safe for production builds.  Hence it is only done in non-official
    // builds.  For more details, take a look at: http://crbug.com/341966.
#if !defined(OFFICIAL_BUILD) || !defined(NO_UNWIND_TABLES)
    // Open the object files for all read-only executable regions and cache
    // their file descriptors.
    std::vector<MappedMemoryRegion>::const_iterator it;
    for (it = regions_.begin(); it != regions_.end(); ++it)
    {
      const MappedMemoryRegion& region = *it;
      // Only interesed in read-only executable regions.
      if ((region.permissions & MappedMemoryRegion::READ) ==
              MappedMemoryRegion::READ &&
          (region.permissions & MappedMemoryRegion::WRITE) == 0 &&
          (region.permissions & MappedMemoryRegion::EXECUTE) ==
              MappedMemoryRegion::EXECUTE)
      {
        if (region.path.empty())
        {
          // Skip regions with empty file names.
          continue;
        }
        if (region.path[0] == '[')
        {
          // Skip pseudo-paths, like [stack], [vdso], [heap], etc ...
          continue;
        }
        if (StringUtils::EndsWithNoCase(region.path, " (deleted)"))
        {
          // Skip deleted files.
          continue;
        }
        // Avoid duplicates.
        if (modules_.find(region.path) == modules_.end())
        {
          int fd = open(region.path.c_str(), O_RDONLY | O_CLOEXEC);
          if (fd >= 0)
          {
            modules_.insert(std::make_pair(region.path, fd));
          }
          else
          {
            CLog::Log(LOGWARNING, "Failed to open file: %s Error: %s", region.path.c_str(), strerror(errno));
          }
        }
      }
    }
#endif  // !defined(OFFICIAL_BUILD) || !defined(NO_UNWIND_TABLES)
  }

  // Initializes and installs the symbolization callback.
  void Init()
  {
    if (CacheMemoryRegions())
    {
      OpenSymbolFiles();
      google::InstallSymbolizeOpenObjectFileCallback(
          &OpenObjectFileContainingPc);
    }
  }

  // Unregister symbolization callback.
  void UnregisterCallback()
  {
    if (is_initialized_)
    {
      google::InstallSymbolizeOpenObjectFileCallback(nullptr);
      is_initialized_ = false;
    }
  }

  // Closes all file descriptors owned by this instance.
  void CloseObjectFiles()
  {
#if !defined(OFFICIAL_BUILD) || !defined(NO_UNWIND_TABLES)
    std::map<std::string, int>::iterator it;
    for (it = modules_.begin(); it != modules_.end(); ++it)
    {
      close(it->second);
      it->second = -1;
    }
    modules_.clear();
#endif  // !defined(OFFICIAL_BUILD) || !defined(NO_UNWIND_TABLES)
  }

  // Set to true upon successful initialization.
  bool is_initialized_;

#if !defined(OFFICIAL_BUILD) || !defined(NO_UNWIND_TABLES)
  // Mapping from file name to file descriptor.  Includes file descriptors
  // for all successfully opened object files and the file descriptor for
  // /proc/self/maps.  This code is not safe for production builds.
  std::map<std::string, int> modules_;
#endif  // !defined(OFFICIAL_BUILD) || !defined(NO_UNWIND_TABLES)

  // Cache for the process memory regions.  Produced by parsing the contents
  // of /proc/self/maps cache.
  std::vector<MappedMemoryRegion> regions_;
};

}

namespace KODI
{
namespace DEBUG
{

class PrintBacktraceOutputHandler : public CBacktraceOutputHandler
{
 public:
  PrintBacktraceOutputHandler() = default;

  void HandleOutput(const char* output) override
  {
    // NOTE: This code MUST be async-signal safe (it's used by in-process
    // stack dumping signal handler). NO malloc or stdio is allowed here.
    PrintToStderr(output);
  }
};

class StreamBacktraceOutputHandler : public CBacktraceOutputHandler
{
 public:
  explicit StreamBacktraceOutputHandler(std::ostream* os) : os_(os)
  {
  }

  void HandleOutput(const char* output) override
  {
    (*os_) << std::string(output);
  }

 private:
  std::ostream* os_;
};

bool EnableInProcessStackDumping()
{
  SandboxSymbolizeHelper::GetInstance();

  // When running in an application, our code typically expects SIGPIPE
  // to be ignored.  Therefore, when testing that same code, it should run
  // with SIGPIPE ignored as well.
  struct sigaction sigpipe_action;
  memset(&sigpipe_action, 0, sizeof(sigpipe_action));
  sigpipe_action.sa_handler = SIG_IGN;
  sigemptyset(&sigpipe_action.sa_mask);
  bool success = (sigaction(SIGPIPE, &sigpipe_action, nullptr) == 0);

  // Avoid hangs during backtrace initialization, see above.
  WarmUpBacktrace();

  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_flags = SA_RESETHAND | SA_SIGINFO;
  action.sa_sigaction = &StackDumpSignalHandler;
  sigemptyset(&action.sa_mask);

  success &= (sigaction(SIGILL, &action, nullptr) == 0);
  success &= (sigaction(SIGABRT, &action, nullptr) == 0);
  success &= (sigaction(SIGFPE, &action, nullptr) == 0);
  success &= (sigaction(SIGBUS, &action, nullptr) == 0);
  success &= (sigaction(SIGSEGV, &action, nullptr) == 0);
// On Linux, SIGSYS is reserved by the kernel for seccomp-bpf sandboxing.
#if !defined(TARGET_LINUX)
  success &= (sigaction(SIGSYS, &action, nullptr) == 0);
#endif  // !defined(TARGET_LINUX)

  return success;
}

#if !defined(__UCLIBC__) && !defined(_AIX)

void OutputPointer(void* pointer, CBacktraceOutputHandler* handler)
{
  // This should be more than enough to store a 64-bit number in hex:
  // 16 hex digits + 1 for null-terminator.
  char buf[17] = { '\0' };
  handler->HandleOutput("0x");
  itoa_r(reinterpret_cast<intptr_t>(pointer), buf, sizeof(buf), 16, 12);
  handler->HandleOutput(buf);
}

void OutputFrameId(intptr_t frame_id, CBacktraceOutputHandler* handler)
{
  // Max unsigned 64-bit number in decimal has 20 digits (18446744073709551615).
  // Hence, 30 digits should be more than enough to represent it in decimal
  // (including the null-terminator).
  char buf[30] = { '\0' };
  handler->HandleOutput("#");
  itoa_r(frame_id, buf, sizeof(buf), 10, 1);
  handler->HandleOutput(buf);
}

void ProcessBacktrace(void* const* trace,
                      size_t size,
                      const char* prefix_string,
                      CBacktraceOutputHandler* handler)
{
// NOTE: This code MUST be async-signal safe (it's used by in-process
// stack dumping signal handler). NO malloc or stdio is allowed here.

  for (size_t i = 0; i < size; ++i)
  {
    if (prefix_string)
      handler->HandleOutput(prefix_string);

    OutputFrameId(i, handler);
    handler->HandleOutput(" ");
    OutputPointer(trace[i], handler);
    handler->HandleOutput(" ");

    char buf[1024] = { '\0' };

    // Subtract by one as return address of function may be in the next
    // function when a function is annotated as noreturn.
    void* address = static_cast<char*>(trace[i]) - 1;
    if (google::Symbolize(address, buf, sizeof(buf)))
      handler->HandleOutput(buf);
    else
      handler->HandleOutput("<unknown>");

    handler->HandleOutput("\n");
  }
}

void StackTrace::OutputToStreamWithPrefix(std::ostream* os,
                                          const char* prefix_string) const
{
  StreamBacktraceOutputHandler handler(os);
  ProcessBacktrace(trace_, count_, prefix_string, &handler);
}

#endif  // !defined(__UCLIBC__) && !defined(_AIX)

size_t CollectStackTrace(void** trace, size_t count) {
  // NOTE: This code MUST be async-signal safe (it's used by in-process
  // stack dumping signal handler). NO malloc or stdio is allowed here.

#if !defined(__UCLIBC__) && !defined(_AIX)
  // Though the backtrace API man page does not list any possible negative
  // return values, we take no chance.
  return static_cast<size_t>(backtrace(trace, count));
#else
  return 0;
#endif
}

void StackTrace::PrintWithPrefix(const char* prefix_string) const {
// NOTE: This code MUST be async-signal safe (it's used by in-process
// stack dumping signal handler). NO malloc or stdio is allowed here.

#if !defined(__UCLIBC__) && !defined(_AIX)
  PrintBacktraceOutputHandler handler;
  ProcessBacktrace(trace_, count_, prefix_string, &handler);
#endif
}

}  // namespace DEBUG
}  // namespace KODI
