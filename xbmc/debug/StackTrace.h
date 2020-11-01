// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Slightly adapted for inclusion in V8.
// Copyright 2016 the V8 project authors. All rights reserved.

#pragma once

#include <stddef.h>

#include <iosfwd>
#include <string>

#if TARGET_POSIX
#include <unistd.h>
#endif

#if TARGET_WINDOWS
struct _EXCEPTION_POINTERS;
struct _CONTEXT;
#endif

namespace KODI
{
namespace DEBUG
{

// Record a stack trace with up to |count| frames into |trace|. Returns the
// number of frames read.
size_t CollectStackTrace(void** trace, size_t count);

// Enables stack dump to console output on exception and signals.
// When enabled, the process will quit immediately. This is meant to be used in
// tests only!
bool EnableInProcessStackDumping();
void DisableSignalStackDump();

// A stacktrace can be helpful in debugging. For example, you can include a
// stacktrace member in a object (probably around #ifndef NDEBUG) so that you
// can later see where the given object was created from.
class StackTrace
{
 public:
  // Creates a stacktrace from the current location.
  StackTrace();

  // Creates a stacktrace from the current location, of up to |count| entries.
  // |count| will be limited to at most |kMaxTraces|.
  explicit StackTrace(size_t count);

  // Creates a stacktrace from an existing array of instruction
  // pointers (such as returned by Addresses()).  |count| will be
  // trimmed to |kMaxTraces|.
  StackTrace(const void* const* trace, size_t count);

#if TARGET_WINDOWS
  // Creates a stacktrace for an exception.
  // Note: this function will throw an import not found (StackWalk64) exception
  // on system without dbghelp 5.1.
  StackTrace(_EXCEPTION_POINTERS* exception_pointers);
  StackTrace(const _CONTEXT* context);
#endif

  // Copying and assignment are allowed with the default functions.

  // Gets an array of instruction pointer values. |*count| will be set to the
  // number of elements in the returned array.
  const void* const* Addresses(size_t* count) const;

  // Prints the stack trace to stderr.
  void Print() const;

  // Prints the stack trace to stderr, prepending the given string before
  // each output line.
  void PrintWithPrefix(const char* prefix_string) const;

  // Resolves backtrace to symbols and write to stream.
  void OutputToStream(std::ostream* os) const;

  // Resolves backtrace to symbols and write to stream, with the provided
  // prefix string prepended to each line.
  void OutputToStreamWithPrefix(std::ostream* os,
                                const char* prefix_string) const;

  // Resolves backtrace to symbols and returns as string.
  std::string ToString() const;

  // Resolves backtrace to symbols and returns as string, prepending the
  // provided prefix string to each line.
  std::string ToStringWithPrefix(const char* prefix_string) const;

 private:
#if TARGET_WINDOWS
  void InitTrace(const _CONTEXT* context_record);
#endif

#if defined(TARGET_ANDROID)
  // TODO(https://crbug.com/925525): Testing indicates that Android has issues
  // with a larger value here, so leave Android at 62.
  static constexpr int kMaxTraces = 62;
#else
  // For other platforms, use 250. This seems reasonable without
  // being huge.
  static constexpr int kMaxTraces = 250;
#endif

  void* trace_[kMaxTraces];

  // The number of valid frames in |trace_|.
  size_t count_;
};

// Forwards to StackTrace::OutputToStream().
std::ostream& operator<<(std::ostream& os, const StackTrace& s);

}  // namespace DEBUG
}  // namespace KODI

