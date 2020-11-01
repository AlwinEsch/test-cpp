#pragma once

#define USE(...)                                                   \
  do {                                                             \
    ::KODI::UTILS::Use unused_tmp_array_for_use_macro[]{__VA_ARGS__}; \
    (void)unused_tmp_array_for_use_macro;                          \
  } while (false)

namespace KODI
{
namespace UTILS
{

// The USE(x, ...) template is used to silence C++ compiler warnings
// issued for (yet) unused variables (typically parameters).
// The arguments are guaranteed to be evaluated from left to right.
struct Use
{
  template <typename T>
  Use(T&&) {}  // NOLINT(runtime/explicit)
};

} /* namespace UTILS */
} /* namespace KODI */
