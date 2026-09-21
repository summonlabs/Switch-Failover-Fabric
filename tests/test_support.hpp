// Switch Failover Fabric - minimal dependency-free test harness.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Deliberately tiny: no third-party framework, no test timeouts, no watchdog threads. A test
// that hangs is a defect in the code under test and must be diagnosed, not masked.
#ifndef SFF_TESTS_TEST_SUPPORT_HPP
#define SFF_TESTS_TEST_SUPPORT_HPP

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <sstream>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#include "sff/core/identity.hpp"
#include "sff/core/outcome.hpp"
#include "sff/model/generation.hpp"

namespace sfftest {

struct TestCase {
  const char* name;
  void (*fn)();
};

inline std::vector<TestCase>& registry() {
  static std::vector<TestCase> value;
  return value;
}

inline std::uint64_t& failure_count() {
  static std::uint64_t value = 0;
  return value;
}

inline std::uint64_t& check_count() {
  static std::uint64_t value = 0;
  return value;
}

inline std::string& current_case() {
  static std::string value;
  return value;
}

struct Registrar {
  Registrar(const char* name, void (*fn)()) { registry().push_back(TestCase{name, fn}); }
};

/// Deterministic pseudo-random generator. Every property test takes an explicit seed so that a
/// failing run can be reproduced exactly.
class Rng {
 public:
  explicit Rng(std::uint64_t seed) : state_(seed == 0 ? 0x9e3779b97f4a7c15ull : seed) {}

  std::uint64_t next() {
    std::uint64_t z = (state_ += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
  }

  std::uint64_t bounded(std::uint64_t upper_exclusive) {
    return upper_exclusive == 0 ? 0 : next() % upper_exclusive;
  }

  bool coin() { return (next() & 1u) != 0u; }

 private:
  std::uint64_t state_;
};

/// Temporary directory that always cleans up after itself, so no test debris is left behind.
class TempDir {
 public:
  explicit TempDir(const std::string& tag) {
    const auto now = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
    static std::uint64_t counter = 0;
    counter += 1;
    std::ostringstream name;
    name << "sff-test-" << tag << "-" << now << "-" << counter;
    path_ = std::filesystem::temp_directory_path() / name.str();
    std::error_code code;
    std::filesystem::remove_all(path_, code);
    std::filesystem::create_directories(path_, code);
  }

  ~TempDir() {
    std::error_code code;
    std::filesystem::remove_all(path_, code);
  }

  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;

  const std::filesystem::path& path() const { return path_; }
  std::filesystem::path file(const std::string& name) const { return path_ / name; }

 private:
  std::filesystem::path path_;
};

// --- value rendering ------------------------------------------------------------------------

template <class T, class = void>
struct is_streamable : std::false_type {};

template <class T>
struct is_streamable<T, std::void_t<decltype(std::declval<std::ostream&>()
                                             << std::declval<const T&>())>> : std::true_type {};

template <class T>
std::string describe(const T& value) {
  if constexpr (std::is_arithmetic_v<T>) {
    return std::to_string(value);
  } else if constexpr (std::is_convertible_v<T, const char*>) {
    return std::string(static_cast<const char*>(value));
  } else if constexpr (std::is_enum_v<T>) {
    return std::to_string(static_cast<long long>(value));
  } else if constexpr (is_streamable<T>::value) {
    std::ostringstream stream;
    stream << value;
    return stream.str();
  } else {
    return "<?>";
  }
}

// Overloads for the library's own value types keep failure output readable.
inline std::string describe(sff::Code value) { return sff::to_string(value); }
inline std::string describe(const sff::SwitchKey& value) { return value.to_string(); }
inline std::string describe(const sff::DependentRef& value) { return value.to_string(); }
inline std::string describe(const sff::GenerationVector& value) { return value.to_string(); }

inline std::string describe(const std::string& value) { return value; }
inline std::string describe(const std::filesystem::path& value) { return value.string(); }
inline std::string describe(const char* value) { return std::string(value == nullptr ? "(null)" : value); }
inline std::string describe(bool value) { return value ? "true" : "false"; }

inline void fail(const char* file, int line, const std::string& message) {
  failure_count() += 1;
  std::printf("  FAIL %s:%d [%s] %s\n", file, line, current_case().c_str(), message.c_str());
  std::fflush(stdout);
}

inline void record_check() { check_count() += 1; }

template <class A, class B>
void check_equal(const char* file, int line, const A& left, const B& right, const char* text) {
  record_check();
  if (!(left == right)) {
    fail(file, line, std::string(text) + " (left=" + describe(left) + " right=" + describe(right) + ")");
  }
}

template <class A, class B>
void check_not_equal(const char* file, int line, const A& left, const B& right, const char* text) {
  record_check();
  if (left == right) {
    fail(file, line, std::string(text) + " (both=" + describe(left) + ")");
  }
}

template <class A, class B>
void check_less(const char* file, int line, const A& left, const B& right, const char* text) {
  record_check();
  if (!(left < right)) {
    fail(file, line, std::string(text) + " (left=" + describe(left) + " right=" + describe(right) + ")");
  }
}

inline int run_all() {
  std::printf("running %zu test cases\n", registry().size());
  std::uint64_t failed_cases = 0;
  const auto started = std::chrono::steady_clock::now();
  for (const auto& test : registry()) {
    current_case() = test.name;
    const std::uint64_t before = failure_count();
    std::printf("- %s\n", test.name);
    std::fflush(stdout);
    test.fn();
    if (failure_count() != before) failed_cases += 1;
  }
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - started)
                           .count();
  std::printf("cases=%zu failed_cases=%llu checks=%llu elapsed_ms=%lld\n", registry().size(),
              static_cast<unsigned long long>(failed_cases),
              static_cast<unsigned long long>(check_count()),
              static_cast<long long>(elapsed));
  return failed_cases == 0 ? 0 : 1;
}

}  // namespace sfftest

#define SFF_TEST(name)                                                    \
  static void name();                                                     \
  static const ::sfftest::Registrar sff_registrar_##name(#name, &name);   \
  static void name()

#define CHECK(condition)                                                        \
  do {                                                                          \
    ::sfftest::record_check();                                                  \
    if (!(condition)) ::sfftest::fail(__FILE__, __LINE__, #condition);          \
  } while (false)

#define CHECK_EQ(left, right) \
  ::sfftest::check_equal(__FILE__, __LINE__, (left), (right), #left " == " #right)

#define CHECK_NE(left, right) \
  ::sfftest::check_not_equal(__FILE__, __LINE__, (left), (right), #left " != " #right)

#define CHECK_LT(left, right) \
  ::sfftest::check_less(__FILE__, __LINE__, (left), (right), #left " < " #right)

#define SFF_MAIN() \
  int main() { return ::sfftest::run_all(); }

#endif  // SFF_TESTS_TEST_SUPPORT_HPP
