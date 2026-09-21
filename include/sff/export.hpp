// Switch Failover Fabric - public export macros.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef SFF_EXPORT_HPP
#define SFF_EXPORT_HPP

#if defined(_WIN32) || defined(__CYGWIN__)
#  if defined(SFF_SHARED)
#    if defined(SFF_BUILDING_LIBRARY)
#      define SFF_API __declspec(dllexport)
#    else
#      define SFF_API __declspec(dllimport)
#    endif
#  else
#    define SFF_API
#  endif
#else
#  if defined(SFF_SHARED) && defined(SFF_BUILDING_LIBRARY) && (defined(__GNUC__) || defined(__clang__))
#    define SFF_API __attribute__((visibility("default")))
#  else
#    define SFF_API
#  endif
#endif

#endif  // SFF_EXPORT_HPP
