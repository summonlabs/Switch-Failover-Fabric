// Switch Failover Fabric - version identity.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "sff/version.hpp"

namespace sff {

const char* to_string(EvidenceClass value) noexcept {
  switch (value) {
    case EvidenceClass::Real:
      return "REAL";
    case EvidenceClass::Synthetic:
      return "SYNTHETIC";
    case EvidenceClass::Unsupported:
      return "UNSUPPORTED";
  }
  return "UNRECOGNISED_EVIDENCE_CLASS";
}

}  // namespace sff
