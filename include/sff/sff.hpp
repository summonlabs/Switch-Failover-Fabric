// Switch Failover Fabric - umbrella header.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Switch-level failure fencing and authoritative reconstruction planning.
//
// Boundary, stated once here and enforced throughout:
//   owned  - deciding which dependent authority a failed switch generation invalidates, fencing
//            it, selecting among supplied reconstruction alternatives under current generations,
//            and deciding when service may be restored;
//   not owned - topology discovery, general path solving, switch ASIC programming, routing
//            convergence, hardware repair.
#ifndef SFF_SFF_HPP
#define SFF_SFF_HPP

#include "sff/version.hpp"

#include "sff/core/checked.hpp"
#include "sff/core/clock.hpp"
#include "sff/core/identity.hpp"
#include "sff/core/limits.hpp"
#include "sff/core/log.hpp"
#include "sff/core/outcome.hpp"

#include "sff/codec/bytes.hpp"
#include "sff/codec/integrity.hpp"

#include "sff/model/authority.hpp"
#include "sff/model/decision.hpp"
#include "sff/model/evidence.hpp"
#include "sff/model/generation.hpp"
#include "sff/model/switch.hpp"
#include "sff/model/topology.hpp"

#include "sff/plan/plan.hpp"
#include "sff/plan/planner.hpp"
#include "sff/plan/reference_solver.hpp"
#include "sff/plan/validator.hpp"

#include "sff/persist/records.hpp"
#include "sff/persist/store.hpp"

#include "sff/runtime/coordinator.hpp"
#include "sff/runtime/failover.hpp"
#include "sff/runtime/policy.hpp"
#include "sff/runtime/session.hpp"

#include "sff/transport/client.hpp"
#include "sff/transport/frame.hpp"
#include "sff/transport/server.hpp"

#endif  // SFF_SFF_HPP
