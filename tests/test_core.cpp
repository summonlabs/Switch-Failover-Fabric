// Switch Failover Fabric - core contract verification.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Covers the outcome taxonomy, bounded explanations, strong identity, generation vectors, the
// canonical digest accumulator, checked arithmetic, bounded limits, the bounded event log and the
// deterministic manual clock.
//
// Every property-style test uses an explicit seed, and every invariant is re-asserted after each
// operation rather than only at the end of the loop.

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <vector>

#include "sff/codec/integrity.hpp"
#include "sff/core/checked.hpp"
#include "sff/core/clock.hpp"
#include "sff/core/identity.hpp"
#include "sff/core/limits.hpp"
#include "sff/core/log.hpp"
#include "sff/core/outcome.hpp"
#include "sff/model/generation.hpp"

#include "test_support.hpp"

namespace {

using sff::Code;

/// The complete durable outcome taxonomy: Ok (0) through Expired (27). A new enumerator must be
/// added here deliberately, which is exactly the review this list exists to force.
constexpr std::size_t kCodeCount = 28;

Code code_at(std::size_t index) { return static_cast<Code>(index); }

bool is_named_indeterminate(Code code) {
  switch (code) {
    case Code::Unknown:
    case Code::Indeterminate:
    case Code::SearchLimitReached:
    case Code::Ambiguous:
    case Code::Interrupted:
    case Code::Busy:
    case Code::DeadlineExceeded:
      return true;
    default:
      return false;
  }
}

// --- checked-arithmetic probes ---------------------------------------------------------------

template <class T>
bool add_is(T a, T b, T expected) {
  const std::optional<T> result = sff::checked_add(a, b);
  return result.has_value() && *result == expected;
}

template <class T>
bool add_refused(T a, T b) {
  return !sff::checked_add(a, b).has_value();
}

template <class T>
bool sub_is(T a, T b, T expected) {
  const std::optional<T> result = sff::checked_sub(a, b);
  return result.has_value() && *result == expected;
}

template <class T>
bool sub_refused(T a, T b) {
  return !sff::checked_sub(a, b).has_value();
}

template <class T>
bool mul_is(T a, T b, T expected) {
  const std::optional<T> result = sff::checked_mul(a, b);
  return result.has_value() && *result == expected;
}

template <class T>
bool mul_refused(T a, T b) {
  return !sff::checked_mul(a, b).has_value();
}

sff::SwitchKey key_of(std::uint64_t id, std::uint64_t generation) {
  return sff::SwitchKey(sff::SwitchId(id), sff::SwitchGeneration(generation));
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// Outcome taxonomy
// ---------------------------------------------------------------------------------------------

SFF_TEST(code_taxonomy_renders_distinctly_and_explicitly) {
  std::vector<std::string> names;
  names.reserve(kCodeCount);
  for (std::size_t index = 0; index < kCodeCount; ++index) {
    const Code code = code_at(index);
    const std::string name = sff::to_string(code);
    CHECK(!name.empty());
    CHECK(name != "UNRECOGNISED_CODE");
    CHECK_EQ(name, sff::to_string(code));  // stable: the same code renders identically
    names.push_back(name);
  }
  CHECK_EQ(names.size(), kCodeCount);

  std::size_t distinct = 0;
  for (std::size_t left = 0; left < names.size(); ++left) {
    bool unique = true;
    for (std::size_t right = 0; right < names.size(); ++right) {
      if (left != right && names[left] == names[right]) unique = false;
    }
    if (unique) distinct += 1;
  }
  CHECK_EQ(distinct, kCodeCount);

  // An out-of-range value is reported as unrecognised rather than silently mapped onto a real
  // outcome.
  CHECK_EQ(std::string(sff::to_string(code_at(kCodeCount))), std::string("UNRECOGNISED_CODE"));
  CHECK_EQ(std::string(sff::to_string(code_at(60000))), std::string("UNRECOGNISED_CODE"));
}

SFF_TEST(code_classification_is_exact) {
  for (std::size_t index = 0; index < kCodeCount; ++index) {
    const Code code = code_at(index);
    CHECK_EQ(sff::is_success(code), code == Code::Ok);
    CHECK_EQ(sff::is_fail_closed(code), code != Code::Ok);
    CHECK_EQ(sff::is_indeterminate(code), is_named_indeterminate(code));
  }
  CHECK(sff::is_success(Code::Ok));
  CHECK(!sff::is_fail_closed(Code::Ok));

  // The three codes named by the contract: absence of a conclusion is not a negative conclusion.
  CHECK(!sff::is_indeterminate(Code::Ok));
  CHECK(!sff::is_indeterminate(Code::Invalid));
  CHECK(!sff::is_indeterminate(Code::ProvenInfeasible));
  CHECK(sff::is_indeterminate(Code::Unknown));
  CHECK(sff::is_indeterminate(Code::Indeterminate));
  CHECK(sff::is_indeterminate(Code::SearchLimitReached));
  CHECK(sff::is_indeterminate(Code::Ambiguous));
  CHECK(sff::is_indeterminate(Code::Interrupted));
  CHECK(sff::is_indeterminate(Code::Busy));
  CHECK(sff::is_indeterminate(Code::DeadlineExceeded));

  // A proven negative still confers no authority.
  CHECK(sff::is_fail_closed(Code::ProvenInfeasible));
  CHECK(!sff::is_success(Code::ProvenInfeasible));
}

// ---------------------------------------------------------------------------------------------
// Status: bounded explanations that are never Ok while failing
// ---------------------------------------------------------------------------------------------

SFF_TEST(status_is_never_ok_when_failing_and_is_bounded) {
  const sff::Status success = sff::Status::success();
  CHECK(success.ok());
  CHECK_EQ(std::string(sff::to_string(success.code())), std::string("OK"));
  CHECK_EQ(std::string(success.message()), std::string(""));
  CHECK_EQ(success.detail(), std::uint32_t{0});

  // Code::Ok is normalised: a failing status can never claim the affirmative code.
  const sff::Status normalised = sff::Status::failure(Code::Ok, "cannot be reported as success");
  CHECK(!normalised.ok());
  CHECK(normalised.code() != Code::Ok);
  CHECK(normalised.code() == Code::Invalid);
  CHECK_EQ(std::string(normalised.message()), std::string("cannot be reported as success"));

  const sff::Status detailed = sff::Status::failure(Code::Stale, "outside its validity window", 42);
  CHECK(detailed.code() == Code::Stale);
  CHECK_EQ(detailed.detail(), std::uint32_t{42});
  CHECK(!detailed.ok());

  // Exactly at the bound: retained in full.
  const std::string exact(sff::kMaxMessageBytes, 'x');
  const sff::Status at_bound = sff::Status::failure(Code::Invalid, exact);
  CHECK_EQ(at_bound.message().size(), sff::kMaxMessageBytes);
  CHECK_EQ(at_bound.message(), exact);

  // Over the bound: truncated to exactly the bound, deterministically.
  const std::string oversized(std::size_t{4096}, 'y');
  const sff::Status truncated = sff::Status::failure(Code::Invalid, oversized);
  CHECK_EQ(truncated.message().size(), sff::kMaxMessageBytes);
  CHECK_EQ(truncated.message(), oversized.substr(0, sff::kMaxMessageBytes));
  CHECK_EQ(sff::bounded_message(oversized), truncated.message());
  CHECK_EQ(sff::bounded_message(exact), exact);
  CHECK(!truncated.ok());
}

// ---------------------------------------------------------------------------------------------
// Strong identity
// ---------------------------------------------------------------------------------------------

SFF_TEST(switch_key_is_generation_exact) {
  const sff::SwitchId identity(5);
  const sff::SwitchKey first(identity, sff::SwitchGeneration(1));
  const sff::SwitchKey second(identity, sff::SwitchGeneration(2));

  CHECK(first.valid());
  CHECK(second.valid());
  CHECK(first != second);          // matching identity is not matching generation
  CHECK(first.same_identity(second));
  CHECK(first < second);           // generation order within one identity
  CHECK(!(second < first));
  CHECK(second > first);
  CHECK(first <= second);
  CHECK_EQ(first.id().raw(), std::uint64_t{5});
  CHECK_EQ(first.generation().raw(), std::uint64_t{1});
  CHECK(first.to_string() != second.to_string());

  // Identity order dominates generation order.
  CHECK(key_of(4, 9) < key_of(5, 1));
  CHECK(!(key_of(5, 1) < key_of(4, 9)));

  // Generation 0 means "no generation asserted" and never matches a concrete generation.
  const sff::SwitchKey ungenerationed(identity, sff::SwitchGeneration(0));
  CHECK(!ungenerationed.valid());
  CHECK(!sff::SwitchKey{}.valid());
  CHECK(!key_of(0, 1).valid());
  CHECK(!key_of(1, 0).valid());
  CHECK(key_of(1, 1).valid());
}

SFF_TEST(strong_id_successor_is_monotonic_and_refuses_exhaustion) {
  sff::SwitchId cursor(1);
  for (std::size_t step = 0; step < 64; ++step) {
    const sff::SwitchId next = cursor.next();
    CHECK_EQ(next.raw(), cursor.raw() + 1);
    CHECK(cursor < next);
    cursor = next;
  }

  constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();

  // The maximum value has NO successor. Exhaustion is reported as an invalid id rather than
  // handing back the maximum again (a replayed identity) or wrapping to zero-plus-one.
  const sff::SwitchId top(kMax);
  const sff::SwitchId exhausted = top.next();
  CHECK_EQ(exhausted.raw(), std::uint64_t{0});
  CHECK(!exhausted.valid());
  CHECK(exhausted != top);
  CHECK(exhausted != sff::SwitchId(1));  // exhaustion is never a fresh identity either

  // The step up to the maximum is still exact and valid.
  const sff::SwitchId penultimate(kMax - 1);
  CHECK_EQ(penultimate.next().raw(), kMax);
  CHECK(penultimate.next().valid());
  CHECK(penultimate < penultimate.next());
  CHECK_EQ(sff::SwitchId(0).next().raw(), std::uint64_t{1});
  CHECK(sff::SwitchId(0).next().valid());
}

// ---------------------------------------------------------------------------------------------
// Generation vectors
// ---------------------------------------------------------------------------------------------

SFF_TEST(generation_vector_is_canonical_and_generation_exact) {
  const sff::SwitchKey a = key_of(5, 1);
  const sff::SwitchKey b = key_of(5, 2);
  const sff::SwitchKey c = key_of(9, 1);
  const sff::SwitchKey unqualified = key_of(7, 0);

  const sff::GenerationVector vector =
      sff::GenerationVector::canonicalise({c, b, a, b, unqualified, c});
  CHECK_EQ(vector.size(), std::size_t{3});
  CHECK(vector.keys()[0] == a);
  CHECK(vector.keys()[1] == b);
  CHECK(vector.keys()[2] == c);

  CHECK(vector.contains(a));
  CHECK(vector.contains(b));
  CHECK(vector.contains(c));
  CHECK(!vector.contains(unqualified));
  CHECK(!vector.contains(key_of(5, 3)));  // the exact generation is required

  // Identity-only matching exists, is correct, and is deliberately named.
  CHECK(vector.contains_identity_deliberately(sff::SwitchId(5)));
  CHECK(vector.contains_identity_deliberately(sff::SwitchId(9)));
  CHECK(!vector.contains_identity_deliberately(sff::SwitchId(6)));

  // Insertion order can never change the digest: the set, not the history, is what is bound.
  const sff::GenerationVector forward = sff::GenerationVector::canonicalise({a, b, c});
  const sff::GenerationVector backward = sff::GenerationVector::canonicalise({c, b, a});
  CHECK(forward == backward);
  CHECK_EQ(forward.digest(), backward.digest());
  CHECK_EQ(forward.digest(), vector.digest());

  sff::GenerationVector built;
  CHECK(built.insert(c));
  CHECK(built.insert(a));
  CHECK(built.insert(b));
  CHECK(!built.insert(a));
  CHECK(!built.insert(unqualified));
  CHECK(built == vector);
  CHECK_EQ(built.digest(), vector.digest());

  const sff::GenerationVector left = sff::GenerationVector::canonicalise({a, b});
  const sff::GenerationVector right = sff::GenerationVector::canonicalise({b, c});
  const sff::GenerationVector both = left.united(right);
  CHECK(both == vector);
  CHECK_EQ(both.digest(), vector.digest());

  const sff::GenerationVector shared = left.intersected(right);
  CHECK_EQ(shared.size(), std::size_t{1});
  CHECK(shared.contains(b));
  CHECK(!shared.contains(a));
  CHECK(!shared.contains(c));

  const sff::GenerationVector stripped = vector.without_identity(sff::SwitchId(5));
  CHECK_EQ(stripped.size(), std::size_t{1});
  CHECK(stripped.contains(c));
  CHECK(!stripped.contains_identity_deliberately(sff::SwitchId(5)));
  CHECK(vector.without_identity(sff::SwitchId(1234)) == vector);

  CHECK(left.contains_all(left));
  CHECK(!left.contains_all(right));
  CHECK(vector.contains_all(left));
  CHECK(left.intersects(right));
  CHECK(!sff::GenerationVector::canonicalise({a}).intersects(
      sff::GenerationVector::canonicalise({c})));
  CHECK(sff::GenerationVector{}.empty());
  CHECK(!sff::GenerationVector{}.contains(a));
  CHECK(vector.to_string() != sff::GenerationVector{}.to_string());
}

// ---------------------------------------------------------------------------------------------
// Digest128
// ---------------------------------------------------------------------------------------------

SFF_TEST(digest128_is_order_and_content_sensitive) {
  const std::uint8_t forward_bytes[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  std::uint8_t reversed_bytes[8] = {0};
  std::uint8_t changed_bytes[8] = {0};
  for (std::size_t index = 0; index < 8; ++index) {
    reversed_bytes[index] = forward_bytes[7 - index];
    changed_bytes[index] = forward_bytes[index];
  }
  changed_bytes[3] = static_cast<std::uint8_t>(changed_bytes[3] ^ 0x01u);

  sff::Digest128 forward;
  forward.absorb_bytes(forward_bytes, sizeof(forward_bytes));
  sff::Digest128 again;
  again.absorb_bytes(forward_bytes, sizeof(forward_bytes));
  CHECK_EQ(forward.hi, again.hi);
  CHECK_EQ(forward.lo, again.lo);
  CHECK_EQ(forward.to_hex(), again.to_hex());

  sff::Digest128 stepwise;
  for (const std::uint8_t byte : forward_bytes) stepwise.absorb_byte(byte);
  CHECK_EQ(stepwise.hi, forward.hi);
  CHECK_EQ(stepwise.lo, forward.lo);

  sff::Digest128 reversed;
  reversed.absorb_bytes(reversed_bytes, sizeof(reversed_bytes));
  CHECK(reversed.hi != forward.hi || reversed.lo != forward.lo);

  sff::Digest128 changed;
  changed.absorb_bytes(changed_bytes, sizeof(changed_bytes));
  CHECK(changed.hi != forward.hi || changed.lo != forward.lo);

  // absorb_u64 and absorb_string are order sensitive too.
  sff::Digest128 first_order;
  first_order.absorb_u64(0x0123456789abcdefull);
  first_order.absorb_string("sff");
  sff::Digest128 second_order;
  second_order.absorb_string("sff");
  second_order.absorb_u64(0x0123456789abcdefull);
  CHECK(first_order.hi != second_order.hi || first_order.lo != second_order.lo);

  const std::string hex = forward.to_hex();
  CHECK_EQ(hex.size(), std::size_t{32});
  std::size_t hex_digits = 0;
  for (const char digit : hex) {
    if ((digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f')) hex_digits += 1;
  }
  CHECK_EQ(hex_digits, std::size_t{32});

  CHECK_EQ(sff::digest128_of(forward_bytes, sizeof(forward_bytes)).to_hex(), hex);
  const std::vector<std::uint8_t> bytes(forward_bytes, forward_bytes + sizeof(forward_bytes));
  CHECK_EQ(sff::digest128_of(bytes).to_hex(), hex);
  CHECK_EQ(sff::to_hex(forward), hex);

  const sff::Digest128 pristine;
  const sff::Digest128 empty = sff::digest128_of(forward_bytes, 0);
  CHECK_EQ(empty.hi, pristine.hi);
  CHECK_EQ(empty.lo, pristine.lo);
}

// ---------------------------------------------------------------------------------------------
// Checked arithmetic
// ---------------------------------------------------------------------------------------------

SFF_TEST(checked_unsigned_arithmetic_is_exact_at_the_boundaries) {
  constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();
  constexpr std::uint64_t kHalf = kMax / 2;

  CHECK(add_is<std::uint64_t>(0, 0, 0));
  CHECK(add_is<std::uint64_t>(0, kMax, kMax));
  CHECK(add_is<std::uint64_t>(kMax, 0, kMax));
  CHECK(add_is<std::uint64_t>(1, kMax - 1, kMax));
  CHECK(add_is<std::uint64_t>(kHalf, kHalf, kMax - 1));
  CHECK(add_is<std::uint64_t>(kHalf + 1, kHalf, kMax));
  CHECK(add_is<std::uint64_t>(kHalf, kHalf + 1, kMax));
  CHECK(add_refused<std::uint64_t>(kMax, 1));
  CHECK(add_refused<std::uint64_t>(1, kMax));
  CHECK(add_refused<std::uint64_t>(kMax, kMax));

  CHECK(sub_is<std::uint64_t>(0, 0, 0));
  CHECK(sub_is<std::uint64_t>(kMax, 0, kMax));
  CHECK(sub_is<std::uint64_t>(kMax, kMax, 0));
  CHECK(sub_is<std::uint64_t>(kHalf + 1, kHalf, 1));
  CHECK(sub_is<std::uint64_t>(kMax, kHalf, kHalf + 1));
  CHECK(sub_refused<std::uint64_t>(0, 1));
  CHECK(sub_refused<std::uint64_t>(kHalf, kHalf + 1));

  CHECK(mul_is<std::uint64_t>(0, kMax, 0));
  CHECK(mul_is<std::uint64_t>(kMax, 0, 0));
  CHECK(mul_is<std::uint64_t>(1, kMax, kMax));
  CHECK(mul_is<std::uint64_t>(kMax, 1, kMax));
  CHECK(mul_is<std::uint64_t>(65536, 65536, 0x100000000ull));
  CHECK(mul_refused<std::uint64_t>(kMax, 2));
  CHECK(mul_refused<std::uint64_t>(2, kMax));
  CHECK(mul_refused<std::uint64_t>(kMax, kMax));
  // 2^64-1 is odd, so the largest exact product is (kMax/2)*2 == kMax-1 and one more unit of
  // either operand overflows.
  CHECK(mul_is<std::uint64_t>(kHalf, 2, kMax - 1));
  CHECK(mul_refused<std::uint64_t>(kHalf + 1, 2));
}

SFF_TEST(checked_signed_arithmetic_is_exact_at_the_boundaries) {
  constexpr std::int64_t kMax = std::numeric_limits<std::int64_t>::max();
  constexpr std::int64_t kMin = std::numeric_limits<std::int64_t>::min();
  constexpr std::int64_t kHalf = kMax / 2;

  CHECK(add_is<std::int64_t>(0, 0, 0));
  CHECK(add_is<std::int64_t>(kMax, 0, kMax));
  CHECK(add_is<std::int64_t>(0, kMax, kMax));
  CHECK(add_is<std::int64_t>(kMax, -1, kMax - 1));
  CHECK(add_is<std::int64_t>(kMin, 0, kMin));
  CHECK(add_is<std::int64_t>(kMin, 1, kMin + 1));
  CHECK(add_is<std::int64_t>(kMin, kMax, -1));
  CHECK(add_is<std::int64_t>(kMax, kMin, -1));
  CHECK(add_is<std::int64_t>(-1, 1, 0));
  CHECK(add_is<std::int64_t>(kHalf, kHalf, kMax - 1));
  CHECK(add_refused<std::int64_t>(kMax, 1));
  CHECK(add_refused<std::int64_t>(1, kMax));
  CHECK(add_refused<std::int64_t>(kMin, -1));
  CHECK(add_refused<std::int64_t>(-1, kMin));
  CHECK(add_refused<std::int64_t>(kHalf + 1, kHalf + 1));

  CHECK(sub_is<std::int64_t>(kMin, kMin, 0));
  CHECK(sub_is<std::int64_t>(kMax, kMax, 0));
  CHECK(sub_is<std::int64_t>(kMin + 1, kMin, 1));
  CHECK(sub_is<std::int64_t>(0, kMax, -kMax));
  CHECK(sub_is<std::int64_t>(-1, kMax, kMin));
  // kMax - (kMin + 1) == 2^64 - 2 and kMax - kMin == 2^64 - 1: both are outside the range.
  CHECK(sub_refused<std::int64_t>(kMax, kMin + 1));
  CHECK(sub_refused<std::int64_t>(kMax, kMin));
  // 0 - kMax is exactly kMin + 1.
  CHECK(sub_is<std::int64_t>(0, kMax, kMin + 1));
  CHECK(sub_refused<std::int64_t>(kMin, 1));
  CHECK(sub_refused<std::int64_t>(kMax, -1));
  CHECK(sub_refused<std::int64_t>(0, kMin));
  CHECK(sub_refused<std::int64_t>(kMin, kMax));

  CHECK(mul_is<std::int64_t>(0, kMin, 0));
  CHECK(mul_is<std::int64_t>(kMin, 0, 0));
  CHECK(mul_is<std::int64_t>(1, kMin, kMin));
  CHECK(mul_is<std::int64_t>(kMin, 1, kMin));
  CHECK(mul_is<std::int64_t>(-1, -1, 1));
  CHECK(mul_is<std::int64_t>(-2, -2, 4));
  CHECK(mul_is<std::int64_t>(-1, kMax, kMin + 1));
  CHECK(mul_is<std::int64_t>(kMax, -1, kMin + 1));
  CHECK(mul_is<std::int64_t>(kMin / 2, 2, kMin));
  CHECK(mul_is<std::int64_t>(46341, 46341, 2147488281));
  CHECK(mul_refused<std::int64_t>(kMax, 2));
  CHECK(mul_refused<std::int64_t>(kMin, 2));
  CHECK(mul_refused<std::int64_t>(-1, kMin));
  CHECK(mul_refused<std::int64_t>(kMin, -1));
  CHECK(mul_refused<std::int64_t>(kMin / 2 - 1, 2));
  CHECK(mul_refused<std::int64_t>(kMin, kMin));
}

SFF_TEST(checked_arithmetic_invariants_hold_for_random_operands) {
  constexpr std::uint64_t kUnsignedMax = std::numeric_limits<std::uint64_t>::max();
  sfftest::Rng unsigned_rng(0x5ff20260101ull);
  for (std::size_t iteration = 0; iteration < 512; ++iteration) {
    const std::uint64_t a = unsigned_rng.next();
    const std::uint64_t b = unsigned_rng.next();

    const std::optional<std::uint64_t> sum = sff::checked_add(a, b);
    if (sum.has_value()) {
      CHECK_EQ(*sum, a + b);
      CHECK(*sum >= a);
      CHECK(*sum >= b);
    } else {
      CHECK(a > kUnsignedMax - b);
    }

    const std::optional<std::uint64_t> difference = sff::checked_sub(a, b);
    if (difference.has_value()) {
      CHECK_EQ(*difference, a - b);
      CHECK(*difference <= a);
    } else {
      CHECK(b > a);
    }

    const std::optional<std::uint64_t> product = sff::checked_mul(a, b);
    if (product.has_value()) {
      CHECK(b == 0 || *product / b == a);
      CHECK(a == 0 || *product / a == b);
    } else {
      CHECK(a != 0 && b != 0);
      CHECK(a > kUnsignedMax / b);
    }
  }

  constexpr std::int64_t kSignedMax = std::numeric_limits<std::int64_t>::max();
  constexpr std::uint64_t kMagnitudeLimit = static_cast<std::uint64_t>(kSignedMax) + 1;
  sfftest::Rng signed_rng(0x5ff20260102ull);
  for (std::size_t iteration = 0; iteration < 512; ++iteration) {
    const std::int64_t a = static_cast<std::int64_t>(signed_rng.next());
    const std::int64_t b = static_cast<std::int64_t>(signed_rng.next());

    const std::optional<std::int64_t> sum = sff::checked_add(a, b);
    if (sum.has_value()) {
      // Modular agreement is necessary but not sufficient; the sign cases below prove that a
      // refusal only ever happens when the exact result is genuinely out of range.
      CHECK_EQ(static_cast<std::uint64_t>(*sum) - static_cast<std::uint64_t>(a),
               static_cast<std::uint64_t>(b));
    } else if (a >= 0 && b >= 0) {
      CHECK(static_cast<std::uint64_t>(a) >
            static_cast<std::uint64_t>(kSignedMax) - static_cast<std::uint64_t>(b));
    } else if (a <= 0 && b <= 0) {
      const std::uint64_t magnitude_a = std::uint64_t{0} - static_cast<std::uint64_t>(a);
      const std::uint64_t magnitude_b = std::uint64_t{0} - static_cast<std::uint64_t>(b);
      CHECK(magnitude_a > kMagnitudeLimit - magnitude_b);
    } else {
      // Opposite signs can never overflow, so a refusal here would itself be the defect.
      CHECK(sum.has_value());
    }
  }

  CHECK(sff::checked_align_up(0, 8).value() == std::size_t{0});
  CHECK(sff::checked_align_up(1, 8).value() == std::size_t{8});
  CHECK(sff::checked_align_up(8, 8).value() == std::size_t{8});
  CHECK(!sff::checked_align_up(1, 0).has_value());
  CHECK(!sff::checked_align_up(kUnsignedMax, 8).has_value());
  CHECK_EQ(sff::narrow_size(0).value(), std::size_t{0});
  CHECK_EQ(sff::narrow_size(4096).value(), std::size_t{4096});
}

// ---------------------------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------------------------

SFF_TEST(limits_validate_accepts_defaults_and_refuses_out_of_range) {
  const sff::Limits defaults = sff::Limits::defaults();
  CHECK(defaults.validate().ok());

  // A zero field is refused: no collection may be bounded by an unusable number.
  const char* zero_fields[] = {"max_switches", "max_closure_nodes", "max_plan_steps",
                               "max_evidence_records", "max_event_records", "max_frame_payload"};
  for (std::size_t index = 0; index < 6; ++index) {
    sff::Limits limits = defaults;
    switch (index) {
      case 0: limits.max_switches = 0; break;
      case 1: limits.max_closure_nodes = 0; break;
      case 2: limits.max_plan_steps = 0; break;
      case 3: limits.max_evidence_records = 0; break;
      case 4: limits.max_event_records = 0; break;
      default: limits.max_frame_payload = 0; break;
    }
    const sff::Status status = limits.validate();
    CHECK(!status.ok());
    CHECK(status.code() == Code::Invalid);
    CHECK(status.message().find(zero_fields[index]) != std::string::npos);
  }

  sff::Limits no_freshness = defaults;
  no_freshness.freshness_window_ns = 0;
  CHECK(!no_freshness.validate().ok());
  sff::Limits no_fence_horizon = defaults;
  no_fence_horizon.fence_horizon_ns = 0;
  CHECK(!no_fence_horizon.validate().ok());

  // Above the hard ceiling is refused outright.
  sff::Limits above_elements = defaults;
  above_elements.max_switches = sff::kHardMaxElements + 1;
  CHECK(!above_elements.validate().ok());
  CHECK_EQ(above_elements.validate().code(), Code::Invalid);

  sff::Limits above_events = defaults;
  above_events.max_event_records = sff::kHardMaxEventRecords + 1;
  CHECK(!above_events.validate().ok());

  sff::Limits above_terms = defaults;
  above_terms.max_explanation_terms = sff::kHardMaxExplanationTerms + 1;
  CHECK(!above_terms.validate().ok());

  sff::Limits above_frame = defaults;
  above_frame.max_frame_payload = sff::kHardMaxFramePayload + 1;
  CHECK(!above_frame.validate().ok());

  sff::Limits above_document = defaults;
  above_document.max_document_bytes = sff::kHardMaxDocumentBytes + 1;
  CHECK(!above_document.validate().ok());

  // Internal consistency: a document bound below the frame bound is refused.
  sff::Limits inconsistent = defaults;
  inconsistent.max_frame_payload = inconsistent.max_document_bytes + 1;
  CHECK(!inconsistent.validate().ok());

  // Exactly at the ceiling is accepted.
  sff::Limits at_ceiling = defaults;
  at_ceiling.max_switches = sff::kHardMaxElements;
  at_ceiling.max_event_records = sff::kHardMaxEventRecords;
  at_ceiling.max_explanation_terms = sff::kHardMaxExplanationTerms;
  at_ceiling.max_frame_payload = sff::kHardMaxFramePayload;
  at_ceiling.max_document_bytes = sff::kHardMaxDocumentBytes;
  CHECK(at_ceiling.validate().ok());
}

SFF_TEST(refuse_exhausted_names_both_numbers) {
  const sff::Status status = sff::refuse_exhausted("max_switches", 7, 3);
  CHECK(!status.ok());
  CHECK(status.code() == Code::Exhausted);
  CHECK(sff::is_fail_closed(status.code()));
  const std::string message = status.message();
  CHECK(message.find("max_switches") != std::string::npos);
  CHECK(message.find("7") != std::string::npos);
  CHECK(message.find("3") != std::string::npos);
  CHECK(!message.empty());

  const sff::Status anonymous = sff::refuse_exhausted(nullptr, 1, 0);
  CHECK(anonymous.code() == Code::Exhausted);
  CHECK(!anonymous.message().empty());
}

// ---------------------------------------------------------------------------------------------
// Bounded event log
// ---------------------------------------------------------------------------------------------

SFF_TEST(event_log_is_bounded_and_never_reuses_a_sequence) {
  sff::ManualClock clock(1000);
  sff::EventLog log(4, &clock);

  CHECK_EQ(log.size(), std::size_t{0});
  CHECK_EQ(log.capacity(), std::size_t{4});
  CHECK_EQ(log.first_seq(), std::uint64_t{0});
  CHECK_EQ(log.last_seq(), std::uint64_t{0});
  CHECK_EQ(log.dropped(), std::uint64_t{0});

  for (std::size_t index = 0; index < 10; ++index) {
    clock.advance(10);
    log.append(sff::EventKind::RuntimeBooted, Code::Ok, "record",
               static_cast<std::uint64_t>(index), 1);
    const std::uint64_t expected_seq = static_cast<std::uint64_t>(index) + 1;
    CHECK_EQ(log.last_seq(), expected_seq);
    CHECK(log.size() <= log.capacity());
    CHECK_EQ(log.dropped(), expected_seq > 4 ? expected_seq - 4 : 0);
    CHECK_EQ(log.size() + log.dropped(), expected_seq);
  }

  CHECK_EQ(log.size(), std::size_t{4});
  CHECK_EQ(log.dropped(), std::uint64_t{6});
  CHECK_EQ(log.first_seq(), std::uint64_t{7});
  CHECK_EQ(log.last_seq(), std::uint64_t{10});

  const std::vector<sff::EventRecord> tail = log.tail(64);
  CHECK_EQ(tail.size(), std::size_t{4});
  for (std::size_t index = 0; index < tail.size(); ++index) {
    CHECK_EQ(tail[index].seq, std::uint64_t{7} + index);
    CHECK(tail[index].code == Code::Ok);
    if (index != 0) CHECK(tail[index - 1].seq < tail[index].seq);
  }
  CHECK_EQ(log.tail(2).size(), std::size_t{2});
  CHECK_EQ(log.tail(2)[0].seq, std::uint64_t{9});
  CHECK_EQ(log.tail(0).size(), std::size_t{0});

  const std::uint64_t before_clear = log.last_seq();
  log.clear();
  CHECK_EQ(log.size(), std::size_t{0});
  CHECK_EQ(log.first_seq(), std::uint64_t{0});
  CHECK_EQ(log.last_seq(), std::uint64_t{0});

  clock.advance(10);
  log.append(sff::EventKind::RuntimeBooted, Code::Ok, "after clear");
  CHECK(log.last_seq() > before_clear);  // a sequence number is never reused

  const std::string oversized(std::size_t{2048}, 'z');
  log.append(sff::EventKind::Refused, Code::Exhausted, oversized);
  const std::vector<sff::EventRecord> last = log.tail(1);
  CHECK_EQ(last.size(), std::size_t{1});
  CHECK_EQ(last[0].text.size(), sff::kMaxMessageBytes);
  CHECK(last[0].code == Code::Exhausted);

  // Shrinking retention evicts the oldest records and reports the eviction.
  log.set_capacity(1);
  CHECK_EQ(log.capacity(), std::size_t{1});
  CHECK_EQ(log.size(), std::size_t{1});
  CHECK(log.dropped() >= 1);
  CHECK_EQ(log.first_seq(), log.last_seq());
  log.set_capacity(0);  // clamped, never zero-sized
  CHECK_EQ(log.capacity(), std::size_t{1});
  CHECK_EQ(log.size(), std::size_t{1});
}

// ---------------------------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------------------------

SFF_TEST(manual_clock_is_strictly_monotonic_under_advance) {
  sff::ManualClock clock(1000);
  CHECK_EQ(clock.now_ns(), std::uint64_t{1000});

  sfftest::Rng rng(0x5ff20260103ull);
  std::uint64_t previous = clock.now_ns();
  for (std::size_t iteration = 0; iteration < 256; ++iteration) {
    const std::uint64_t delta = rng.bounded(1000) + 1;
    clock.advance(delta);
    const std::uint64_t now = clock.now_ns();
    CHECK(now > previous);
    CHECK_EQ(now - previous, delta);
    previous = now;
  }

  sff::ManualClock defaulted;
  CHECK_EQ(defaulted.now_ns(), std::uint64_t{1000});
  defaulted.advance(1);
  CHECK_EQ(defaulted.now_ns(), std::uint64_t{1001});
}

SFF_MAIN()
