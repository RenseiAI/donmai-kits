---
name: swift-testing
description: Author and debug Swift tests — Swift Testing units, XCUITest UI flows, snapshot regressions, and Swift 6 strict-concurrency data-race errors. Use when swift/xcodebuild test commands fail, snapshots mismatch, UI tests flake, or the compiler reports a data race.
license: MIT
metadata:
  author: donmai
  version: "1.0.0"
---

# Swift Testing

## Overview

Authoring and debugging Swift tests across the full stack: Swift Testing for
unit-level logic, XCUITest for UI flows, swift-snapshot-testing for view
regression, and diagnosing the Swift 6 strict-concurrency compile errors that
block all three.

## Triggers

Use this skill when:
- `swift test` fails, or a `@Test` reports a failed `#expect`/`#require`
- A snapshot-testing assertion mismatches a reference image
- An XCUITest flakes or fails to find an element
- The compiler reports a strict-concurrency / data-race error (Swift 6)
- A test or type builds on macOS but fails to build on the Linux cloud lane

## Debugging / Authoring Workflow

### 1. Writing Swift Testing Tests

Prefer Swift Testing over XCTest for new unit tests — it runs on both Apple
platforms and Linux, so logic tests stay portable:

```swift
import Testing
@testable import MyModule

@Test("adds two positive numbers")
func addsPositiveNumbers() {
  #expect(add(2, 3) == 5)
}

@Test("parses valid and invalid input", arguments: [
  ("42", 42), ("0", 0), ("-7", -7),
])
func parsesInt(input: String, expected: Int) throws {
  let parsed = try #require(Int(input))
  #expect(parsed == expected)
}
```

- `#expect` records a failure and keeps running the test; `#require` throws
  and stops the test immediately — use `#require` when a later expectation
  would crash without the value (e.g. unwrapping an `Optional`)
- `@Test(arguments:)` parameterizes a test over a collection without hand
  writing a loop; each element becomes its own reported test case
- Traits (`.disabled("reason")`, `.tags(.regression)`, `.timeLimit(...)`)
  attach metadata without extra boilerplate
- Keep testable logic in a plain SPM module (no UIKit/SwiftUI import) so it
  also runs on the Linux CI lane; Apple-only code needs the macOS lane

### 2. The Structured-Output Agent Loop

Run tests with combined output captured, read the failures, fix, re-run:

```
swift test 2>&1 | tee /tmp/swift-test.log
grep -E "error:|failed|Test .* recorded an issue" /tmp/swift-test.log | head -40
```

Read the FIRST failure's file:line and message — Swift Testing prints the
exact `#expect` expression and its evaluated operands, so the diagnostic
usually states the fix directly. Fix one failure, re-run, repeat rather than
trying to fix every reported failure from a single stale log.

### 3. XCUITest Conventions

- **Accessibility identifiers are the contract.** Query elements by
  `.accessibilityIdentifier`, never by label text (which localizes/changes) —
  set identifiers explicitly in the view (`.accessibilityIdentifier("loginButton")`)
  so agent-authored tests have a stable, intentional hook
- Disable animations for determinism: launch with
  `app.launchArguments += ["-UITestDisableAnimations", "YES"]` or set
  `UIView.setAnimationsEnabled(false)` in a test-only launch hook — animations
  are the single biggest source of XCUITest flakiness
- On failure, Xcode attaches screenshots into the run's `.xcresult` bundle;
  extract them for inspection without opening Xcode:
  ```
  xcrun xcresulttool export attachments --path Result.xcresult \
    --output-path /tmp/xcuitest-failures --only-failures
  ```
- Wait on `XCUIElement.waitForExistence(timeout:)` before interacting; a bare
  `.tap()` on an element that hasn't appeared yet is a common flake source

### 4. Snapshot Testing Rules

- References must be compared on the **same simulator OS version, device
  model, color gamut, and display scale** that recorded them — a different
  simulator runtime renders fonts/hairlines differently and produces false
  mismatches unrelated to the code change
- Pin the recording/verifying simulator explicitly in CI (exact runtime
  identifier, not "latest") so the reference images stay reproducible
- Run CI in `.never` record mode — a CI run must never silently record a new
  reference; only a deliberate local run with recording enabled updates
  snapshots, and the diff is then reviewed like any other code change
- A mismatch failure attaches the reference, the failure, and a diff image —
  inspect the diff first; a one-pixel anti-aliasing diff is a runtime
  mismatch, a structural diff is a real regression

### 5. Diagnosing Strict-Concurrency Errors

Under Swift 6, data races are compile errors, not runtime crashes — the
compiler names the isolation domain it thinks is violated:

```
swift build 2>&1 | grep -A3 "error: .*[Ss]endable\|error: .*actor-isolated"
```

- Read which actor/isolation the compiler names (`main actor`, `nonisolated`,
  a custom global actor) — the fix is almost always one of:
  - mark the type or function `@MainActor` if it only ever touches UI state
  - mark the function `nonisolated` if it does not touch actor-isolated state
    and should be callable from any context
  - make the crossing type conform to `Sendable` (usually via `struct`/`enum`
    value types, or `final class` + `Sendable` with all-`let` storage)
- `@Model` / `ModelContext` (SwiftData) types are never `Sendable` — do not
  try to satisfy the compiler by force-casting or `@unchecked Sendable`;
  instead pass the `PersistentIdentifier` across the actor boundary and
  re-fetch the model from a `ModelContext` local to the receiving actor
- Prefer fixing the isolation over reaching for `@unchecked Sendable` —
  it silences the compiler but reintroduces the exact race strict
  concurrency exists to catch

## Notes

- Logic-module tests (`swift test` on pure-Swift targets) run on the Linux
  cloud lane. XCUITest, snapshot tests against a simulator, and any target
  importing UIKit/SwiftUI/SwiftData/ActivityKit require the macOS-pool lane.
