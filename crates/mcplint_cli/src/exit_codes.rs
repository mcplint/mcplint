/// Exit code constants for CI-predictable behavior.
///
/// Convention:
///   0 — Success. No findings above threshold.
///   1 — Operational error. Bad input, parse failure, misconfiguration.
///   2 — Policy violation. Findings or drift detected above threshold.
pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_VIOLATION: i32 = 2;
