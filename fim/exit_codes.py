"""CLI exit codes for scripting and automation."""

EXIT_SUCCESS = 0
EXIT_CHANGES_DETECTED = 1
EXIT_CONFIG_ERROR = 2
EXIT_DATABASE_ERROR = 3
EXIT_SCAN_ERROR = 4
EXIT_APPLICATION_ERROR = 5

EXIT_CODE_DESCRIPTIONS = {
    EXIT_SUCCESS: "Success, no changes detected (scan) or command completed successfully",
    EXIT_CHANGES_DETECTED: "Changes detected during scan",
    EXIT_CONFIG_ERROR: "Configuration error",
    EXIT_DATABASE_ERROR: "Database error",
    EXIT_SCAN_ERROR: "Scan error",
    EXIT_APPLICATION_ERROR: "Other controlled application error",
}
