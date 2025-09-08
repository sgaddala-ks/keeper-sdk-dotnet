//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper Commander
// Copyright 2025 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System;
using System.Collections.Generic;

namespace KeeperBiometric.Utils
{
    /// <summary>
    /// Constants and configuration values for biometric operations
    /// </summary>
    public static class BiometricConstants
    {
        // Default timeout value for all biometric operations (in seconds)
        public const uint DEFAULT_BIOMETRIC_TIMEOUT = 60;

        // Platform/System constants
        public const string PLATFORM_WINDOWS = "Windows";
        public const string PLATFORM_DARWIN = "Darwin";

        // HTTP Status codes
        public const int STATUS_SUCCESS = 200;      // OK
        public const int STATUS_NOT_FOUND = 404;    // Not Found
        public const int STATUS_BAD_REQUEST = 400;  // Bad Request
        public const int STATUS_ERROR = 500;        // Internal Server Error

        /// <summary>
        /// Status code to readable message mapping
        /// </summary>
        public static readonly Dictionary<int, string> STATUS_MESSAGES = new()
        {
            [STATUS_SUCCESS] = "Success",
            [STATUS_NOT_FOUND] = "Not Found",
            [STATUS_BAD_REQUEST] = "Bad Request",
            [STATUS_ERROR] = "Error"
        };

        /// <summary>
        /// Get readable message for HTTP status code
        /// </summary>
        /// <param name="statusCode">HTTP status code</param>
        /// <returns>Readable message for the status code</returns>
        public static string GetStatusMessage(int statusCode)
        {
            return STATUS_MESSAGES.GetValueOrDefault(statusCode, $"Unknown Status ({statusCode})");
        }

        /// <summary>
        /// Check if status code indicates success (2xx range)
        /// </summary>
        /// <param name="statusCode">HTTP status code</param>
        /// <returns>True if status indicates success</returns>
        public static bool IsSuccessStatus(int statusCode)
        {
            return statusCode >= 200 && statusCode < 300;
        }

        /// <summary>
        /// API Endpoints for passkey operations
        /// </summary>
        public static readonly Dictionary<string, string> API_ENDPOINTS = new()
        {
            ["generate_registration"] = "authentication/passkey/generate_registration",
            ["verify_registration"] = "authentication/passkey/verify_registration",
            ["generate_authentication"] = "authentication/passkey/generate_authentication",
            ["verify_authentication"] = "authentication/passkey/verify_authentication",
            ["get_available_keys"] = "authentication/passkey/get_available_keys",
            ["disable_passkey"] = "authentication/passkey/disable",
            ["update_passkey_name"] = "authentication/passkey/update_friendly_name"
        };

        /// <summary>
        /// API Response Messages
        /// </summary>
        public static readonly Dictionary<string, string> API_RESPONSE_MESSAGES = new()
        {
            ["passkey_disabled_success"] = "Passkey was successfully disabled and no longer available for login",
            ["passkey_name_updated_success"] = "Passkey friendly name was successfully updated",
            ["disable_bad_request"] = "Unable to disable. Data error. Credential ID or UserID mismatch",
            ["update_bad_request"] = "Unable to update. Data error. Credential ID or UserID mismatch",
            ["server_exception"] = "Unexpected server exception"
        };

        /// <summary>
        /// Default authenticator selection criteria
        /// </summary>
        public static readonly Dictionary<string, string> AUTHENTICATOR_SELECTION = new()
        {
            ["authenticatorAttachment"] = "platform",
            ["userVerification"] = "required"
        };

        /// <summary>
        /// Storage paths and service names
        /// </summary>
        public static class StoragePaths
        {
            public const string WINDOWS_REGISTRY_PATH = @"SOFTWARE\Keeper Security\Commander\Biometric";
            public const string MACOS_PREFS_PATH = "com.keepersecurity.commander.biometric.plist";
            public const string MACOS_KEYCHAIN_SERVICE_PREFIX = "Keeper WebAuthn";
        }

        /// <summary>
        /// Check if FIDO2 dependencies are available
        /// </summary>
        public static bool FIDO2_AVAILABLE => CheckFido2Availability();

        /// <summary>
        /// Check if FIDO2 library components are available
        /// </summary>
        /// <returns>True if FIDO2 dependencies are available</returns>
        private static bool CheckFido2Availability()
        {
            try
            {
                // Check if main Fido2NetLib is available
                var fido2Type = typeof(Fido2NetLib.Fido2);
                return fido2Type != null;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Error messages for biometric operations
        /// </summary>
        public static readonly Dictionary<string, string> ERROR_MESSAGES = new()
        {
            ["no_fido2"] = "FIDO2 library not available. Please install: Install-Package Fido2.NetFramework",
            ["platform_not_supported"] = "Biometric authentication not supported on this platform",
            ["no_credentials"] = "No biometric credentials found. Please register first using \"biometric register\"",
            ["authentication_cancelled"] = "Biometric authentication was cancelled",
            ["authentication_timeout"] = "Biometric authentication timed out",
            ["authentication_failed"] = "Biometric authentication failed",
            ["registration_failed"] = "Biometric registration failed",
            ["verification_failed"] = "Biometric verification failed",
            ["credential_exists"] = "A biometric credential for this account already exists. Use \"biometric unregister\" first.",
            ["credential_already_registered"] = "A biometric credential for this account already exists. Use \"biometric unregister\" first.",
            ["keychain_store_failed"] = "Failed to store credential in keychain",
            ["touchid_not_available"] = "Touch ID is not available or configured",
            ["windows_hello_not_setup"] = "Windows Hello is available but not yet set up. Please complete the setup in Windows Settings > Accounts > Sign-In options, then try running this command again.",
            ["no_matching_credential"] = "No matching credential found in keychain"
        };

        /// <summary>
        /// Success messages for biometric operations
        /// </summary>
        public static readonly Dictionary<string, string> SUCCESS_MESSAGES = new()
        {
            ["registration_complete"] = "Biometric authentication completed successfully!",
            ["unregistration_complete"] = "Biometric authentication has been completely removed",
            ["verification_success"] = "Your biometric authentication is working correctly!",
            ["credential_disabled"] = "Passkey was successfully disabled and no longer available for login"
        };

        /// <summary>
        /// Default credential name template
        /// </summary>
        public const string CREDENTIAL_NAME_TEMPLATE = "Commander CLI ({hostname})";

        /// <summary>
        /// Common authentication reasons
        /// </summary>
        public static readonly Dictionary<string, string> AUTH_REASONS = new()
        {
            ["register"] = "Register biometric authentication for {rp_id}",
            ["login"] = "Authenticate with Keeper for {rp_id}",
            ["verification"] = "Verify biometric authentication for {rp_id}"
        };

        /// <summary>
        /// Format authentication reason with actual RP ID
        /// </summary>
        /// <param name="reasonKey">Reason key from AUTH_REASONS</param>
        /// <param name="rpId">Relying Party ID</param>
        /// <returns>Formatted authentication reason</returns>
        public static string FormatAuthReason(string reasonKey, string rpId)
        {
            var template = AUTH_REASONS.GetValueOrDefault(reasonKey, "Authenticate for {rp_id}");
            return template.Replace("{rp_id}", rpId);
        }

        /// <summary>
        /// Format credential name template with hostname
        /// </summary>
        /// <param name="hostname">Hostname to use in credential name</param>
        /// <returns>Formatted credential name</returns>
        public static string FormatCredentialName(string hostname)
        {
            return CREDENTIAL_NAME_TEMPLATE.Replace("{hostname}", hostname);
        }
    }

    /// <summary>
    /// Platform-specific constants and utilities
    /// </summary>
    public static class PlatformConstants
    {
        /// <summary>
        /// Get current platform name
        /// </summary>
        /// <returns>Platform name string</returns>
        public static string GetCurrentPlatform()
        {
            if (OperatingSystem.IsWindows())
                return BiometricConstants.PLATFORM_WINDOWS;
            else if (OperatingSystem.IsMacOS())
                return BiometricConstants.PLATFORM_DARWIN;
            else
                return Environment.OSVersion.Platform.ToString();
        }

        /// <summary>
        /// Check if current platform is Windows
        /// </summary>
        /// <returns>True if running on Windows</returns>
        public static bool IsWindows()
        {
            return OperatingSystem.IsWindows();
        }

        /// <summary>
        /// Check if current platform is macOS
        /// </summary>
        /// <returns>True if running on macOS</returns>
        public static bool IsMacOS()
        {
            return OperatingSystem.IsMacOS();
        }
    }

    /// <summary>
    /// Timeout constants for various operations
    /// </summary>
    public static class TimeoutConstants
    {
        /// <summary>
        /// Default biometric timeout in milliseconds
        /// </summary>
        public static readonly uint DEFAULT_BIOMETRIC_TIMEOUT_MS = BiometricConstants.DEFAULT_BIOMETRIC_TIMEOUT * 1000;

        /// <summary>
        /// Short timeout for quick operations (15 seconds)
        /// </summary>
        public const uint SHORT_TIMEOUT = 15;

        /// <summary>
        /// Long timeout for complex operations (120 seconds)
        /// </summary>
        public const uint LONG_TIMEOUT = 120;

        /// <summary>
        /// Convert seconds to milliseconds
        /// </summary>
        /// <param name="seconds">Seconds to convert</param>
        /// <returns>Milliseconds</returns>
        public static uint SecondsToMilliseconds(uint seconds)
        {
            return seconds * 1000;
        }
    }
}
