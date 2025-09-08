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
    /// AAGUID (Authenticator Attestation GUID) related constants and utilities.
    /// These constants help identify the specific authenticator/provider used for WebAuthn credentials.
    /// </summary>
    public static class AaguidHelper
    {
        /// <summary>
        /// AAGUID to provider name mapping
        /// Based on community-sourced data from https://github.com/passkeydeveloper/passkey-authenticator-aaguids
        /// </summary>
        public static readonly Dictionary<string, string> AAGUID_PROVIDER_MAPPING = new()
        {
            ["ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4"] = "Google Password Manager",
            ["adce0002-35bc-c60a-648b-0b25f1f05503"] = "Chrome on Mac",
            ["fbfc3007-154e-4ecc-8c0b-6e020557d7bd"] = "iCloud Keychain",
            ["dd4ec289-e01d-41c9-bb89-70fa845d4bf2"] = "iCloud Keychain (Managed)",
            ["08987058-cadc-4b81-b6e1-30de50dcbe96"] = "Windows Hello",
            ["9ddd1817-af5a-4672-a2b9-3e3dd95000a9"] = "Windows Hello",
            ["6028b017-b1d4-4c02-b4b3-afcdafc96bb2"] = "Windows Hello",
            ["00000000-0000-0000-0000-000000000000"] = "Platform Authenticator"
        };

        /// <summary>
        /// Get friendly provider name from AAGUID
        /// </summary>
        /// <param name="aaguid">AAGUID string (with or without dashes)</param>
        /// <returns>Friendly provider name, or null if not found or invalid AAGUID</returns>
        public static string GetProviderNameFromAaguid(string aaguid)
        {
            if (string.IsNullOrEmpty(aaguid))
                return null;

            // Normalize AAGUID format (ensure lowercase, with dashes)
            var normalizedAaguid = aaguid.ToLowerInvariant();
            
            // If no dashes and exactly 32 characters, add dashes in proper positions
            if (normalizedAaguid.Length == 32 && !normalizedAaguid.Contains("-"))
            {
                normalizedAaguid = $"{normalizedAaguid.Substring(0, 8)}-" +
                                  $"{normalizedAaguid.Substring(8, 4)}-" +
                                  $"{normalizedAaguid.Substring(12, 4)}-" +
                                  $"{normalizedAaguid.Substring(16, 4)}-" +
                                  $"{normalizedAaguid.Substring(20)}";
            }

            return AAGUID_PROVIDER_MAPPING.GetValueOrDefault(normalizedAaguid);
        }

        /// <summary>
        /// Check if AAGUID is valid format
        /// </summary>
        /// <param name="aaguid">AAGUID string to validate</param>
        /// <returns>True if AAGUID is in valid format</returns>
        public static bool IsValidAaguid(string aaguid)
        {
            if (string.IsNullOrEmpty(aaguid))
                return false;

            // Check if it's 32 characters without dashes or standard GUID format with dashes
            if (aaguid.Length == 32 && !aaguid.Contains("-"))
            {
                // All hex characters
                foreach (char c in aaguid)
                {
                    if (!Uri.IsHexDigit(c))
                        return false;
                }
                return true;
            }
            
            // Check standard GUID format with dashes (36 characters)
            if (aaguid.Length == 36)
            {
                return Guid.TryParse(aaguid, out _);
            }

            return false;
        }

        /// <summary>
        /// Convert AAGUID to standard GUID format with dashes
        /// </summary>
        /// <param name="aaguid">AAGUID string (with or without dashes)</param>
        /// <returns>AAGUID in standard GUID format, or null if invalid</returns>
        public static string NormalizeAaguid(string aaguid)
        {
            if (string.IsNullOrEmpty(aaguid))
                return null;

            var normalizedAaguid = aaguid.ToLowerInvariant();
            
            // If no dashes and exactly 32 characters, add dashes
            if (normalizedAaguid.Length == 32 && !normalizedAaguid.Contains("-"))
            {
                if (!IsValidAaguid(normalizedAaguid))
                    return null;

                normalizedAaguid = $"{normalizedAaguid.Substring(0, 8)}-" +
                                  $"{normalizedAaguid.Substring(8, 4)}-" +
                                  $"{normalizedAaguid.Substring(12, 4)}-" +
                                  $"{normalizedAaguid.Substring(16, 4)}-" +
                                  $"{normalizedAaguid.Substring(20)}";
            }
            else if (normalizedAaguid.Length == 36)
            {
                // Validate existing format
                if (!IsValidAaguid(normalizedAaguid))
                    return null;
            }
            else
            {
                return null; // Invalid length
            }

            return normalizedAaguid;
        }

        /// <summary>
        /// Get all known provider names
        /// </summary>
        /// <returns>Collection of all known provider names</returns>
        public static IEnumerable<string> GetAllProviderNames()
        {
            return AAGUID_PROVIDER_MAPPING.Values;
        }

        /// <summary>
        /// Get all known AAGUIDs
        /// </summary>
        /// <returns>Collection of all known AAGUIDs</returns>
        public static IEnumerable<string> GetAllAaguids()
        {
            return AAGUID_PROVIDER_MAPPING.Keys;
        }

        /// <summary>
        /// Check if AAGUID corresponds to Windows Hello
        /// </summary>
        /// <param name="aaguid">AAGUID to check</param>
        /// <returns>True if AAGUID is for Windows Hello</returns>
        public static bool IsWindowsHello(string aaguid)
        {
            var providerName = GetProviderNameFromAaguid(aaguid);
            return providerName == "Windows Hello";
        }

        /// <summary>
        /// Check if AAGUID corresponds to iCloud Keychain
        /// </summary>
        /// <param name="aaguid">AAGUID to check</param>
        /// <returns>True if AAGUID is for iCloud Keychain</returns>
        public static bool IsICloudKeychain(string aaguid)
        {
            var providerName = GetProviderNameFromAaguid(aaguid);
            return providerName != null && providerName.Contains("iCloud Keychain");
        }

        /// <summary>
        /// Check if AAGUID corresponds to Chrome/Google authenticator
        /// </summary>
        /// <param name="aaguid">AAGUID to check</param>
        /// <returns>True if AAGUID is for Chrome or Google authenticator</returns>
        public static bool IsGoogleChrome(string aaguid)
        {
            var providerName = GetProviderNameFromAaguid(aaguid);
            return providerName != null && (providerName.Contains("Google") || providerName.Contains("Chrome"));
        }

        /// <summary>
        /// Check if AAGUID corresponds to a platform authenticator
        /// </summary>
        /// <param name="aaguid">AAGUID to check</param>
        /// <returns>True if AAGUID is for a platform authenticator</returns>
        public static bool IsPlatformAuthenticator(string aaguid)
        {
            var providerName = GetProviderNameFromAaguid(aaguid);
            return providerName == "Platform Authenticator" || 
                   IsWindowsHello(aaguid) || 
                   IsICloudKeychain(aaguid);
        }
    }
}
