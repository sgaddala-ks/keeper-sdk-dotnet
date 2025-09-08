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
using System.Text.Json;
using System.Text;
using System.Threading.Tasks;
using Fido2NetLib;
using Fido2NetLib.Objects;
using KeeperBiometric.Platforms;
using KeeperBiometric.Utils;
using KeeperSecurity.Vault;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using Authentication;

namespace KeeperBiometric
{
    /// <summary>
    /// WebAuthn origin scheme constant
    /// </summary>
    public static class WebAuthnConstants
    {
        public const string WEBAUTHN_ORIGIN_SCHEME = "https";
    }

    /// <summary>
    /// Main client for biometric authentication operations
    /// </summary>
    public class BiometricClient
    {
        private readonly BiometricDetector _detector;
        private PlatformHandler _platformHandler;
        private readonly object _keeperAuth; // IKeeperAuth interface from KeeperSDK

        /// <summary>
        /// Get the current platform handler
        /// </summary>
        public PlatformHandler PlatformHandler => _platformHandler;

        /// <summary>
        /// Get the biometric detector instance
        /// </summary>
        public BiometricDetector Detector => _detector;

        /// <summary>
        /// Get the keeper authentication instance
        /// </summary>
        public object KeeperAuth => _keeperAuth;

        /// <summary>
        /// Initialize the BiometricClient with KeeperAuth
        /// </summary>
        /// <param name="keeperAuth">IKeeperAuth instance for API communication</param>
        public BiometricClient(object keeperAuth)
        {
            _keeperAuth = keeperAuth ?? throw new ArgumentNullException(nameof(keeperAuth));
            _detector = new BiometricDetector();
            _platformHandler = null;
            InitializePlatformHandler();
        }

        /// <summary>
        /// Initialize platform-specific handler
        /// </summary>
        private void InitializePlatformHandler()
        {
            try
            {
                _platformHandler = _detector.GetPlatformHandler();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"WARNING: Failed to initialize platform handler: {ex.Message}");
            }
        }

        /// <summary>
        /// Check if biometric authentication is available on this platform
        /// </summary>
        /// <returns>True if biometric authentication is supported</returns>
        public bool IsBiometricAvailable()
        {
            if (_platformHandler == null)
            {
                return false;
            }

            var (supported, message) = _platformHandler.DetectCapabilities();
            if (!supported)
            {
                Console.WriteLine($"DEBUG: Biometric not available: {message}");
            }
            
            return supported;
        }

        /// <summary>
        /// Get platform capabilities information
        /// </summary>
        /// <returns>Tuple with support status and descriptive message</returns>
        public (bool supported, string message) GetPlatformCapabilities()
        {
            if (_platformHandler == null)
            {
                return (false, "No platform handler available");
            }

            return _platformHandler.DetectCapabilities();
        }

        /// <summary>
        /// Check if biometric credentials exist for a user
        /// </summary>
        /// <param name="username">Username to check</param>
        /// <returns>True if biometric credentials exist for the user</returns>
        public bool HasBiometricCredentials(string username)
        {
            if (_platformHandler == null)
            {
                return false;
            }

            var storageHandler = _platformHandler.GetStorageHandler();
            return storageHandler?.GetBiometricFlag(username) ?? false;
        }

        /// <summary>
        /// Create a WebAuthn client for platform operations
        /// </summary>
        /// <param name="dataCollector">Optional data collector for client configuration</param>
        /// <returns>Configured WebAuthn client</returns>
        public IFido2 CreateWebAuthnClient(object dataCollector = null)
        {
            if (_platformHandler == null)
            {
                throw new InvalidOperationException("No platform handler available for WebAuthn operations");
            }

            return _platformHandler.CreateWebAuthnClient(dataCollector);
        }

        /// <summary>
        /// Get the current platform name
        /// </summary>
        /// <returns>Platform name or "Unknown" if no handler is available</returns>
        public string GetPlatformName()
        {
            if (_platformHandler == null)
            {
                return "Unknown";
            }

            // This would be implemented differently per platform
            // For now, return a generic response
            return "Biometric Platform";
        }

        /// <summary>
        /// Handle credential creation options for the current platform
        /// </summary>
        /// <param name="creationOptions">Credential creation options</param>
        /// <returns>Platform-specific processed options</returns>
        public Dictionary<string, object> HandleCredentialCreation(Dictionary<string, object> creationOptions)
        {
            if (_platformHandler == null)
            {
                throw new InvalidOperationException("No platform handler available");
            }

            return _platformHandler.HandleCredentialCreation(creationOptions);
        }

        /// <summary>
        /// Handle authentication options for the current platform
        /// </summary>
        /// <param name="authOptions">Authentication options</param>
        /// <returns>Platform-specific processed options</returns>
        public Dictionary<string, object> HandleAuthenticationOptions(Dictionary<string, object> authOptions)
        {
            if (_platformHandler == null)
            {
                throw new InvalidOperationException("No platform handler available");
            }

            return _platformHandler.HandleAuthenticationOptions(authOptions);
        }

        /// <summary>
        /// Store biometric credentials for a user
        /// </summary>
        /// <param name="username">Username to store credentials for</param>
        /// <param name="credentialId">Credential ID to store</param>
        /// <returns>True if credentials were stored successfully</returns>
        public bool StoreBiometricCredentials(string username, string credentialId)
        {
            if (_platformHandler == null)
            {
                return false;
            }

            var storageHandler = _platformHandler.GetStorageHandler();
            if (storageHandler == null)
            {
                return false;
            }

            // Set biometric flag and store credential ID if the storage handler supports it
            var flagSet = storageHandler.SetBiometricFlag(username, true);
            
            // If storage handler has credential ID storage capability, use it
            if (storageHandler is Platforms.WindowsStorageHandler windowsStorage)
            {
                return windowsStorage.StoreCredentialId(username, credentialId);
            }

            return flagSet;
        }

        /// <summary>
        /// Remove biometric credentials for a user
        /// </summary>
        /// <param name="username">Username to remove credentials for</param>
        /// <returns>True if credentials were removed successfully</returns>
        public bool RemoveBiometricCredentials(string username)
        {
            if (_platformHandler == null)
            {
                return false;
            }

            var storageHandler = _platformHandler.GetStorageHandler();
            return storageHandler?.DeleteBiometricFlag(username) ?? false;
        }

        /// <summary>
        /// Get stored credential ID for a user
        /// </summary>
        /// <param name="username">Username to get credential ID for</param>
        /// <returns>Stored credential ID or null if not found</returns>
        public string GetCredentialId(string username)
        {
            if (_platformHandler == null)
            {
                return null;
            }

            var storageHandler = _platformHandler.GetStorageHandler();
            
            // If storage handler has credential ID retrieval capability, use it
            if (storageHandler is Platforms.WindowsStorageHandler windowsStorage)
            {
                return windowsStorage.GetCredentialId(username);
            }

            // Fallback: if biometric flag exists, return a default credential ID
            if (storageHandler?.GetBiometricFlag(username) == true)
            {
                return $"biometric_{username}_{DateTime.UtcNow.Ticks}";
            }

            return null;
        }

        /// <summary>
        /// Generate registration options from Keeper API
        /// </summary>
        /// <returns>Dictionary containing challenge token and creation options</returns>
        public async Task<Dictionary<string, object>> GenerateRegistrationOptions(VaultOnline vault)
        {
            try
            {
                var request = new PasskeyRegistrationRequest();
                request.AuthenticatorAttachment = Authentication.AuthenticatorAttachment.Platform;
                
                var response = await vault.Auth.ExecuteAuthRest<PasskeyRegistrationRequest, PasskeyRegistrationResponse>(
                    "authentication/passkey/generate_registration",request);
                
                return new Dictionary<string, object>
                {
                    ["challenge_token"] = response.ChallengeToken,
                    ["creation_options"] = JsonUtils.ParseJson<Dictionary<string, object>>(Encoding.UTF8.GetBytes(response.PkCreationOptions))
                };
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to generate registration options: {ex.Message}", ex);
            }
        }

       
    }
}
