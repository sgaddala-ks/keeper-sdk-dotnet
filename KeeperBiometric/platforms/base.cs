using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Fido2NetLib;
using Fido2NetLib.Objects;
using KeeperBiometric.Utils;

namespace KeeperBiometric.Platforms
{

    /// <summary>
    /// Abstract base class for platform-specific biometric handlers
    /// </summary>

    public abstract class PlatformHandler : IDisposable
    {
        /// <summary>
        /// Detect biometric capabilities for this platform
        /// </summary>
        /// <returns>Tuple indicating if capabilities are supported and descriptive message</returns>
        public abstract (bool supported, string message) DetectCapabilities();

        /// <summary>
        /// Create platform-specific WebAuthn client
        /// </summary>
        /// <param name="dataCollector">Data collector for client configuration</param>
        /// <returns>Configured WebAuthn client</returns>
        public abstract IFido2 CreateWebAuthnClient(object dataCollector = null);

        /// <summary>
        /// Handle platform-specific credential creation options
        /// </summary>
        /// <param name="creationOptions">Creation options to be processed</param>
        /// <returns>Processed creation options</returns>
        public abstract Dictionary<string, object> HandleCredentialCreation(Dictionary<string, object> creationOptions);

        /// <summary>
        /// Handle platform-specific authentication options  
        /// </summary>
        /// <param name="authOptions">Authentication options to be processed</param>
        /// <returns>Processed authentication options</returns>
        public abstract Dictionary<string, object> HandleAuthenticationOptions(Dictionary<string, object> authOptions);

        /// <summary>
        /// Get the storage handler for this platform
        /// </summary>
        /// <returns>Storage handler instance</returns>
        public abstract StorageHandler GetStorageHandler();

        /// <summary>
        /// Perform platform-specific authentication
        /// </summary>
        /// <param name="client">WebAuthn client</param>
        /// <param name="options">Public key credential request options</param>
        /// <returns>Authentication result</returns>
        public abstract Task<AuthenticatorAssertionRawResponse> PerformAuthentication(
            IFido2 client, 
            AssertionOptions options);

        /// <summary>
        /// Perform platform-specific credential creation
        /// </summary>
        /// <param name="client">WebAuthn client</param>
        /// <param name="options">Public key credential creation options</param>
        /// <returns>Credential creation result</returns>
        public abstract Task<AuthenticatorAttestationRawResponse> PerformCredentialCreation(
            IFido2 client, 
            CredentialCreateOptions options);

        /// <summary>
        /// Get default timeout for biometric operations
        /// </summary>
        /// <returns>Timeout in seconds</returns>
        protected virtual uint GetDefaultTimeout()
        {
            return Utils.BiometricConstants.DEFAULT_BIOMETRIC_TIMEOUT;
        }

        /// <summary>
        /// Dispose of resources
        /// </summary>
        public virtual void Dispose()
        {
            // Base implementation - derived classes should override if needed
        }
    }

    /// <summary>
    /// Abstract base class for biometric flag storage
    /// </summary>
    public abstract class StorageHandler
    {
        /// <summary>
        /// Get biometric flag for user
        /// </summary>
        /// <param name="username">Username to check</param>
        /// <returns>True if biometric is enabled for user, false otherwise</returns>
        public abstract bool GetBiometricFlag(string username);

        /// <summary>
        /// Set biometric flag for user
        /// </summary>
        /// <param name="username">Username to set flag for</param>
        /// <param name="enabled">Whether biometric should be enabled</param>
        /// <returns>True if operation was successful</returns>
        public abstract bool SetBiometricFlag(string username, bool enabled);

        /// <summary>
        /// Delete biometric flag for user
        /// </summary>
        /// <param name="username">Username to delete flag for</param>
        /// <returns>True if deletion was successful, false otherwise</returns>
        public abstract bool DeleteBiometricFlag(string username);

        /// <summary>
        /// Check if biometric flag exists for user
        /// </summary>
        /// <param name="username">Username to check</param>
        /// <returns>True if flag exists (regardless of value)</returns>
        public abstract bool HasBiometricFlag(string username);
    }

    /// <summary>
    /// Interface for data collection during biometric operations
    /// </summary>
    public interface IDataCollector
    {
        /// <summary>
        /// Collect platform-specific data for biometric operations
        /// </summary>
        /// <returns>Collected data as dictionary</returns>
        Dictionary<string, object> CollectData();

        /// <summary>
        /// Get origin for WebAuthn operations
        /// </summary>
        /// <returns>Origin URL</returns>
        string GetOrigin();

        /// <summary>
        /// Get timeout for operations
        /// </summary>
        /// <returns>Timeout in milliseconds</returns>
        uint GetTimeout();
    }

    /// <summary>
    /// Default data collector implementation
    /// </summary>
    public class DefaultDataCollector : IDataCollector
    {
        private readonly string _origin;
        private readonly uint _timeout;

        public DefaultDataCollector(string origin = "https://keepersecurity.com", uint? timeout = null)
        {
            _origin = origin ?? "https://keepersecurity.com";
            _timeout = timeout ?? TimeoutConstants.DEFAULT_BIOMETRIC_TIMEOUT_MS;
        }

        public Dictionary<string, object> CollectData()
        {
            return new Dictionary<string, object>
            {
                ["origin"] = GetOrigin(),
                ["timeout"] = GetTimeout(),
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            };
        }

        public string GetOrigin()
        {
            return _origin;
        }

        public uint GetTimeout()
        {
            return _timeout;
        }
    }

    /// <summary>
    /// Base implementation for platform handlers with common functionality
    /// </summary>
    public abstract class BasePlatformHandler : PlatformHandler
    {
        /// <summary>
        /// Storage handler for biometric flags
        /// </summary>
        protected StorageHandler StorageHandler { get; private set; }

        /// <summary>
        /// Initialize base platform handler with storage handler
        /// </summary>
        protected BasePlatformHandler()
        {
            StorageHandler = CreateStorageHandler();
        }

        /// <summary>
        /// Create platform-specific storage handler
        /// </summary>
        /// <returns>Storage handler instance</returns>
        protected abstract StorageHandler CreateStorageHandler();

        /// <summary>
        /// Get the storage handler for this platform
        /// </summary>
        /// <returns>Storage handler instance</returns>
        public override StorageHandler GetStorageHandler()
        {
            return StorageHandler;
        }

        /// <summary>
        /// Get biometric flag for user
        /// </summary>
        /// <param name="username">Username to check</param>
        /// <returns>True if biometric is enabled for user</returns>
        public virtual bool GetBiometricFlag(string username)
        {
            if (string.IsNullOrEmpty(username))
                throw new ArgumentException("Username cannot be null or empty", nameof(username));

            return StorageHandler.GetBiometricFlag(username);
        }

        /// <summary>
        /// Set biometric flag for user
        /// </summary>
        /// <param name="username">Username to set flag for</param>
        /// <param name="enabled">Whether biometric should be enabled</param>
        /// <returns>True if operation was successful</returns>
        public virtual bool SetBiometricFlag(string username, bool enabled)
        {
            if (string.IsNullOrEmpty(username))
                throw new ArgumentException("Username cannot be null or empty", nameof(username));

            return StorageHandler.SetBiometricFlag(username, enabled);
        }

        /// <summary>
        /// Delete biometric flag for user
        /// </summary>
        /// <param name="username">Username to delete flag for</param>
        /// <returns>True if deletion was successful</returns>
        public virtual bool DeleteBiometricFlag(string username)
        {
            if (string.IsNullOrEmpty(username))
                throw new ArgumentException("Username cannot be null or empty", nameof(username));

            return StorageHandler.DeleteBiometricFlag(username);
        }

        /// <summary>
        /// Check if biometric flag exists for user
        /// </summary>
        /// <param name="username">Username to check</param>
        /// <returns>True if flag exists (regardless of value)</returns>
        public virtual bool HasBiometricFlag(string username)
        {
            if (string.IsNullOrEmpty(username))
                throw new ArgumentException("Username cannot be null or empty", nameof(username));

            return StorageHandler.HasBiometricFlag(username);
        }

        /// <summary>
        /// Dispose of resources
        /// </summary>
        /// <param name="disposing">Whether to dispose managed resources</param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (StorageHandler is IDisposable disposableStorage)
                {
                    disposableStorage.Dispose();
                }
            }
        }

        /// <summary>
        /// Prepare credential creation options - common processing for all platforms
        /// </summary>
        /// <param name="creationOptions">Creation options to prepare</param>
        /// <returns>Prepared creation options</returns>
        protected virtual PkCreationOptions _PrepareCredentialCreationOptions(PkCreationOptions creationOptions)
        {
            if (creationOptions == null)
                throw new ArgumentNullException(nameof(creationOptions));

            // Decode user ID from base64url if it's a string
            if (!string.IsNullOrEmpty(creationOptions.User?.Id))
            {
                try
                {
                    var userIdBytes = Base64UrlDecode(creationOptions.User.Id);
                    creationOptions.User.Id = Convert.ToBase64String(userIdBytes);
                }
                catch
                {
                    // If decoding fails, leave as is
                }
            }

            // Remove unsupported options
            creationOptions.Hints?.Clear();
            creationOptions.Extensions?.Clear();

            // Remove empty excludeCredentials
            if (creationOptions.ExcludeCredentials?.Count == 0)
            {
                creationOptions.ExcludeCredentials = null;
            }

            // Set authenticator selection
            if (creationOptions.AuthenticatorSelection == null)
            {
                creationOptions.AuthenticatorSelection = new AuthenticatorSelection();
            }

            // Apply default authenticator selection
            creationOptions.AuthenticatorSelection.AuthenticatorAttachment = "platform";
            creationOptions.AuthenticatorSelection.UserVerification = "required";
            creationOptions.AuthenticatorSelection.ResidentKey = "required";

            // Set default timeout if not present (convert to milliseconds)
            if (creationOptions.Timeout == null)
            {
                creationOptions.Timeout = GetDefaultTimeout() * 1000;
            }

            return creationOptions;
        }

        /// <summary>
        /// Prepare authentication options - common processing for all platforms
        /// </summary>
        /// <param name="pkOptions">Authentication options to prepare</param>
        /// <returns>Prepared authentication options</returns>
        protected virtual Dictionary<string, object> _PrepareAuthenticationOptions(Dictionary<string, object> pkOptions)
        {
            if (pkOptions == null)
                throw new ArgumentNullException(nameof(pkOptions));

            // Remove unsupported options
            pkOptions.Remove("hints");
            pkOptions.Remove("extensions");

            // Clean up empty transports in allowCredentials
            if (pkOptions.TryGetValue("allowCredentials", out var allowCredsObj) && allowCredsObj is IEnumerable<object> allowCreds)
            {
                foreach (var credObj in allowCreds)
                {
                    if (credObj is Dictionary<string, object> cred)
                    {
                        if (cred.TryGetValue("transports", out var transportsObj))
                        {
                            // Check if transports is empty
                            bool isEmpty = false;
                            if (transportsObj is IEnumerable<object> transports)
                            {
                                isEmpty = !transports.Any();
                            }
                            else if (transportsObj is Array array)
                            {
                                isEmpty = array.Length == 0;
                            }

                            if (isEmpty)
                            {
                                cred.Remove("transports");
                            }
                        }
                    }
                }
            }

            // Set user verification to required
            pkOptions["userVerification"] = "required";

            // Set default timeout if not present (convert to milliseconds)
            if (!pkOptions.ContainsKey("timeout"))
            {
                pkOptions["timeout"] = GetDefaultTimeout() * 1000;
            }

            return pkOptions;
        }

        

        /// <summary>
        /// Decode base64url encoded string
        /// </summary>
        /// <param name="input">Base64url encoded string</param>
        /// <returns>Decoded bytes</returns>
        private static byte[] Base64UrlDecode(string input)
        {
            if (string.IsNullOrEmpty(input))
                return Array.Empty<byte>();

            // Add padding if needed
            switch (input.Length % 4)
            {
                case 2: input += "=="; break;
                case 3: input += "="; break;
            }

            // Replace URL-safe characters
            input = input.Replace('-', '+').Replace('_', '/');

            return Convert.FromBase64String(input);
        }

        /// <summary>
        /// Common error handling for authentication failures
        /// </summary>
        /// <param name="error">Original exception</param>
        /// <param name="platformName">Platform name (default: "Biometric")</param>
        /// <returns>Formatted exception with user-friendly message</returns>
        protected virtual Exception _HandleAuthenticationError(Exception error, string platformName = "Biometric")
        {
            return Utils.BiometricErrorHandler.HandleAuthenticationError(error, platformName);
        }

        /// <summary>
        /// Common error handling for credential creation failures
        /// </summary>
        /// <param name="error">Original exception</param>
        /// <param name="platformName">Platform name (default: "Biometric")</param>
        /// <returns>Formatted exception with user-friendly message</returns>
        protected virtual Exception _HandleCredentialCreationError(Exception error, string platformName = "Biometric")
        {
            return Utils.BiometricErrorHandler.HandleCredentialCreationError(error, platformName);
        }

        /// <summary>
        /// Dispose of resources
        /// </summary>
        public override void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }

    /// <summary>
    /// Exception thrown during platform-specific biometric operations
    /// </summary>
    public class PlatformException : Exception
    {
        public string Platform { get; }

        public PlatformException(string platform, string message) : base(message)
        {
            Platform = platform;
        }

        public PlatformException(string platform, string message, Exception innerException) 
            : base(message, innerException)
        {
            Platform = platform;
        }
    }

    /// <summary>
    /// Exception thrown during storage operations
    /// </summary>
    public class StorageException : Exception
    {
        public string Username { get; }

        public StorageException(string username, string message) : base(message)
        {
            Username = username;
        }

        public StorageException(string username, string message, Exception innerException) 
            : base(message, innerException)
        {
            Username = username;
        }
    }
}
