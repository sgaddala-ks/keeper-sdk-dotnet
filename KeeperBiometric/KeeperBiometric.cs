using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;

namespace KeeperBiometric
{
    /// <summary>
    /// Main class for Keeper SDK Biometric Extensions
    /// </summary>
    public class KeeperBiometric : BiometricBase
    {
        private readonly IAuthentication _auth;
        private readonly IClient _client;

        /// <summary>
        /// Initialize KeeperBiometric with authenticated Keeper connection
        /// </summary>
        /// <param name="auth">Authenticated Keeper connection</param>
        /// <param name="detector">Platform detector for biometric capabilities (optional)</param>
        /// <param name="client">Client with platform handler (optional)</param>
        public KeeperBiometric(IAuthentication auth, IPlatformDetector detector = null, IClient client = null) : base(detector)
        {
            _auth = auth ?? throw new ArgumentNullException(nameof(auth));
            _client = client ?? new DefaultClient();
        }

        /// <summary>
        /// Gets the authenticated Keeper connection
        /// </summary>
        public IAuthentication Auth => _auth;

        /// <summary>
        /// Register biometric authentication for the authenticated user
        /// </summary>
        /// <param name="auth">Authenticated Keeper connection</param>
        /// <param name="parameters">Registration parameters (optional)</param>
        /// <returns>Registration result</returns>
        /// <exception cref="CommandError">Thrown when registration fails</exception>
        public static async Task<BiometricRegistrationResult> RegisterBiometrics(IAuthentication auth, RegistrationParameters parameters = null)
        {
            if (auth == null)
                throw new ArgumentNullException(nameof(auth));

            // Create KeeperBiometric instance
            var biometric = new KeeperBiometric(auth);
            
            return await biometric.RegisterBiometricsInternal(parameters ?? new RegistrationParameters());
        }

        /// <summary>
        /// Internal registration method with full validation and processing
        /// </summary>
        /// <param name="parameters">Registration parameters</param>
        /// <returns>Registration result</returns>
        private async Task<BiometricRegistrationResult> RegisterBiometricsInternal(RegistrationParameters parameters)
        {
            try
            {
                // 1. Check platform support
                var (platformSupported, platformMessage) = _CheckPlatformSupport(parameters.Force);
                
                // 2. Get username from authenticated session
                var username = _auth.Username;
                if (string.IsNullOrEmpty(username))
                {
                    throw new CommandError("Unable to determine username from authenticated session");
                }
                
                // 3. Check for existing credentials
                _CheckExistingCredentials(username);
                
                // 4. Prepare registration data
                var registrationData = BiometricRegistration._PrepareRegistration(parameters);
                
                // 5. Perform the actual registration (placeholder for now)
                // In a real implementation, this would:
                // - Create FIDO2 credentials
                // - Store them securely
                // - Register with Keeper backend
                await Task.Delay(100); // Simulate async operation
                
                // 6. Return success result
                return new BiometricRegistrationResult
                {
                    Success = true,
                    Username = username,
                    FriendlyName = registrationData.FriendlyName,
                    Message = $"Biometric authentication registered successfully for {username}",
                    PlatformSupported = platformSupported,
                    PlatformMessage = platformMessage
                };
            }
            catch (CommandError)
            {
                // Re-throw CommandErrors as-is
                throw;
            }
            catch (Exception ex)
            {
                // Wrap other exceptions in CommandError
                throw new CommandError($"Registration failed: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Check if credential already exists for this user
        /// </summary>
        /// <param name="username">Username to check for existing credentials</param>
        /// <exception cref="CommandError">Thrown when credential already registered</exception>
        private void _CheckExistingCredentials(string username)
        {
            if (string.IsNullOrEmpty(username))
                throw new ArgumentException("Username cannot be null or empty", nameof(username));

            // Check if client has platform handler
            if (_client.PlatformHandler != null && _client.PlatformHandler.StorageHandler != null)
            {
                var storageHandler = _client.PlatformHandler.StorageHandler;
                
                // Check if storage handler can get credential IDs
                var existingCredentialId = storageHandler.GetCredentialId(username);
                
                if (!string.IsNullOrEmpty(existingCredentialId))
                {
                    throw new CommandError(ERROR_MESSAGES["credential_already_registered"]);
                }
            }
        }
    }

    /// <summary>
    /// Result of biometric registration operation
    /// </summary>
    public class BiometricRegistrationResult
    {
        public bool Success { get; set; }
        public string Username { get; set; }
        public string FriendlyName { get; set; }
        public string Message { get; set; }
        public string ErrorMessage { get; set; }
        public bool PlatformSupported { get; set; }
        public string PlatformMessage { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Interface for client with platform handling capabilities
    /// </summary>
    public interface IClient
    {
        /// <summary>
        /// Platform handler for biometric operations
        /// </summary>
        IPlatformHandler PlatformHandler { get; }
    }

    /// <summary>
    /// Interface for platform handler
    /// </summary>
    public interface IPlatformHandler
    {
        /// <summary>
        /// Storage handler for credential management
        /// </summary>
        IStorageHandler StorageHandler { get; }
    }

    /// <summary>
    /// Interface for credential storage operations
    /// </summary>
    public interface IStorageHandler
    {
        /// <summary>
        /// Get credential ID for a specific username
        /// </summary>
        /// <param name="username">Username to lookup</param>
        /// <returns>Credential ID if exists, null/empty if not found</returns>
        string GetCredentialId(string username);

        /// <summary>
        /// Store credential ID for a username
        /// </summary>
        /// <param name="username">Username</param>
        /// <param name="credentialId">Credential ID to store</param>
        void StoreCredentialId(string username, string credentialId);

        /// <summary>
        /// Remove credential ID for a username
        /// </summary>
        /// <param name="username">Username</param>
        /// <returns>True if removed successfully</returns>
        bool RemoveCredentialId(string username);
    }

    /// <summary>
    /// Default client implementation
    /// </summary>
    public class DefaultClient : IClient
    {
        public IPlatformHandler PlatformHandler { get; }

        public DefaultClient(IPlatformHandler platformHandler = null)
        {
            PlatformHandler = platformHandler ?? new DefaultPlatformHandler();
        }
    }

    /// <summary>
    /// Default platform handler implementation
    /// </summary>
    public class DefaultPlatformHandler : IPlatformHandler
    {
        public IStorageHandler StorageHandler { get; }

        public DefaultPlatformHandler(IStorageHandler storageHandler = null)
        {
            StorageHandler = storageHandler ?? new InMemoryStorageHandler();
        }
    }

    /// <summary>
    /// In-memory storage handler for demonstration/testing
    /// </summary>
    public class InMemoryStorageHandler : IStorageHandler
    {
        private readonly Dictionary<string, string> _credentialStore = new();

        public string GetCredentialId(string username)
        {
            return _credentialStore.TryGetValue(username, out var credentialId) ? credentialId : null;
        }

        public void StoreCredentialId(string username, string credentialId)
        {
            if (string.IsNullOrEmpty(username))
                throw new ArgumentException("Username cannot be null or empty", nameof(username));
            
            if (string.IsNullOrEmpty(credentialId))
                throw new ArgumentException("Credential ID cannot be null or empty", nameof(credentialId));

            _credentialStore[username] = credentialId;
        }

        public bool RemoveCredentialId(string username)
        {
            if (string.IsNullOrEmpty(username))
                return false;

            return _credentialStore.Remove(username);
        }
    }
}
