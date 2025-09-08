using System;
using System.Collections.Generic;
using KeeperBiometric.Utils;

namespace KeeperBiometric
{
    /// <summary>
    /// Constants for biometric credential naming
    /// </summary>
    public static class BiometricConstants
    {
        public const string CREDENTIAL_NAME_PREFIX = "Commander CLI (";
        public const string CREDENTIAL_NAME_SUFFIX = ")";
        public const string CREDENTIAL_NAME_TEMPLATE = "Commander CLI ({hostname})";
        public const int MAX_CREDENTIAL_NAME_LENGTH = 31;
    }

    /// <summary>
    /// Base class for biometric authentication support
    /// </summary>
    public abstract class BiometricBase
    {
        protected readonly IPlatformDetector _detector;

        // Error messages from centralized handler
        protected static readonly Dictionary<string, string> ERROR_MESSAGES = Utils.BiometricConstants.ERROR_MESSAGES;

        /// <summary>
        /// Initialize BiometricBase with platform detector
        /// </summary>
        /// <param name="detector">Platform detector for biometric capabilities</param>
        protected BiometricBase(IPlatformDetector detector = null)
        {
            _detector = detector ?? new WindowsPlatformDetector();
        }

        /// <summary>
        /// Check if platform supports biometric authentication
        /// </summary>
        /// <param name="force">Force check even if platform not supported</param>
        /// <returns>Tuple of (supported, message)</returns>
        /// <exception cref="CommandError">Thrown when FIDO2 not available or platform not supported</exception>
        protected (bool supported, string message) _CheckPlatformSupport(bool force = false)
        {
            // Check if FIDO2 is available
            if (!IsFido2Available())
            {
                throw new CommandError(ERROR_MESSAGES["no_fido2"]);
            }

            // Detect platform capabilities
            var (supported, message) = _detector.DetectPlatformCapabilities();

            // Raise error if not supported (unless forced)
            if (!supported && !force)
            {
                throw new CommandError($"{ERROR_MESSAGES["platform_not_supported"]}: {message}");
            }

            return (supported, message);
        }

        /// <summary>
        /// Check if FIDO2 is available on this system
        /// </summary>
        /// <returns>True if FIDO2 is available</returns>
        private bool IsFido2Available()
        {
            try
            {
                // Check if Fido2 types are available
                var fido2Type = typeof(Fido2NetLib.Fido2);
                return fido2Type != null;
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Interface for platform detection capabilities
    /// </summary>
    public interface IPlatformDetector
    {
        /// <summary>
        /// Detect platform biometric capabilities
        /// </summary>
        /// <returns>Tuple of (supported, message)</returns>
        (bool supported, string message) DetectPlatformCapabilities();
    }

    /// <summary>
    /// Windows-specific platform detector for biometric capabilities
    /// </summary>
    public class WindowsPlatformDetector : IPlatformDetector
    {
        /// <summary>
        /// Detect Windows biometric capabilities
        /// </summary>
        /// <returns>Tuple of (supported, message)</returns>
        public (bool supported, string message) DetectPlatformCapabilities()
        {
            try
            {
                // Check if running on Windows
                if (!OperatingSystem.IsWindows())
                {
                    return (false, "Not running on Windows platform");
                }

                // Check Windows version (Windows 10+ required for Windows Hello)
                var version = Environment.OSVersion.Version;
                if (version.Major < 10)
                {
                    return (false, $"Windows 10 or higher required. Current version: {version}");
                }

                // Basic check - in production this would check for TPM, Windows Hello availability, etc.
                return (true, "Windows platform with potential biometric support detected");
            }
            catch (Exception ex)
            {
                return (false, $"Error detecting platform capabilities: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Utility class for biometric operations
    /// </summary>
    public static class BiometricUtils
    {
        /// <summary>
        /// Generate default credential name
        /// </summary>
        /// <returns>Default credential name with hostname</returns>
        public static string _GetDefaultCredentialName()
        {
            // Get hostname (equivalent to platform.node() in Python)
            var hostname = Environment.MachineName ?? "Unknown";
            
            var prefix = BiometricConstants.CREDENTIAL_NAME_PREFIX;
            var suffix = BiometricConstants.CREDENTIAL_NAME_SUFFIX;
            var maxHostnameLength = BiometricConstants.MAX_CREDENTIAL_NAME_LENGTH - prefix.Length - suffix.Length;
            
            // Truncate hostname if too long
            if (hostname.Length > maxHostnameLength)
            {
                hostname = hostname.Substring(0, maxHostnameLength);
            }
            
            // Format using template
            return BiometricConstants.CREDENTIAL_NAME_TEMPLATE.Replace("{hostname}", hostname);
        }
    }

    /// <summary>
    /// Exception thrown for command errors in biometric operations
    /// </summary>
    public class CommandError : Exception
    {
        public CommandError(string message) : base(message) { }
        public CommandError(string message, Exception innerException) : base(message, innerException) { }
    }
}
