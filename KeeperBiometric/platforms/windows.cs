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
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using Fido2NetLib;
using Fido2NetLib.Objects;
using KeeperBiometric.Utils;

namespace KeeperBiometric.Platforms
{
    /// <summary>
    /// Windows Registry storage handler
    /// </summary>
    public class WindowsStorageHandler : StorageHandler
    {
        private readonly string _keyPath;

        /// <summary>
        /// Initialize Windows storage handler
        /// </summary>
        public WindowsStorageHandler()
        {
            _keyPath = Utils.BiometricConstants.StoragePaths.WINDOWS_REGISTRY_PATH;
        }

        /// <summary>
        /// Get Windows registry key for biometric storage
        /// </summary>
        /// <returns>Registry key or null if not available</returns>
        private RegistryKey GetRegistryKey()
        {
            try
            {
                // Try to open existing key
                var key = Registry.CurrentUser.OpenSubKey(_keyPath, writable: true);
                if (key != null)
                {
                    return key;
                }

                // Create key if it doesn't exist
                return Registry.CurrentUser.CreateSubKey(_keyPath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DEBUG: Failed to get registry key: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Execute registry operation with proper key disposal
        /// </summary>
        /// <typeparam name="T">Return type</typeparam>
        /// <param name="operation">Operation to perform with registry key</param>
        /// <returns>Result of operation</returns>
        private T WithRegistryKey<T>(Func<RegistryKey, T> operation)
        {
            using var key = GetRegistryKey();
            if (key == null)
            {
                throw new InvalidOperationException("Registry key not available");
            }
            return operation(key);
        }

        /// <summary>
        /// Execute registry operation with proper key disposal (void return)
        /// </summary>
        /// <param name="operation">Operation to perform with registry key</param>
        private void WithRegistryKey(Action<RegistryKey> operation)
        {
            using var key = GetRegistryKey();
            if (key == null)
            {
                throw new InvalidOperationException("Registry key not available");
            }
            operation(key);
        }

        /// <summary>
        /// Get biometric flag from Windows registry - True if credential ID exists
        /// </summary>
        /// <param name="username">Username to check</param>
        /// <returns>True if biometric flag is set for user</returns>
        public override bool GetBiometricFlag(string username)
        {
            return GetCredentialId(username) != null;
        }

        /// <summary>
        /// Set biometric flag for user (stores credential ID)
        /// </summary>
        /// <param name="username">Username to set flag for</param>
        /// <param name="enabled">Whether biometric should be enabled</param>
        /// <returns>True if operation was successful</returns>
        public override bool SetBiometricFlag(string username, bool enabled)
        {
            if (enabled)
            {
                // Generate a default credential ID if enabling
                var defaultCredentialId = Guid.NewGuid().ToString();
                return StoreCredentialId(username, defaultCredentialId);
            }
            else
            {
                return DeleteCredentialId(username);
            }
        }

        /// <summary>
        /// Delete biometric flag from Windows registry - removes credential ID
        /// </summary>
        /// <param name="username">Username to delete flag for</param>
        /// <returns>True if deletion was successful</returns>
        public override bool DeleteBiometricFlag(string username)
        {
            return DeleteCredentialId(username);
        }

        /// <summary>
        /// Check if biometric flag exists for user
        /// </summary>
        /// <param name="username">Username to check</param>
        /// <returns>True if flag exists (regardless of value)</returns>
        public override bool HasBiometricFlag(string username)
        {
            return GetCredentialId(username) != null;
        }

        /// <summary>
        /// Store credential ID for user in Windows registry (also serves as biometric flag)
        /// </summary>
        /// <param name="username">Username to store credential ID for</param>
        /// <param name="credentialId">Credential ID to store</param>
        /// <returns>True if storage was successful</returns>
        public bool StoreCredentialId(string username, string credentialId)
        {
            try
            {
                WithRegistryKey(key =>
                {
                    key.SetValue(username, credentialId, RegistryValueKind.String);
                });
                
                Console.WriteLine($"DEBUG: Stored credential ID for user: {username}");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"WARNING: Failed to store credential ID for {username}: {ex.Message}");
                BiometricErrorHandler.CreateStorageError("store credential ID", "Windows registry", ex);
                return false;
            }
        }

        /// <summary>
        /// Get stored credential ID for user from Windows registry
        /// </summary>
        /// <param name="username">Username to get credential ID for</param>
        /// <returns>Credential ID if found, null otherwise</returns>
        public string GetCredentialId(string username)
        {
            try
            {
                return WithRegistryKey(key =>
                {
                    var value = key.GetValue(username);
                    if (value is string credentialId && !string.IsNullOrEmpty(credentialId))
                    {
                        Console.WriteLine($"DEBUG: Retrieved credential ID for user: {username}");
                        return credentialId;
                    }
                    
                    Console.WriteLine($"DEBUG: No stored credential ID found for user: {username}");
                    return null;
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"WARNING: Failed to retrieve credential ID for {username}: {ex.Message}");
                BiometricErrorHandler.CreateStorageError("get credential ID", "Windows registry", ex);
                return null;
            }
        }

        /// <summary>
        /// Delete stored credential ID for user from Windows registry
        /// </summary>
        /// <param name="username">Username to delete credential ID for</param>
        /// <returns>True if deletion was successful</returns>
        public bool DeleteCredentialId(string username)
        {
            try
            {
                WithRegistryKey(key =>
                {
                    try
                    {
                        key.DeleteValue(username);
                        Console.WriteLine($"DEBUG: Deleted stored credential ID for user: {username}");
                    }
                    catch (ArgumentException)
                    {
                        // Value doesn't exist, which is fine
                        Console.WriteLine($"DEBUG: Credential ID for user {username} was already deleted");
                    }
                });
                
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"WARNING: Failed to delete credential ID for {username}: {ex.Message}");
                BiometricErrorHandler.CreateStorageError("delete credential ID", "Windows registry", ex);
                return false;
            }
        }
    }

    /// <summary>
    /// Windows platform handler for biometric authentication
    /// </summary>
    public class WindowsHandler : BasePlatformHandler
    {
        /// <summary>
        /// Create platform-specific storage handler
        /// </summary>
        /// <returns>Windows registry storage handler</returns>
        protected override StorageHandler CreateStorageHandler()
        {
            return new WindowsStorageHandler();
        }

        /// <summary>
        /// Get platform name for this handler
        /// </summary>
        /// <returns>Platform name</returns>
        protected virtual string GetPlatformName()
        {
            return "Windows Hello";
        }

        /// <summary>
        /// Get current user SID using PowerShell and WMI
        /// </summary>
        /// <returns>Current user SID or null if not available</returns>
        private string GetCurrentUserSid()
        {
            try
            {
                var username = Environment.UserName;
                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = $"-Command \"(Get-WmiObject -Class Win32_UserAccount -Filter \\\"Name='{username}'\\\").SID\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = System.Diagnostics.Process.Start(startInfo);
                process?.WaitForExit();
                var result = process?.StandardOutput.ReadToEnd()?.Trim();
                
                if (!string.IsNullOrEmpty(result) && result.StartsWith("S-"))
                {
                    return result;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DEBUG: PowerShell SID query failed: {ex.Message}");
            }

            try
            {
                // Fallback to whoami command
                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "whoami",
                    Arguments = "/user /fo csv",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = System.Diagnostics.Process.Start(startInfo);
                process?.WaitForExit();
                var result = process?.StandardOutput.ReadToEnd()?.Trim();
                
                if (!string.IsNullOrEmpty(result))
                {
                    var lines = result.Split('\n');
                    if (lines.Length > 1)
                    {
                        var sidLine = lines[1].Split(',');
                        if (sidLine.Length > 1)
                        {
                            return sidLine[1].Trim('"');
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DEBUG: whoami SID query failed: {ex.Message}");
            }

            return null;
        }

        /// <summary>
        /// Check if biometrics (face/fingerprint) are enrolled using Windows Runtime API
        /// </summary>
        /// <returns>True if biometrics are available</returns>
        private async Task<bool> CheckBiometricsAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    // Check if running on Windows
                    if (!OperatingSystem.IsWindows())
                        return false;

                    // Check Windows version (Windows 10+ required for Windows Hello)
                    var version = Environment.OSVersion.Version;
                    if (version.Major < 10)
                        return false;

                    // Use PowerShell to check Windows Hello availability
                    try
                    {
                        var powershellCmd = @"
                            try {
                                $biometricDevices = Get-WmiObject Win32_BiometricDevice -ErrorAction SilentlyContinue
                                $biometricCount = ($biometricDevices | Measure-Object).Count
                                
                                if ($biometricCount -gt 0) {
                                    # Check if Windows Hello is configured
                                    $helloForBusiness = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' -Name 'Enabled' -ErrorAction SilentlyContinue
                                    if ($helloForBusiness -and $helloForBusiness.Enabled -eq 1) {
                                        Write-Output 'TRUE'
                                    } else {
                                        # Check user-specific Hello settings
                                        $userHello = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BiometricProvider' -ErrorAction SilentlyContinue
                                        if ($userHello) {
                                            Write-Output 'TRUE'
                                        } else {
                                            Write-Output 'PARTIAL'
                                        }
                                    }
                                } else {
                                    Write-Output 'FALSE'
                                }
                            } catch {
                                Write-Output 'FALSE'
                            }";
                        
                        var startInfo = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "powershell",
                            Arguments = $"-Command \"{powershellCmd}\"",
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            CreateNoWindow = true
                        };
                        
                        using (var process = System.Diagnostics.Process.Start(startInfo))
                        {
                            if (process != null)
                            {
                                var output = process.StandardOutput.ReadToEnd().Trim();
                                process.WaitForExit();
                                
                                return output == "TRUE" || output == "PARTIAL";
                            }
                        }
                        
                        return false;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"DEBUG: PowerShell check failed: {ex.Message}");
                        return false;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"DEBUG: Failed to check biometrics availability: {ex.Message}");
                    return false;
                }
            });
        }

        /// <summary>
        /// Detect Windows Hello capabilities
        /// </summary>
        /// <returns>Tuple indicating if capabilities are supported and descriptive message</returns>
        public override (bool supported, string message) DetectCapabilities()
        {
            // Check if running on Windows
            if (!OperatingSystem.IsWindows())
            {
                return (false, "Not running on Windows");
            }

            try
            {
                // Run the async biometrics check
                var hasBiometrics = CheckBiometricsAsync().GetAwaiter().GetResult();
                
                if (hasBiometrics)
                {
                    return (true, "Windows Hello available: Biometrics");
                }
                else
                {
                    return (false, "Windows Hello is not set up or biometrics are not enrolled");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"WARNING: Error detecting Windows Hello: {ex.Message}");
                return (false, $"Error detecting Windows Hello: {ex.Message}");
            }
        }

        /// <summary>
        /// Create Windows WebAuthn client
        /// </summary>
        /// <param name="dataCollector">Data collector for client configuration</param>
        /// <returns>Configured WebAuthn client</returns>
        public override IFido2 CreateWebAuthnClient(object dataCollector = null)
        {
            try
            {
                // In Python, this would use: from fido2.client.windows import WindowsClient
                // For C#, we use Fido2NetLib with Windows-specific configuration
                var fido2Config = new Fido2Configuration()
                {
                    ServerDomain = "keepersecurity.com",
                    ServerName = "Keeper Security", 
                    Origins = new HashSet<string> { "https://keepersecurity.com" }
                };

                return new Fido2(fido2Config);
            }
            catch (Exception)
            {
                throw new Exception("Windows Hello client not available. Install Fido2NetLib Windows support");
            }
        }

        /// <summary>
        /// Handle Windows-specific credential creation
        /// </summary>
        /// <param name="creationOptions">Creation options to be processed</param>
        /// <returns>Processed creation options</returns>
        public override Dictionary<string, object> HandleCredentialCreation(Dictionary<string, object> creationOptions)
        {
            // Apply Windows-specific settings
            var processedOptions = new Dictionary<string, object>(creationOptions);
            
            if (processedOptions.ContainsKey("authenticatorSelection"))
            {
                if (processedOptions["authenticatorSelection"] is Dictionary<string, object> authSelection)
                {
                    authSelection["authenticatorAttachment"] = "platform";
                    authSelection["userVerification"] = "required";
                }
            }
            
            return processedOptions;
        }

        /// <summary>
        /// Handle Windows-specific authentication options
        /// </summary>
        /// <param name="authOptions">Authentication options to be processed</param>
        /// <returns>Processed authentication options</returns>
        public override Dictionary<string, object> HandleAuthenticationOptions(Dictionary<string, object> authOptions)
        {
            return _PrepareAuthenticationOptions(authOptions);
        }

        /// <summary>
        /// Perform Windows Hello authentication
        /// </summary>
        /// <param name="client">WebAuthn client</param>
        /// <param name="options">Public key credential request options</param>
        /// <returns>Authentication result</returns>
        public override async Task<AuthenticatorAssertionRawResponse> PerformAuthentication(IFido2 client, AssertionOptions options)
        {
            try
            {
                // In Python: return client.get_assertion(options)
                // This would call the actual Windows Hello authentication
                // For now, this is a placeholder that needs actual Windows Hello integration
                // The actual implementation would use Windows Hello APIs
                await Task.Delay(1); // Make it actually async
                throw new NotImplementedException("Windows Hello authentication integration not yet implemented");
            }
            catch (Exception ex)
            {
                throw _HandleAuthenticationError(ex, GetPlatformName());
            }
        }

        /// <summary>
        /// Perform Windows Hello credential creation
        /// </summary>
        /// <param name="client">WebAuthn client</param>
        /// <param name="options">Public key credential creation options</param>
        /// <returns>Credential creation result</returns>
        public override async Task<AuthenticatorAttestationRawResponse> PerformCredentialCreation(IFido2 client, CredentialCreateOptions options)
        {
            try
            {
                // In Python: return client.make_credential(options)
                // This would call the actual Windows Hello credential creation
                // For now, this is a placeholder that needs actual Windows Hello integration
                // The actual implementation would use Windows Hello APIs
                await Task.Delay(1); // Make it actually async
                throw new NotImplementedException("Windows Hello credential creation integration not yet implemented");
            }
            catch (Exception ex)
            {
                throw _HandleCredentialCreationError(ex, GetPlatformName());
            }
        }
    }
}
