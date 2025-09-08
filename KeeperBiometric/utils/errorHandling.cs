using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace KeeperBiometric.Utils
{
    /// <summary>
    /// Centralized error handling for biometric operations
    /// </summary>
    public static class BiometricErrorHandler
    {
        // Error message keywords for authentication errors
        private static readonly string[] CancelledKeywords = { "cancelled", "denied" };
        private static readonly string[] NotEnrolledPhrases = { 
            "no identities are enrolled", "biometry is not enrolled", "not enrolled", 
            "biometric not set up", "touch id not set up" 
        };
        private static readonly string[] NotConfiguredPhrases = { 
            "not configured", "not enabled", "unavailable", "not supported" 
        };

        /// <summary>
        /// Handle authentication errors with consistent messaging
        /// </summary>
        /// <param name="error">Original exception</param>
        /// <param name="platformName">Platform name (default: "Biometric")</param>
        /// <returns>Formatted exception with user-friendly message</returns>
        public static Exception HandleAuthenticationError(Exception error, string platformName = "Biometric")
        {
            var errorMsg = error.Message.ToLowerInvariant();
            var errorStr = error.Message;

            if (CancelledKeywords.Any(keyword => errorMsg.Contains(keyword)))
            {
                return new Exception($"{platformName} authentication cancelled");
            }
            else if (errorMsg.Contains("timeout"))
            {
                return new Exception($"{platformName} authentication timed out");
            }
            else if (errorMsg.Contains("not available"))
            {
                return new Exception($"{platformName} is not available or not set up");
            }
            else if (NotEnrolledPhrases.Any(phrase => errorMsg.Contains(phrase)))
            {
                return new Exception($"{platformName} is not set up - please enroll your biometric credentials in system settings");
            }
            else if (errorMsg.Contains("parameter is incorrect"))
            {
                return new Exception($"{platformName} parameter error - please check your biometric setup");
            }
            else if (NotConfiguredPhrases.Any(phrase => errorMsg.Contains(phrase)))
            {
                return new Exception($"{platformName} is not available or not configured");
            }
            else if (errorMsg.Contains("no matching credential found"))
            {
                return new Exception(BiometricConstants.ERROR_MESSAGES["no_matching_credential"]);
            }
            else
            {
                if (errorMsg.Contains("error domain=") || errorMsg.Contains("code="))
                {
                    if (errorMsg.Contains("localizeddescription="))
                    {
                        var descStart = errorMsg.IndexOf("localizeddescription=") + "localizeddescription=".Length;
                        var descEnd = errorMsg.IndexOf("}", descStart);
                        if (descEnd == -1)
                            descEnd = errorMsg.Length;
                        
                        var description = errorStr.Substring(descStart, descEnd - descStart).Trim();
                        return new Exception($"{platformName} error: {description}");
                    }
                }

                return new Exception($"{platformName} authentication failed: {errorStr}");
            }
        }

        /// <summary>
        /// Handle credential creation errors with consistent messaging
        /// </summary>
        /// <param name="error">Original exception</param>
        /// <param name="platformName">Platform name (default: "Biometric")</param>
        /// <returns>Formatted exception with user-friendly message</returns>
        public static Exception HandleCredentialCreationError(Exception error, string platformName = "Biometric")
        {
            var errorMsg = error.Message.ToLowerInvariant();
            var errorStr = error.Message;

            if (CancelledKeywords.Any(keyword => errorMsg.Contains(keyword)))
            {
                return new Exception($"{platformName} registration cancelled");
            }
            else if (errorMsg.Contains("object already exists") || 
                    (errorMsg.Contains("oserror") && errorMsg.Contains("22") && errorMsg.Contains("object already exists")))
            {
                return new Exception("A biometric credential for this account already exists");
            }
            else if (errorMsg.Contains("timeout"))
            {
                return new Exception($"{platformName} registration timed out");
            }
            else if (errorMsg.Contains("not available"))
            {
                return new Exception($"{platformName} is not available or not set up");
            }
            else if (NotEnrolledPhrases.Any(phrase => errorMsg.Contains(phrase)))
            {
                return new Exception($"{platformName} is not set up - please enroll your biometric credentials in system settings");
            }
            else if (NotConfiguredPhrases.Any(phrase => errorMsg.Contains(phrase)))
            {
                return new Exception($"{platformName} is not available or not configured");
            }
            else
            {
                if (errorMsg.Contains("error domain=") || errorMsg.Contains("code="))
                {
                    if (errorMsg.Contains("localizeddescription="))
                    {
                        var descStart = errorMsg.IndexOf("localizeddescription=") + "localizeddescription=".Length;
                        var descEnd = errorMsg.IndexOf("}", descStart);
                        if (descEnd == -1)
                            descEnd = errorMsg.Length;
                        
                        var description = errorStr.Substring(descStart, descEnd - descStart).Trim();
                        return new Exception($"{platformName} error: {description}");
                    }
                }

                return new Exception($"{platformName} registration failed: {errorStr}");
            }
        }

        /// <summary>
        /// Handle command errors with clean error messages
        /// </summary>
        /// <param name="commandName">Name of the command</param>
        /// <param name="operation">Operation being performed</param>
        /// <param name="error">Original exception</param>
        /// <exception cref="CommandError">Throws CommandError with formatted message</exception>
        public static void HandleCommandError(string commandName, string operation, Exception error)
        {
            throw new CommandError(error.Message);
        }

        /// <summary>
        /// Handle keyboard interrupt with clean error messages
        /// </summary>
        /// <param name="commandName">Name of the command</param>
        /// <param name="operation">Operation being performed</param>
        /// <exception cref="CommandError">Throws CommandError for cancellation</exception>
        public static void HandleKeyboardInterrupt(string commandName, string operation)
        {
            throw new CommandError($"{operation} cancelled by user");
        }

        /// <summary>
        /// Create platform-specific error message
        /// </summary>
        /// <param name="platformName">Platform name</param>
        /// <param name="errorKey">Error message key</param>
        /// <param name="additionalInfo">Additional information (optional)</param>
        /// <returns>Formatted error message</returns>
        public static string CreatePlatformError(string platformName, string errorKey, string additionalInfo = "")
        {
            var baseMessage = BiometricConstants.ERROR_MESSAGES.GetValueOrDefault(errorKey, $"Unknown error in {platformName}");
            
            if (!string.IsNullOrEmpty(additionalInfo))
            {
                return $"{baseMessage}: {additionalInfo}";
            }
            
            return baseMessage;
        }

        /// <summary>
        /// Validate that required assemblies/types are available
        /// </summary>
        /// <param name="requiredTypes">List of required type names</param>
        /// <param name="platformName">Platform name (default: "Platform")</param>
        /// <exception cref="Exception">Throws exception if required types are missing</exception>
        public static void ValidateDependencies(List<string> requiredTypes, string platformName = "Platform")
        {
            var missingTypes = new List<string>();
            
            foreach (var typeName in requiredTypes)
            {
                try
                {
                    // Try to find the type in loaded assemblies
                    var type = Type.GetType(typeName) ?? 
                              AppDomain.CurrentDomain.GetAssemblies()
                                  .SelectMany(a => a.GetTypes())
                                  .FirstOrDefault(t => t.Name == typeName || t.FullName == typeName);
                    
                    if (type == null)
                    {
                        missingTypes.Add(typeName);
                    }
                }
                catch
                {
                    missingTypes.Add(typeName);
                }
            }

            if (missingTypes.Count > 0)
            {
                throw new Exception($"Required {platformName} dependencies not available: {string.Join(", ", missingTypes)}");
            }
        }

        /// <summary>
        /// Log storage operation errors consistently
        /// </summary>
        /// <param name="operation">Storage operation name</param>
        /// <param name="platformName">Platform name</param>
        /// <param name="error">Original exception</param>
        public static void CreateStorageError(string operation, string platformName, Exception error)
        {
            // Log debug message (using Console for now, could be replaced with proper logging framework)
            Console.WriteLine($"DEBUG: Failed to {operation} {platformName} biometric flag: {error.Message}");
        }

        /// <summary>
        /// Execute a function with consistent error handling
        /// </summary>
        /// <typeparam name="T">Return type of the function</typeparam>
        /// <param name="commandName">Name of the command</param>
        /// <param name="operation">Operation being performed</param>
        /// <param name="func">Function to execute</param>
        /// <returns>Result of the function execution</returns>
        /// <exception cref="CommandError">Throws CommandError for handled exceptions</exception>
        public static T ExecuteWithErrorHandling<T>(string commandName, string operation, Func<T> func)
        {
            try
            {
                return func();
            }
            catch (OperationCanceledException)
            {
                HandleKeyboardInterrupt(commandName, operation);
                throw; // This won't be reached due to HandleKeyboardInterrupt throwing
            }
            catch (Exception e)
            {
                HandleCommandError(commandName, operation, e);
                throw; // This won't be reached due to HandleCommandError throwing
            }
        }

        /// <summary>
        /// Execute an action with consistent error handling
        /// </summary>
        /// <param name="commandName">Name of the command</param>
        /// <param name="operation">Operation being performed</param>
        /// <param name="action">Action to execute</param>
        /// <exception cref="CommandError">Throws CommandError for handled exceptions</exception>
        public static void ExecuteWithErrorHandling(string commandName, string operation, Action action)
        {
            try
            {
                action();
            }
            catch (OperationCanceledException)
            {
                HandleKeyboardInterrupt(commandName, operation);
            }
            catch (Exception e)
            {
                HandleCommandError(commandName, operation, e);
            }
        }
    }

}
