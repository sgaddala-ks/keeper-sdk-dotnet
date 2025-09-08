using System;
using System.Collections.Generic;

namespace KeeperBiometric
{
    /// <summary>
    /// Registration data for biometric authentication
    /// </summary>
    public class RegistrationData
    {
        public string FriendlyName { get; set; }
    }

    /// <summary>
    /// Registration parameters for biometric setup
    /// </summary>
    public class RegistrationParameters
    {
        public string Name { get; set; }
        public bool Force { get; set; } = false;
        // Add other parameters as needed
    }

    /// <summary>
    /// Biometric registration functionality
    /// </summary>
    public static class BiometricRegistration
    {
        /// <summary>
        /// Prepare registration data and options
        /// </summary>
        /// <param name="parameters">Registration parameters</param>
        /// <returns>Registration data prepared for biometric setup</returns>
        /// <exception cref="ArgumentException">Thrown when friendly name is too long</exception>
        public static RegistrationData _PrepareRegistration(RegistrationParameters parameters)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));

            // Get friendly name from parameters or use default
            var friendlyName = parameters.Name ?? BiometricUtils._GetDefaultCredentialName();
            
            // Validate friendly name length (must be 32 characters or less)
            if (friendlyName.Length > 32)
            {
                throw new ArgumentException("Friendly name must be 32 characters or less");
            }
            
            // Log the operation (using Console for now, can be replaced with proper logging)
            Console.WriteLine($"Adding biometric authentication method: {friendlyName}");
            
            // Return registration data
            return new RegistrationData
            {
                FriendlyName = friendlyName
            };
        }

        /// <summary>
        /// Prepare registration data using dictionary parameters (alternative overload)
        /// </summary>
        /// <param name="kwargs">Dictionary of keyword arguments</param>
        /// <returns>Registration data prepared for biometric setup</returns>
        /// <exception cref="ArgumentException">Thrown when friendly name is too long</exception>
        public static RegistrationData _PrepareRegistration(Dictionary<string, object> kwargs)
        {
            if (kwargs == null)
                kwargs = new Dictionary<string, object>();

            // Convert dictionary to parameters
            var parameters = new RegistrationParameters();
            
            if (kwargs.TryGetValue("name", out var nameValue))
            {
                parameters.Name = nameValue?.ToString();
            }
            
            if (kwargs.TryGetValue("force", out var forceValue))
            {
                if (forceValue is bool force)
                {
                    parameters.Force = force;
                }
                else if (bool.TryParse(forceValue?.ToString(), out var parsedForce))
                {
                    parameters.Force = parsedForce;
                }
            }
            
            return _PrepareRegistration(parameters);
        }
    }
}
