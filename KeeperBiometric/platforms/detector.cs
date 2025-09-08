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
using KeeperBiometric.Utils;

namespace KeeperBiometric.Platforms
{
    /// <summary>
    /// Centralized biometric capability detection
    /// </summary>
    public class BiometricDetector
    {
        private readonly Dictionary<string, PlatformHandler> _platformHandlers;

        /// <summary>
        /// Initialize biometric detector and load available platform handlers
        /// </summary>
        public BiometricDetector()
        {
            _platformHandlers = _LoadPlatformHandlers();
        }

        /// <summary>
        /// Load available platform handlers
        /// </summary>
        /// <returns>Dictionary of platform handlers</returns>
        private Dictionary<string, PlatformHandler> _LoadPlatformHandlers()
        {
            var handlers = new Dictionary<string, PlatformHandler>();

            try
            {
                if (PlatformConstants.GetCurrentPlatform() == Utils.BiometricConstants.PLATFORM_WINDOWS)
                {
                    // Load Windows handler
                    var windowsHandler = new WindowsHandler();
                    handlers[Utils.BiometricConstants.PLATFORM_WINDOWS] = windowsHandler;
                }
            }
            catch (Exception)
            {
                Console.WriteLine("DEBUG: Windows platform handler not available");
            }

            try
            {
                if (PlatformConstants.GetCurrentPlatform() == Utils.BiometricConstants.PLATFORM_DARWIN)
                {
                    // Try to load macOS handler
                    // from .macos import MacOSHandler
                    // handlers[PLATFORM_DARWIN] = MacOSHandler()
                    
                    // For now, this will be implemented when MacOSHandler is created
                    // var macosHandler = new MacOSHandler();
                    // handlers[BiometricConstants.PLATFORM_DARWIN] = macosHandler;
                }
            }
            catch (Exception)
            {
                Console.WriteLine("DEBUG: macOS platform handler not available");
            }

            return handlers;
        }

        /// <summary>
        /// Detect biometric capabilities for current platform
        /// </summary>
        /// <returns>Tuple indicating if capabilities are supported and descriptive message</returns>
        public (bool supported, string message) DetectPlatformCapabilities()
        {
            var currentPlatform = PlatformConstants.GetCurrentPlatform();

            if (!_platformHandlers.ContainsKey(currentPlatform))
            {
                return (false, $"Biometric authentication not supported on {currentPlatform}");
            }

            var handler = _platformHandlers[currentPlatform];
            return handler.DetectCapabilities();
        }

        /// <summary>
        /// Get platform handler for current system
        /// </summary>
        /// <returns>Platform handler for current system</returns>
        /// <exception cref="Exception">Thrown when biometric authentication is not supported on current platform</exception>
        public PlatformHandler GetPlatformHandler()
        {
            var currentPlatform = PlatformConstants.GetCurrentPlatform();

            if (!_platformHandlers.ContainsKey(currentPlatform))
            {
                throw new Exception($"Biometric authentication not supported on {currentPlatform}");
            }

            return _platformHandlers[currentPlatform];
        }
    }
}
