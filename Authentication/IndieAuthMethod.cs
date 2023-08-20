using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IndieAuth.Authentication
{
    /// <summary>
    /// Supported authentication methods
    /// </summary>
    public class IndieAuthMethod
    {
        /// <summary>
        /// GitHub
        /// </summary>
        public const string GITHUB = "github";

        /// <summary>
        /// All supported authentication methods
        /// </summary>
        public static string[] AllSupported = new string[] { GITHUB };
    }

    /// <summary>
    /// Regex for supported authentication methods
    /// </summary>
    public class IndieAuthProviderRegex
    {

        /// <summary>
        /// Get Regex for provider
        /// </summary>
        /// <param name="provider"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public static string GetForProvider(string provider)
        {
            return provider switch
            {
                IndieAuthMethod.GITHUB => GITHUB,
                _ => throw new ArgumentException("Invalid provider", nameof(provider))
            };
        }

        /// <summary>
        /// GitHub
        /// </summary>
        public const string GITHUB = @"^https?://(?:www\.)?github\.com/([a-zA-Z0-9](?:[a-zA-Z0-9]|-(?=[a-zA-Z0-9])){0,38})/?$";

    }

}
