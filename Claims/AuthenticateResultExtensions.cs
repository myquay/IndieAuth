using IndieAuth.Claims;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication
{
    public static class AuthenticationResultExtensions
    {
        /// <summary>
        /// Check if the authentication provider is for the correct website
        /// </summary>
        /// <param name="result"></param>
        /// <param name="expectedProperty"></param>
        /// <returns></returns>
        public static bool VerifyWebsite(this AuthenticateResult result, string me)
        {
            if (!result.Succeeded)
                return false;

            var claimedUser = result.Principal.Claims.FirstOrDefault(u => u.Type == IndieAuthClaims.ME)?.Value;

            if (claimedUser == null)
                return false;

            return claimedUser == me?.ToString().Trim('/');
        }

        /// <summary>
        /// Get the actual website parameter from the authentication result
        /// </summary>
        /// <param name="result"></param>
        /// <returns></returns>
        public static string? GetSuppliedWebsiteParameter(this AuthenticateResult result)
        {
            if (!result.Succeeded)
                return null;
            return result.Principal.Claims.FirstOrDefault(u => u.Type == IndieAuthClaims.ME)?.Value;
        }
    }
}
