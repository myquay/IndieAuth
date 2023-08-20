using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IndieAuth.Authentication;

namespace IndieAuth
{
    /// <summary>
    /// Default values related to IndieAuth authentication handler
    /// </summary>
    public static class IndieAuthDefaults
    {
        /// <summary>
        /// Default value for AuthenticationScheme property in the <see cref="IndieAuthOptions"/>.
        /// </summary>
        public const string AuthenticationScheme = "IndieAuth";

        /// <summary>
        /// External cookie for downstream providers
        /// </summary>
        public const string ExternalCookieSignInScheme = "ExternalCookie";

        /// <summary>
        /// The default display name for IndieAuth authentication.
        /// </summary>
        public static readonly string DisplayName = "IndieAuth";
    }
}
