using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IndieAuth.Authentication
{
    public class IndieAuthOptions : RemoteAuthenticationOptions
    {
        /// <summary>
        /// Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; } = default!;


        /// <summary>
        /// Gets or sets the authentication scheme corresponding to the middleware
        /// responsible of persisting user's identity after a successful authentication with external authentication provider.
        /// This value typically corresponds to an external cookie middleware registered in the Startup class.
        /// When omitted, <see cref="IndieAuthDefaults.ExternalCookieSignInScheme"/> is used as a fallback value.
        /// </summary>
        public string ExternalSignInScheme { get; set; } = IndieAuthDefaults.ExternalCookieSignInScheme;


        /// <summary>
        /// IndieAuth Server Metadata Endpoint. See: <see href="https://indieauth.spec.indieweb.org/#indieauth-server-metadata">https://indieauth.spec.indieweb.org/#indieauth-server-metadata</see>
        /// </summary>
        public string MetadataEndpoint { get; set; } = "/.well-known/oauth-authorization-server";

        /// <summary>
        /// Whether the endpoint should be enabled
        /// </summary>
        public bool EnableMetadataEndpoint { get; set; } = true;

        /// <summary>
        /// Scopes supported
        /// </summary>
        public string[] Scopes { get; set; } = Array.Empty<string>();

        /// <summary>
        /// Issuer
        /// </summary>
        public string Issuer { get; set; } = default!;

        /// <summary>
        /// Authorization Endpoint
        /// </summary>
        public string AuthorizationEndpoint { get; set; } = "/indie-auth/authorization";

        /// <summary>
        /// Token Endpoint
        /// </summary>
        public string TokenEndpoint { get; set; } = "/indie-auth/token";

        /// <summary>
        /// Introspection Endpoint
        /// </summary>
        public string IntrospectionEndpoint { get; set; } = "/indie-auth/token-info";

        /// <summary>
        /// Revocation Endpoint
        /// </summary>
        public string? RevocationEndpoint { get; set; } = default;

        /// <summary>
        /// Userinfo endpoint
        /// </summary>
        public string? UserinfoEndpoint { get; set; } = default;

        /// <summary>
        /// ClientId, Me, and Redirect URIs must use the HTTPS scheme
        /// </summary>
        public bool RequireHttps { get; set; } = true;
    }
}
