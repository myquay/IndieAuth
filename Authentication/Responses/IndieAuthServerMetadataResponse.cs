using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IndieAuth.Authentication.Responses
{
    /// <summary>
    /// Server metadata response. See <see href="https://indieauth.spec.indieweb.org/#indieauth-server-metadata">https://indieauth.spec.indieweb.org/#indieauth-server-metadata</see>.
    /// </summary>
    public class IndieAuthServerMetadataResponse
    {
        /// <summary>
        /// Issuer
        /// </summary>
        public string Issuer { get; set; } = default!;

        /// <summary>
        /// Authorization Endpoint
        /// </summary>
        public string AuthorizationEndpoint { get; set; } = default!;   

        /// <summary>
        /// Token Endpoint
        /// </summary>
        public string TokenEndpoint { get; set; } = default!;

        /// <summary>
        /// Introspection Endpoint
        /// </summary>
        public string IntrospectionEndpoint { get; set; } = default!;

        /// <summary>
        /// Revocation Endpoint
        /// </summary>
        public string? RevocationEndpoint { get; set; } = default;

        /// <summary>
        /// Auth methods for revocation endpoint
        /// </summary>
        public string[] RevocationEndpointAuthMethodsSupported { get; set; } = new[] { "none" };

        /// <summary>
        /// Scopes supported
        /// </summary>
        public string[] ScopesSupported { get; set; } = Array.Empty<string>();

        /// <summary>
        /// Response types supported
        /// </summary>
        public string[] ResponseTypesSupported { get; set; } = new[] { "code" };

        /// <summary>
        /// Grant types supported
        /// </summary>
        public string[] GrantTypesSupported { get; set; } = new[] { "authorization_code" };

        /// <summary>
        /// Human readable service definition
        /// </summary>
        public string ServiceDocumentation { get; set; } = "https://indieauth.spec.indieweb.org/";

        /// <summary>
        /// Code challenge methods supported
        /// </summary>
        public string[] CodeChallengeMethodsSupported { get; set; } = new[] { "S256" };

        /// <summary>
        /// Authorisation response iss parameter supported
        /// </summary>
        public bool AuthorizationResponseIssParameterSupported { get; set; } = false;

        /// <summary>
        /// Userinfo endpoint
        /// </summary>
        public string? UserinfoEndpoint { get; set; } = default;
    }
}
