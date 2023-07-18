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
        /// IndieAuth Server <see href="https://indieauth.spec.indieweb.org/#indieauth-server-metadata">Metadata Endpoint</see>
        /// </summary>
        public string MetadataEndpoint { get; set; } = "/.well-known/oauth-authorization-server";
    }
}
