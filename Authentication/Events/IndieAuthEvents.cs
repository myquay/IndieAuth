using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IndieAuth.Authentication.Events
{
    /// <summary>
    /// Events
    /// </summary>
    public class IndieAuthEvents : RemoteAuthenticationEvents
    {
        /// <summary>
        /// Gets or sets the delegate that is invoked when the RedirectToAuthorizationEndpoint method is invoked.
        /// </summary>
        public Func<RedirectContext<IndieAuthOptions>, Task> OnRedirectToAuthorizationEndpoint { get; set; } = context =>
        {
            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        };

        /// <summary>
        /// Invoked before redirecting to the identity provider to authenticate. This can be used to set ProtocolMessage.State
        /// that will be persisted through the authentication process. The ProtocolMessage can also be used to add or customize
        /// parameters sent to the identity provider.
        /// </summary>
        public Func<RedirectContext<IndieAuthOptions>, Task> OnRedirectToIdentityProvider { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the OAuth handler.
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge.</param>
        public virtual Task RedirectToAuthorizationEndpoint(RedirectContext<IndieAuthOptions> context) => OnRedirectToAuthorizationEndpoint(context);

        /// <summary>
        /// Invoked before redirecting to the identity provider to authenticate. This can be used to set ProtocolMessage.State
        /// that will be persisted through the authentication process. The ProtocolMessage can also be used to add or customize
        /// parameters sent to the identity provider.
        /// </summary>
        public virtual Task RedirectToIdentityProvider(RedirectContext<IndieAuthOptions> context) => OnRedirectToIdentityProvider(context);

    }
}
