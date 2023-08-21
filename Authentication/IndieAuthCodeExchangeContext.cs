using Microsoft.AspNetCore.Authentication;

namespace AspNet.Security.IndieAuth;

public class IndieAuthCodeExchangeContext
{
    /// <summary>
    /// Initializes a new <see cref="OAuthCodeExchangeContext"/>.
    /// </summary>
    /// <param name="properties">The <see cref="AuthenticationProperties"/>.</param>
    /// <param name="code">The code returned from the authorization endpoint.</param>
    /// <param name="redirectUri">The redirect uri used in the authorization request.</param>
    public IndieAuthCodeExchangeContext(AuthenticationProperties properties, string code, string redirectUri)
    {
        Properties = properties;
        Code = code;
        RedirectUri = redirectUri;
    }

    /// <summary>
    /// State for the authentication flow.
    /// </summary>
    public AuthenticationProperties Properties { get; }

    /// <summary>
    /// The code returned from the authorization endpoint.
    /// </summary>
    public string Code { get; }

    /// <summary>
    /// The redirect uri used in the authorization request.
    /// </summary>
    public string RedirectUri { get; }
}