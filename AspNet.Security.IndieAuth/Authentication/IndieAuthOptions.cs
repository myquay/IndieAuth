using AspNet.Security.IndieAuth.Events;
using AspNet.Security.IndieAuth.Infrastructure;
using Microsoft.AspNetCore.Authentication;

namespace AspNet.Security.IndieAuth;


/// <summary>
/// Configuration options IndieAuth.
/// </summary>
public class IndieAuthOptions : RemoteAuthenticationOptions
{
    /// <summary>
    /// Initializes a new instance of <see cref="IndieAuthOptions"/>.
    /// </summary>
    public IndieAuthOptions()
    {
        Events = new IndieAuthEvents();
    }

    /// <summary>
    /// Check that the options are valid. Should throw an exception if things are not ok.
    /// </summary>
    public override void Validate()
    {
        base.Validate();

        if (string.IsNullOrEmpty(ClientId))
            throw new ArgumentException("Client Id must be a well formed URI string", nameof(ClientId));

        if (!Uri.IsWellFormedUriString(ClientId, UriKind.Absolute))
            throw new ArgumentException("Client Id must be a well formed URI string", nameof(ClientId));

        if (!CallbackPath.HasValue)
            throw new ArgumentException("A callback path must be provided", nameof(CallbackPath));
    }

    /// <summary>
    /// Gets or sets the client id
    /// </summary>
    public string ClientId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the <see cref="IndieAuthEvents"/> used to handle authentication events.
    /// </summary>
    public new IndieAuthEvents Events
    {
        get { return (IndieAuthEvents)base.Events; }
        set { base.Events = value; }
    }

    /// <summary>
    /// A collection of claim actions used to select values from the json user data and create Claims.
    /// </summary>
    public ClaimActionCollection ClaimActions { get; } = new ClaimActionCollection();

    /// <summary>
    /// Gets the list of permissions to request.
    /// </summary>
    public ICollection<string> Scope { get; } = new HashSet<string>();

    /// <summary>
    /// Gets or sets the type used to secure data handled by the middleware.
    /// </summary>
    public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; } = default!;

    #region Discovery Options

    /// <summary>
    /// Gets or sets whether to cache discovery results. Default: true.
    /// When enabled, discovery results are cached to avoid repeated HTTP requests
    /// for the same profile URL during the authentication flow.
    /// </summary>
    public bool CacheDiscoveryResults { get; set; } = true;

    /// <summary>
    /// Gets or sets the discovery cache expiration. Default: 5 minutes.
    /// Only used when <see cref="CacheDiscoveryResults"/> is true.
    /// </summary>
    public TimeSpan DiscoveryCacheExpiration { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets a custom discovery cache implementation.
    /// If null and <see cref="CacheDiscoveryResults"/> is true, uses the default in-memory cache.
    /// </summary>
    public IDiscoveryCache? DiscoveryCache { get; set; }

    /// <summary>
    /// Gets or sets whether to use HEAD request optimization for discovery.
    /// When enabled, a HEAD request is made first to check for Link headers,
    /// potentially avoiding the need to fetch the full HTML body.
    /// Default: false (for backwards compatibility).
    /// </summary>
    public bool UseHeadRequestForDiscovery { get; set; }

    #endregion

    #region Validation Options

    /// <summary>
    /// Gets or sets whether to enforce strict profile URL validation per IndieAuth spec section 3.2.
    /// When enabled, profile URLs are validated against all spec requirements:
    /// <list type="bullet">
    ///   <item>MUST have http or https scheme</item>
    ///   <item>MUST contain a path component</item>
    ///   <item>MUST NOT contain dot path segments (. or ..)</item>
    ///   <item>MUST NOT contain fragment, username, password, or port</item>
    ///   <item>Host MUST be a domain name (not IP address)</item>
    /// </list>
    /// Default: true.
    /// </summary>
    public bool StrictProfileUrlValidation { get; set; } = true;

    /// <summary>
    /// Gets or sets whether to enable Authorization Server Confirmation per IndieAuth spec section 5.4.
    /// When enabled, the client verifies that the authorization server is authorized to make
    /// claims about the returned 'me' URL by performing discovery on the returned URL if it
    /// differs from the initial discovery URL.
    /// Default: true.
    /// </summary>
    public bool EnableAuthorizationServerConfirmation { get; set; } = true;

    /// <summary>
    /// Gets or sets whether to validate the 'iss' (issuer) parameter per RFC 9207.
    /// When enabled, the client verifies that the issuer in the authorization response
    /// matches the issuer discovered during endpoint discovery.
    /// Only applies when metadata discovery was used (not legacy endpoints).
    /// Default: true.
    /// </summary>
    public bool ValidateIssuer { get; set; } = true;

    /// <summary>
    /// Gets or sets whether to map profile information to claims.
    /// When enabled and the 'profile' scope is granted, user profile data
    /// (name, photo, url, email) is mapped to OIDC-compatible claims.
    /// Default: true.
    /// </summary>
    public bool MapProfileToClaims { get; set; } = true;

    #endregion
}