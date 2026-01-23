using System.Security.Claims;

namespace AspNet.Security.IndieAuth;

/// <summary>
/// OIDC-compatible claim types for IndieAuth profile information.
/// Default mapping uses standard OIDC claim names for interoperability.
/// </summary>
public static class IndieAuthClaimTypes
{
    /// <summary>
    /// The user's IndieAuth profile URL (the 'me' value).
    /// </summary>
    public const string Me = "me";

    /// <summary>
    /// Display name. Maps to OIDC 'name' claim.
    /// </summary>
    public const string Name = "name";

    /// <summary>
    /// Profile photo URL. Maps to OIDC 'picture' claim.
    /// </summary>
    public const string Picture = "picture";

    /// <summary>
    /// Website URL. Maps to OIDC 'website' claim.
    /// </summary>
    public const string Website = "website";

    /// <summary>
    /// Email address. Maps to standard email claim type.
    /// </summary>
    public const string Email = ClaimTypes.Email;

    /// <summary>
    /// Email verified status. Always 'false' for IndieAuth per spec warning.
    /// </summary>
    public const string EmailVerified = "email_verified";
}
