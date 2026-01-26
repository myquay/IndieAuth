namespace AspNet.Security.IndieAuth;

/// <summary>
/// Default values for IndieAuth bearer token authentication.
/// </summary>
public static class IndieAuthBearerDefaults
{
    /// <summary>
    /// Default authentication scheme for IndieAuth bearer tokens.
    /// </summary>
    public const string AuthenticationScheme = "IndieAuthBearer";

    /// <summary>
    /// The default display name for IndieAuth bearer authentication.
    /// </summary>
    public static readonly string DisplayName = "IndieAuth Bearer";
}
