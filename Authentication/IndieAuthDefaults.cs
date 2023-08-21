namespace AspNet.Security.IndieAuth;

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
    /// The default display name for IndieAuth authentication.
    /// </summary>
    public static readonly string DisplayName = "IndieAuth";
}