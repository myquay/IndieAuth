namespace AspNet.Security.IndieAuth;

/// <summary>
/// Error codes for profile URL validation failures.
/// These correspond to the validation requirements in IndieAuth spec section 3.2.
/// </summary>
public enum ProfileUrlValidationError
{
    /// <summary>No error - the URL is valid.</summary>
    None = 0,

    /// <summary>The URL is null or empty.</summary>
    NullOrEmpty,

    /// <summary>The URL is not a well-formed URI.</summary>
    MalformedUrl,

    /// <summary>The URL scheme is not http or https (spec: MUST have http or https scheme).</summary>
    InvalidScheme,

    /// <summary>The URL does not contain a path component (spec: MUST contain a path component).</summary>
    MissingPath,

    /// <summary>The URL contains single-dot or double-dot path segments (spec: MUST NOT contain . or .. segments).</summary>
    DotPathSegment,

    /// <summary>The URL contains a fragment component (spec: MUST NOT contain a fragment).</summary>
    ContainsFragment,

    /// <summary>The URL contains a username component (spec: MUST NOT contain username).</summary>
    ContainsUsername,

    /// <summary>The URL contains a password component (spec: MUST NOT contain password).</summary>
    ContainsPassword,

    /// <summary>The URL contains a port (spec: profile URLs MUST NOT contain a port).</summary>
    ContainsPort,

    /// <summary>The host is an IPv4 address (spec: host MUST be a domain name, not IP address).</summary>
    HostIsIPv4Address,

    /// <summary>The host is an IPv6 address (spec: host MUST be a domain name, not IP address).</summary>
    HostIsIPv6Address
}

/// <summary>
/// Result of validating a profile URL against IndieAuth spec section 3.2 requirements.
/// </summary>
/// <param name="IsValid">Whether the URL is a valid profile URL.</param>
/// <param name="ErrorCode">The error code if validation failed.</param>
/// <param name="ErrorMessage">Human-readable error message if validation failed.</param>
public readonly record struct ProfileUrlValidationResult(
    bool IsValid,
    ProfileUrlValidationError ErrorCode,
    string? ErrorMessage)
{
    /// <summary>
    /// Creates a successful validation result.
    /// </summary>
    public static ProfileUrlValidationResult Success() =>
        new(true, ProfileUrlValidationError.None, null);

    /// <summary>
    /// Creates a failed validation result for null or empty input.
    /// </summary>
    public static ProfileUrlValidationResult NullOrEmpty() =>
        new(false, ProfileUrlValidationError.NullOrEmpty, "Profile URL is null or empty.");

    /// <summary>
    /// Creates a failed validation result for a malformed URL.
    /// </summary>
    public static ProfileUrlValidationResult MalformedUrl(string url) =>
        new(false, ProfileUrlValidationError.MalformedUrl, $"'{url}' is not a well-formed URL.");

    /// <summary>
    /// Creates a failed validation result for an invalid scheme.
    /// </summary>
    public static ProfileUrlValidationResult InvalidScheme(string scheme) =>
        new(false, ProfileUrlValidationError.InvalidScheme,
            $"Profile URL scheme '{scheme}' is not valid. Must be 'http' or 'https'.");

    /// <summary>
    /// Creates a failed validation result for a missing path.
    /// </summary>
    public static ProfileUrlValidationResult MissingPath() =>
        new(false, ProfileUrlValidationError.MissingPath,
            "Profile URL must contain a path component ('/' is valid).");

    /// <summary>
    /// Creates a failed validation result for dot path segments.
    /// </summary>
    public static ProfileUrlValidationResult DotPathSegment(string segment) =>
        new(false, ProfileUrlValidationError.DotPathSegment,
            $"Profile URL must not contain '{segment}' path segments.");

    /// <summary>
    /// Creates a failed validation result for a fragment.
    /// </summary>
    public static ProfileUrlValidationResult ContainsFragment() =>
        new(false, ProfileUrlValidationError.ContainsFragment,
            "Profile URL must not contain a fragment component.");

    /// <summary>
    /// Creates a failed validation result for a username.
    /// </summary>
    public static ProfileUrlValidationResult ContainsUsername() =>
        new(false, ProfileUrlValidationError.ContainsUsername,
            "Profile URL must not contain a username component.");

    /// <summary>
    /// Creates a failed validation result for a password.
    /// </summary>
    public static ProfileUrlValidationResult ContainsPassword() =>
        new(false, ProfileUrlValidationError.ContainsPassword,
            "Profile URL must not contain a password component.");

    /// <summary>
    /// Creates a failed validation result for a port.
    /// </summary>
    public static ProfileUrlValidationResult ContainsPort(int port) =>
        new(false, ProfileUrlValidationError.ContainsPort,
            $"Profile URL must not contain a port (found port {port}).");

    /// <summary>
    /// Creates a failed validation result for an IPv4 host.
    /// </summary>
    public static ProfileUrlValidationResult HostIsIPv4Address(string host) =>
        new(false, ProfileUrlValidationError.HostIsIPv4Address,
            $"Profile URL host '{host}' is an IPv4 address. Host must be a domain name.");

    /// <summary>
    /// Creates a failed validation result for an IPv6 host.
    /// </summary>
    public static ProfileUrlValidationResult HostIsIPv6Address(string host) =>
        new(false, ProfileUrlValidationError.HostIsIPv6Address,
            $"Profile URL host '{host}' is an IPv6 address. Host must be a domain name.");
}
