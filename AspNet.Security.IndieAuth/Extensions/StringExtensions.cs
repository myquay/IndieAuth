using System.Net;

namespace AspNet.Security.IndieAuth;

/// <summary>
/// Extension methods for string manipulation in IndieAuth.
/// </summary>
public static class StringExtensions
{
    private static readonly char[] s_pathSeparators = ['/', '?', '#'];
    /// <summary>
    /// Canonicalizes a URL according to IndieAuth specification section 3.4.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This method applies the following transformations per the IndieAuth spec:
    /// </para>
    /// <list type="bullet">
    ///   <item>If no scheme is present, prepends "https://"</item>
    ///   <item>Converts the host component to lowercase (domain names are case-insensitive)</item>
    ///   <item>Ensures the path ends with "/" if empty</item>
    ///   <item>Removes any fragment component</item>
    /// </list>
    /// <para>
    /// See: https://indieauth.spec.indieweb.org/#url-canonicalization
    /// </para>
    /// </remarks>
    /// <param name="uri">The URL string to canonicalize.</param>
    /// <returns>The canonicalized URL string, or the original value if null/empty.</returns>
    public static string Canonicalize(this string uri)
    {
        if (string.IsNullOrEmpty(uri))
            return uri;

        // Handle host-only input (e.g., "example.com")
        // Per spec: clients MAY allow users to enter just the host part,
        // in which case prepend https:// scheme
        if (!uri.Contains("://", StringComparison.Ordinal))
        {
            uri = "https://" + uri;
        }

        var uriBuilder = new UriBuilder(uri);

        // Per spec: domain names are case insensitive, so convert host to lowercase
        // SHOULD convert the host to lowercase when storing and using URLs
        uriBuilder.Host = uriBuilder.Host.ToLowerInvariant();

        // Per spec: a URL with no path component MUST be treated as if it had the path /
        if (string.IsNullOrEmpty(uriBuilder.Path) || uriBuilder.Path == "/")
            uriBuilder.Path = "/";

        // Remove fragment component (per spec section 2.1)
        uriBuilder.Fragment = string.Empty;

        return uriBuilder.Uri.ToString();
    }

    /// <summary>
    /// Validates a URL against IndieAuth profile URL requirements (spec section 3.2).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Profile URLs have the following requirements per the IndieAuth spec:
    /// </para>
    /// <list type="bullet">
    ///   <item>MUST have either an https or http scheme</item>
    ///   <item>MUST contain a path component (/ is a valid path)</item>
    ///   <item>MUST NOT contain single-dot or double-dot path segments</item>
    ///   <item>MAY contain a query string component</item>
    ///   <item>MUST NOT contain a fragment component</item>
    ///   <item>MUST NOT contain a username or password component</item>
    ///   <item>MUST NOT contain a port</item>
    ///   <item>Host MUST be a domain name and MUST NOT be an IPv4 or IPv6 address</item>
    /// </list>
    /// <para>
    /// See: https://indieauth.spec.indieweb.org/#user-profile-url
    /// </para>
    /// </remarks>
    /// <param name="url">The URL string to validate.</param>
    /// <returns>A validation result indicating whether the URL is valid and any error details.</returns>
    public static ProfileUrlValidationResult IsValidProfileUrl(this string? url)
    {
        // Check for null or empty
        if (string.IsNullOrEmpty(url))
        {
            return ProfileUrlValidationResult.NullOrEmpty();
        }

        // Try to parse the URL
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return ProfileUrlValidationResult.MalformedUrl(url);
        }

        // MUST have http or https scheme
        if (!uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase) &&
            !uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            return ProfileUrlValidationResult.InvalidScheme(uri.Scheme);
        }

        // MUST contain a path component (/ is valid)
        // Uri.AbsolutePath always returns at least "/" for http/https URLs
        if (string.IsNullOrEmpty(uri.AbsolutePath))
        {
            return ProfileUrlValidationResult.MissingPath();
        }

        // MUST NOT contain single-dot or double-dot path segments
        var pathSegments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        foreach (var segment in pathSegments)
        {
            if (segment == "." || segment == "..")
            {
                return ProfileUrlValidationResult.DotPathSegment(segment);
            }
        }

        // Also check the original URL for encoded dot segments or unresolved ones
        // Uri.TryCreate normalizes .. segments, so we need to check the original string
        if (url.Contains("/../", StringComparison.Ordinal) ||
            url.Contains("/./", StringComparison.Ordinal) ||
            url.EndsWith("/..", StringComparison.Ordinal) ||
            url.EndsWith("/.", StringComparison.Ordinal))
        {
            return ProfileUrlValidationResult.DotPathSegment("..");
        }

        // MUST NOT contain a fragment component
        if (!string.IsNullOrEmpty(uri.Fragment))
        {
            return ProfileUrlValidationResult.ContainsFragment();
        }

        // MUST NOT contain a username component
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            // UserInfo contains "username" or "username:password"
            if (uri.UserInfo.Contains(':'))
            {
                var parts = uri.UserInfo.Split(':');
                if (!string.IsNullOrEmpty(parts[0]))
                {
                    return ProfileUrlValidationResult.ContainsUsername();
                }
                if (parts.Length > 1 && !string.IsNullOrEmpty(parts[1]))
                {
                    return ProfileUrlValidationResult.ContainsPassword();
                }
            }
            else
            {
                return ProfileUrlValidationResult.ContainsUsername();
            }
        }

        // MUST NOT contain a port
        // Uri.IsDefaultPort is true when no explicit port or default port (80/443)
        if (!uri.IsDefaultPort)
        {
            return ProfileUrlValidationResult.ContainsPort(uri.Port);
        }

        // Check if explicit default port was specified in original URL
        // e.g., "https://example.com:443/" should be rejected
        if (HasExplicitPort(url))
        {
            return ProfileUrlValidationResult.ContainsPort(uri.Port);
        }

        // Host MUST be a domain name, MUST NOT be IPv4 or IPv6 address
        var host = uri.Host;

        // Check for IPv4 address
        if (IPAddress.TryParse(host, out var ipAddress))
        {
            if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                return ProfileUrlValidationResult.HostIsIPv4Address(host);
            }
            if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                return ProfileUrlValidationResult.HostIsIPv6Address(host);
            }
        }

        // Check for IPv6 address in brackets (e.g., [::1])
        if (uri.HostNameType == UriHostNameType.IPv6)
        {
            return ProfileUrlValidationResult.HostIsIPv6Address(host);
        }

        return ProfileUrlValidationResult.Success();
    }

    /// <summary>
    /// Checks if a URL string contains an explicit port specification.
    /// </summary>
    private static bool HasExplicitPort(string url)
    {
        // Find the authority section (after :// and before path)
        var schemeEnd = url.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd < 0) return false;

        var authorityStart = schemeEnd + 3;
        var authorityEnd = url.IndexOfAny(s_pathSeparators, authorityStart);
        if (authorityEnd < 0) authorityEnd = url.Length;

        var authority = url[authorityStart..authorityEnd];

        // Remove userinfo if present
        var atIndex = authority.IndexOf('@');
        if (atIndex >= 0)
        {
            authority = authority[(atIndex + 1)..];
        }

        // Check for port (handle IPv6 addresses in brackets)
        if (authority.StartsWith('['))
        {
            // IPv6: look for ]:port
            var bracketEnd = authority.IndexOf(']');
            if (bracketEnd >= 0 && bracketEnd < authority.Length - 1)
            {
                return authority[bracketEnd + 1] == ':';
            }
            return false;
        }

        // Regular host:port
        return authority.Contains(':');
    }
}