namespace AspNet.Security.IndieAuth;

/// <summary>
/// Extension methods for string manipulation in IndieAuth.
/// </summary>
public static class StringExtensions
{
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
}