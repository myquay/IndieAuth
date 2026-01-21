using System.Text.RegularExpressions;

namespace AspNet.Security.IndieAuth.Infrastructure;

/// <summary>
/// Parses HTTP Link headers according to RFC 8288.
/// </summary>
/// <remarks>
/// Link headers follow the format: &lt;url&gt;; rel="relation"; other-param="value"
/// Multiple links can be separated by commas or provided in separate headers.
/// See: https://tools.ietf.org/html/rfc8288
/// </remarks>
public static class LinkHeaderParser
{
    /// <summary>
    /// Represents a parsed Link header entry.
    /// </summary>
    public record LinkHeader(string Url, string Rel);

    // Regex to match individual link entries: <url>; params
    private static readonly Regex LinkEntryRegex = new(@"<([^>]+)>\s*;?\s*([^,]*)", RegexOptions.Compiled);

    // Regex to extract rel parameter value (quoted or unquoted)
    private static readonly Regex RelParameterRegex = new(@"rel\s*=\s*""?([^""\s;,]+)""?", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Parses all Link header values and extracts link entries.
    /// </summary>
    /// <param name="linkHeaderValues">The Link header values (may contain multiple comma-separated links).</param>
    /// <returns>A collection of parsed link headers in order of appearance.</returns>
    public static IEnumerable<LinkHeader> Parse(IEnumerable<string>? linkHeaderValues)
    {
        if (linkHeaderValues == null)
            yield break;

        foreach (var headerValue in linkHeaderValues)
        {
            if (string.IsNullOrWhiteSpace(headerValue))
                continue;

            foreach (var link in ParseSingleHeader(headerValue))
                yield return link;
        }
    }

    /// <summary>
    /// Parses a single Link header value which may contain multiple comma-separated links.
    /// </summary>
    /// <param name="headerValue">The Link header value.</param>
    /// <returns>A collection of parsed link headers.</returns>
    public static IEnumerable<LinkHeader> ParseSingleHeader(string? headerValue)
    {
        if (string.IsNullOrWhiteSpace(headerValue))
            yield break;

        var matches = LinkEntryRegex.Matches(headerValue);

        foreach (Match match in matches)
        {
            if (!match.Success || match.Groups.Count < 2)
                continue;

            var url = match.Groups[1].Value.Trim();
            var parameters = match.Groups.Count > 2 ? match.Groups[2].Value : string.Empty;

            var relMatch = RelParameterRegex.Match(parameters);
            if (relMatch.Success)
            {
                var rel = relMatch.Groups[1].Value.Trim();
                yield return new LinkHeader(url, rel);
            }
        }
    }

    /// <summary>
    /// Finds the first URL with the specified rel value from Link headers.
    /// </summary>
    /// <param name="linkHeaderValues">The Link header values.</param>
    /// <param name="rel">The rel value to search for (case-insensitive).</param>
    /// <returns>The first matching URL, or null if not found.</returns>
    public static string? FindFirstByRel(IEnumerable<string>? linkHeaderValues, string rel)
    {
        if (linkHeaderValues == null || string.IsNullOrEmpty(rel))
            return null;

        return Parse(linkHeaderValues)
            .FirstOrDefault(link => string.Equals(link.Rel, rel, StringComparison.OrdinalIgnoreCase))
            ?.Url;
    }

    /// <summary>
    /// Finds the first URL with the specified rel value and resolves it against a base URI.
    /// </summary>
    /// <param name="linkHeaderValues">The Link header values.</param>
    /// <param name="rel">The rel value to search for (case-insensitive).</param>
    /// <param name="baseUri">The base URI to resolve relative URLs against.</param>
    /// <returns>The first matching URL resolved to an absolute URL, or null if not found.</returns>
    public static string? FindFirstByRelResolved(IEnumerable<string>? linkHeaderValues, string rel, Uri? baseUri)
    {
        var url = FindFirstByRel(linkHeaderValues, rel);
        if (string.IsNullOrEmpty(url))
            return null;
        return ResolveUrl(url, baseUri);
    }

    /// <summary>
    /// Resolves a URL against a base URI, handling both absolute and relative URLs.
    /// </summary>
    /// <param name="url">The URL to resolve (may be relative or absolute).</param>
    /// <param name="baseUri">The base URI to resolve against.</param>
    /// <returns>The resolved absolute URL, or the original URL if resolution fails.</returns>
    public static string ResolveUrl(string url, Uri? baseUri)
    {
        if (string.IsNullOrEmpty(url))
            return url;

        // Check if it's an absolute URL with an HTTP/HTTPS scheme.
        // We can't rely on Uri.TryCreate with UriKind.Absolute alone because paths like "/metadata"
        // get interpreted as file:// URIs on Unix systems.
        if (Uri.TryCreate(url, UriKind.Absolute, out var absoluteUri) &&
            (absoluteUri.Scheme == Uri.UriSchemeHttp || absoluteUri.Scheme == Uri.UriSchemeHttps))
        {
            return absoluteUri.ToString();
        }

        // Treat as relative URL and resolve against base
        if (baseUri != null && Uri.TryCreate(baseUri, url, out var resolvedUri))
            return resolvedUri.ToString();

        return url;
    }
}
