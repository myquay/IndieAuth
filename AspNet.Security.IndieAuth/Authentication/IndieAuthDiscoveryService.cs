using AspNet.Security.IndieAuth.Infrastructure;
using Microformats;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System.Text.Json;

namespace AspNet.Security.IndieAuth;

/// <summary>
/// Result of IndieAuth endpoint discovery.
/// </summary>
public record DiscoveryResult(
    bool Success,
    string AuthorizationEndpoint,
    string TokenEndpoint,
    string? ErrorMessage = null);

/// <summary>
/// Service for discovering IndieAuth endpoints from a user's profile URL.
/// Implements IndieAuth spec Section 4.1 - Discovery by Clients.
/// </summary>
public class IndieAuthDiscoveryService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;

    public IndieAuthDiscoveryService(HttpClient httpClient, ILogger? logger = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Discovers the IndieAuth authorization and token endpoints for the given profile URL.
    /// </summary>
    /// <remarks>
    /// Discovery follows the precedence defined in IndieAuth spec Section 4.1:
    /// 1. HTTP Link header with rel="indieauth-metadata"
    /// 2. HTML &lt;link&gt; element with rel="indieauth-metadata"
    /// 3. Legacy: HTTP Link header with rel="authorization_endpoint" and rel="token_endpoint"
    /// 4. Legacy: HTML &lt;link&gt; elements with rel="authorization_endpoint" and rel="token_endpoint"
    /// </remarks>
    public async Task<DiscoveryResult> DiscoverEndpointsAsync(string profileUrl)
    {
        if (string.IsNullOrEmpty(profileUrl))
            return new DiscoveryResult(false, string.Empty, string.Empty, "Profile URL is required");

        Log.DiscoveryStarted(_logger, profileUrl);

        // Fetch the user's profile URL
        HttpResponseMessage response;
        try
        {
            response = await _httpClient.GetAsync(profileUrl);
        }
        catch (HttpRequestException ex)
        {
            return new DiscoveryResult(false, string.Empty, string.Empty, $"Failed to fetch profile URL: {ex.Message}");
        }

        if (!response.IsSuccessStatusCode)
        {
            Log.ProfileFetchFailed(_logger, profileUrl, response.StatusCode);
            return new DiscoveryResult(false, string.Empty, string.Empty, $"Profile URL returned {response.StatusCode}");
        }

        // Get the final URL after redirects for resolving relative URLs
        var baseUri = response.RequestMessage?.RequestUri ?? new Uri(profileUrl);
        Log.ProfileResolved(_logger, baseUri);

        // Get Link header values
        var linkHeaders = response.Headers.TryGetValues("Link", out var linkValues)
            ? linkValues.ToList()
            : null;

        // Read HTML content for fallback parsing
        var htmlContent = await response.Content.ReadAsStringAsync();

        // 1. Check HTTP Link header for indieauth-metadata (highest precedence)
        var metadataUrl = LinkHeaderParser.FindFirstByRelResolved(linkHeaders, "indieauth-metadata", baseUri);
        if (!string.IsNullOrEmpty(metadataUrl))
        {
            Log.MetadataFoundInLinkHeader(_logger, metadataUrl);
            return await FetchMetadataAndExtractEndpoints(metadataUrl);
        }

        // 2. Check HTML <link> elements for indieauth-metadata
        var mf2Result = new Mf2().Parse(htmlContent);

        if (mf2Result.Rels.ContainsKey("indieauth-metadata"))
        {
            var htmlMetadataUrl = mf2Result.Rels["indieauth-metadata"].First();
            var resolvedMetadataUrl = LinkHeaderParser.ResolveUrl(htmlMetadataUrl, baseUri);
            Log.MetadataFoundInHtml(_logger, resolvedMetadataUrl);
            return await FetchMetadataAndExtractEndpoints(resolvedMetadataUrl);
        }

        // 3. Legacy fallback: Check HTTP Link header for authorization_endpoint and token_endpoint
        var authEndpointFromHeader = LinkHeaderParser.FindFirstByRelResolved(linkHeaders, "authorization_endpoint", baseUri);
        var tokenEndpointFromHeader = LinkHeaderParser.FindFirstByRelResolved(linkHeaders, "token_endpoint", baseUri);

        if (!string.IsNullOrEmpty(authEndpointFromHeader) && !string.IsNullOrEmpty(tokenEndpointFromHeader))
        {
            Log.LegacyEndpointsFoundInLinkHeaders(_logger, authEndpointFromHeader, tokenEndpointFromHeader);
            return new DiscoveryResult(true, authEndpointFromHeader, tokenEndpointFromHeader);
        }

        // 4. Legacy fallback: Check HTML <link> elements for authorization_endpoint and token_endpoint
        var authEndpointFromHtml = mf2Result.Rels.ContainsKey("authorization_endpoint")
            ? LinkHeaderParser.ResolveUrl(mf2Result.Rels["authorization_endpoint"].First(), baseUri)
            : null;
        var tokenEndpointFromHtml = mf2Result.Rels.ContainsKey("token_endpoint")
            ? LinkHeaderParser.ResolveUrl(mf2Result.Rels["token_endpoint"].First(), baseUri)
            : null;

        if (!string.IsNullOrEmpty(authEndpointFromHtml) && !string.IsNullOrEmpty(tokenEndpointFromHtml))
        {
            Log.LegacyEndpointsFoundInHtml(_logger, authEndpointFromHtml, tokenEndpointFromHtml);
            return new DiscoveryResult(true, authEndpointFromHtml, tokenEndpointFromHtml);
        }

        Log.NoEndpointsFound(_logger, profileUrl);
        return new DiscoveryResult(false, string.Empty, string.Empty, "No IndieAuth endpoints found");
    }

    private async Task<DiscoveryResult> FetchMetadataAndExtractEndpoints(string metadataUrl)
    {
        Log.FetchingMetadata(_logger, metadataUrl);

        HttpResponseMessage metadataResponse;
        try
        {
            metadataResponse = await _httpClient.GetAsync(metadataUrl);
        }
        catch (HttpRequestException ex)
        {
            return new DiscoveryResult(false, string.Empty, string.Empty, $"Failed to fetch metadata: {ex.Message}");
        }

        if (!metadataResponse.IsSuccessStatusCode)
        {
            Log.MetadataFetchFailed(_logger, metadataUrl, metadataResponse.StatusCode);
            return new DiscoveryResult(false, string.Empty, string.Empty, $"Metadata URL returned {metadataResponse.StatusCode}");
        }

        try
        {
            var metadata = JsonSerializer.Deserialize<IndieAuthServerMetadataResponse>(
                await metadataResponse.Content.ReadAsStreamAsync(),
                new JsonSerializerOptions { PropertyNamingPolicy = new SnakeCaseNamingPolicy() });

            if (metadata != null &&
                !string.IsNullOrEmpty(metadata.AuthorizationEndpoint) &&
                !string.IsNullOrEmpty(metadata.TokenEndpoint))
            {
                Log.EndpointsExtractedFromMetadata(_logger, metadata.AuthorizationEndpoint, metadata.TokenEndpoint);
                return new DiscoveryResult(true, metadata.AuthorizationEndpoint, metadata.TokenEndpoint);
            }

            Log.MetadataMissingEndpoints(_logger);
            return new DiscoveryResult(false, string.Empty, string.Empty, "Metadata missing required endpoints");
        }
        catch (JsonException ex)
        {
            Log.MetadataParsingFailed(_logger, ex, metadataUrl);
            return new DiscoveryResult(false, string.Empty, string.Empty, $"Invalid metadata JSON: {ex.Message}");
        }
    }
}
