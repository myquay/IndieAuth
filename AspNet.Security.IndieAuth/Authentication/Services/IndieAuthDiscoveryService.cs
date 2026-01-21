using AspNet.Security.IndieAuth.Infrastructure;
using Microformats;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System.Text.Json;

namespace AspNet.Security.IndieAuth;

/// <summary>
/// Indicates which discovery method was used to find the endpoints.
/// </summary>
public enum DiscoveryMethod
{
    /// <summary>Unknown or not set.</summary>
    Unknown,
    /// <summary>Found via HTTP Link header with rel="indieauth-metadata".</summary>
    MetadataLinkHeader,
    /// <summary>Found via HTML &lt;link&gt; element with rel="indieauth-metadata".</summary>
    MetadataHtmlLink,
    /// <summary>Found via HTTP Link header with legacy authorization_endpoint/token_endpoint.</summary>
    LegacyLinkHeader,
    /// <summary>Found via HTML &lt;link&gt; elements with legacy authorization_endpoint/token_endpoint.</summary>
    LegacyHtmlLink,
    /// <summary>Result was returned from cache.</summary>
    Cached
}

/// <summary>
/// Result of IndieAuth endpoint discovery.
/// </summary>
public record DiscoveryResult(
    bool Success,
    string AuthorizationEndpoint,
    string TokenEndpoint,
    string? ErrorMessage = null,
    // Enhanced fields
    string? Issuer = null,
    string? UserinfoEndpoint = null,
    string? RevocationEndpoint = null,
    string? IntrospectionEndpoint = null,
    IReadOnlyList<string>? ScopesSupported = null,
    IReadOnlyList<string>? CodeChallengeMethods = null,
    DiscoveryMethod Method = DiscoveryMethod.Unknown,
    DateTimeOffset? DiscoveredAt = null);

/// <summary>
/// Options for configuring discovery behavior.
/// </summary>
public class DiscoveryOptions
{
    /// <summary>
    /// Whether to use HEAD request optimization. Default: false.
    /// </summary>
    public bool UseHeadRequest { get; set; }

    /// <summary>
    /// Whether to bypass the cache for this request. Default: false.
    /// </summary>
    public bool BypassCache { get; set; }

    /// <summary>
    /// Cache expiration for this specific request. If null, uses default.
    /// </summary>
    public TimeSpan? CacheExpiration { get; init; }
}

/// <summary>
/// Service for discovering IndieAuth endpoints from a user's profile URL.
/// Implements IndieAuth spec Section 4.1 - Discovery by Clients.
/// </summary>
public class IndieAuthDiscoveryService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;
    private readonly IDiscoveryCache? _cache;
    private readonly TimeSpan _defaultCacheExpiration;

    /// <summary>
    /// Creates a new discovery service.
    /// </summary>
    /// <param name="httpClient">The HTTP client for making requests.</param>
    /// <param name="logger">Optional logger.</param>
    /// <param name="cache">Optional discovery cache.</param>
    /// <param name="defaultCacheExpiration">Default cache expiration. Defaults to 5 minutes.</param>
    public IndieAuthDiscoveryService(
        HttpClient httpClient, 
        ILogger? logger = null,
        IDiscoveryCache? cache = null,
        TimeSpan? defaultCacheExpiration = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? NullLogger.Instance;
        _cache = cache;
        _defaultCacheExpiration = defaultCacheExpiration ?? TimeSpan.FromMinutes(5);
    }

    /// <summary>
    /// Discovers the IndieAuth authorization and token endpoints for the given profile URL.
    /// </summary>
    /// <param name="profileUrl">The user's profile URL.</param>
    /// <param name="options">Optional discovery options.</param>
    /// <remarks>
    /// Discovery follows the precedence defined in IndieAuth spec Section 4.1:
    /// 1. HTTP Link header with rel="indieauth-metadata"
    /// 2. HTML &lt;link&gt; element with rel="indieauth-metadata"
    /// 3. Legacy: HTTP Link header with rel="authorization_endpoint" and rel="token_endpoint"
    /// 4. Legacy: HTML &lt;link&gt; elements with rel="authorization_endpoint" and rel="token_endpoint"
    /// </remarks>
    public async Task<DiscoveryResult> DiscoverEndpointsAsync(string profileUrl, DiscoveryOptions? options = null)
    {
        options ??= new DiscoveryOptions();

        if (string.IsNullOrEmpty(profileUrl))
            return new DiscoveryResult(false, string.Empty, string.Empty, "Profile URL is required");

        // Check cache first (unless bypassed)
        if (_cache != null && !options.BypassCache)
        {
            var cached = await _cache.GetAsync(profileUrl);
            if (cached != null)
            {
                Log.DiscoveryCacheHit(_logger, profileUrl);
                return cached with { Method = DiscoveryMethod.Cached };
            }
            Log.DiscoveryCacheMiss(_logger, profileUrl);
        }

        Log.DiscoveryStarted(_logger, profileUrl);

        // Try HEAD request optimization if enabled
        if (options.UseHeadRequest)
        {
            var headResult = await TryHeadRequestDiscoveryAsync(profileUrl);
            if (headResult != null)
            {
                await CacheResultAsync(profileUrl, headResult, options);
                return headResult;
            }
            // Fall through to GET request
        }

        // Perform GET request discovery
        var result = await PerformGetDiscoveryAsync(profileUrl);
        
        if (result.Success)
        {
            await CacheResultAsync(profileUrl, result, options);
        }

        return result;
    }

    private async Task<DiscoveryResult?> TryHeadRequestDiscoveryAsync(string profileUrl)
    {
        Log.HeadRequestStarted(_logger, profileUrl);

        HttpResponseMessage headResponse;
        try
        {
            var headRequest = new HttpRequestMessage(HttpMethod.Head, profileUrl);
            headResponse = await _httpClient.SendAsync(headRequest);
        }
        catch (HttpRequestException)
        {
            // HEAD failed, fall back to GET
            Log.HeadRequestFailed(_logger, profileUrl);
            return null;
        }

        if (!headResponse.IsSuccessStatusCode)
        {
            return null;
        }

        var baseUri = headResponse.RequestMessage?.RequestUri ?? new Uri(profileUrl);
        var linkHeaders = headResponse.Headers.TryGetValues("Link", out var linkValues)
            ? linkValues.ToList()
            : null;

        // Check for indieauth-metadata in Link header
        var metadataUrl = LinkHeaderParser.FindFirstByRelResolved(linkHeaders, "indieauth-metadata", baseUri);
        if (!string.IsNullOrEmpty(metadataUrl))
        {
            Log.HeadRequestFoundMetadata(_logger, metadataUrl);
            return await FetchMetadataAndExtractEndpoints(metadataUrl, DiscoveryMethod.MetadataLinkHeader);
        }

        // Check for legacy endpoints in Link header
        var authEndpoint = LinkHeaderParser.FindFirstByRelResolved(linkHeaders, "authorization_endpoint", baseUri);
        var tokenEndpoint = LinkHeaderParser.FindFirstByRelResolved(linkHeaders, "token_endpoint", baseUri);

        if (!string.IsNullOrEmpty(authEndpoint) && !string.IsNullOrEmpty(tokenEndpoint))
        {
            Log.LegacyEndpointsFoundInLinkHeaders(_logger, authEndpoint, tokenEndpoint);
            return CreateResult(true, authEndpoint, tokenEndpoint, method: DiscoveryMethod.LegacyLinkHeader);
        }

        // No Link headers found, need to fall back to GET
        Log.HeadRequestFallbackToGet(_logger, profileUrl);
        return null;
    }

    private async Task<DiscoveryResult> PerformGetDiscoveryAsync(string profileUrl)
    {
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

        var baseUri = response.RequestMessage?.RequestUri ?? new Uri(profileUrl);
        Log.ProfileResolved(_logger, baseUri);

        var linkHeaders = response.Headers.TryGetValues("Link", out var linkValues)
            ? linkValues.ToList()
            : null;

        var htmlContent = await response.Content.ReadAsStringAsync();

        // 1. Check HTTP Link header for indieauth-metadata (highest precedence)
        var metadataUrl = LinkHeaderParser.FindFirstByRelResolved(linkHeaders, "indieauth-metadata", baseUri);
        if (!string.IsNullOrEmpty(metadataUrl))
        {
            Log.MetadataFoundInLinkHeader(_logger, metadataUrl);
            return await FetchMetadataAndExtractEndpoints(metadataUrl, DiscoveryMethod.MetadataLinkHeader);
        }

        // 2. Check HTML <link> elements for indieauth-metadata
        var mf2Result = new Mf2().Parse(htmlContent);

        if (mf2Result.Rels.ContainsKey("indieauth-metadata"))
        {
            var htmlMetadataUrl = mf2Result.Rels["indieauth-metadata"].First();
            var resolvedMetadataUrl = LinkHeaderParser.ResolveUrl(htmlMetadataUrl, baseUri);
            Log.MetadataFoundInHtml(_logger, resolvedMetadataUrl);
            return await FetchMetadataAndExtractEndpoints(resolvedMetadataUrl, DiscoveryMethod.MetadataHtmlLink);
        }

        // 3. Legacy fallback: Check HTTP Link header for authorization_endpoint and token_endpoint
        var authEndpointFromHeader = LinkHeaderParser.FindFirstByRelResolved(linkHeaders, "authorization_endpoint", baseUri);
        var tokenEndpointFromHeader = LinkHeaderParser.FindFirstByRelResolved(linkHeaders, "token_endpoint", baseUri);

        if (!string.IsNullOrEmpty(authEndpointFromHeader) && !string.IsNullOrEmpty(tokenEndpointFromHeader))
        {
            Log.LegacyEndpointsFoundInLinkHeaders(_logger, authEndpointFromHeader, tokenEndpointFromHeader);
            return CreateResult(true, authEndpointFromHeader, tokenEndpointFromHeader, method: DiscoveryMethod.LegacyLinkHeader);
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
            return CreateResult(true, authEndpointFromHtml, tokenEndpointFromHtml, method: DiscoveryMethod.LegacyHtmlLink);
        }

        Log.NoEndpointsFound(_logger, profileUrl);
        return new DiscoveryResult(false, string.Empty, string.Empty, "No IndieAuth endpoints found");
    }

    private async Task<DiscoveryResult> FetchMetadataAndExtractEndpoints(string metadataUrl, DiscoveryMethod method)
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
                
                return new DiscoveryResult(
                    Success: true,
                    AuthorizationEndpoint: metadata.AuthorizationEndpoint,
                    TokenEndpoint: metadata.TokenEndpoint,
                    ErrorMessage: null,
                    Issuer: metadata.Issuer,
                    UserinfoEndpoint: metadata.UserinfoEndpoint,
                    RevocationEndpoint: metadata.RevocationEndpoint,
                    IntrospectionEndpoint: metadata.IntrospectionEndpoint,
                    ScopesSupported: metadata.ScopesSupported?.ToList(),
                    CodeChallengeMethods: metadata.CodeChallengeMethodsSupported?.ToList(),
                    Method: method,
                    DiscoveredAt: DateTimeOffset.UtcNow);
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

    private async Task CacheResultAsync(string profileUrl, DiscoveryResult result, DiscoveryOptions options)
    {
        if (_cache == null)
            return;

        var expiration = options.CacheExpiration ?? _defaultCacheExpiration;
        await _cache.SetAsync(profileUrl, result, expiration);
        Log.DiscoveryResultCached(_logger, profileUrl, expiration);
    }

    private static DiscoveryResult CreateResult(
        bool success,
        string authEndpoint,
        string tokenEndpoint,
        string? errorMessage = null,
        DiscoveryMethod method = DiscoveryMethod.Unknown)
    {
        return new DiscoveryResult(
            Success: success,
            AuthorizationEndpoint: authEndpoint,
            TokenEndpoint: tokenEndpoint,
            ErrorMessage: errorMessage,
            Method: method,
            DiscoveredAt: success ? DateTimeOffset.UtcNow : null);
    }
}
