using System.Net;
using Microsoft.Extensions.Logging;

namespace AspNet.Security.IndieAuth;

/// <summary>
/// High-performance logging using LoggerMessage delegates for IndieAuth discovery.
/// </summary>
internal static class Log
{
    private static readonly Action<ILogger, string?, Exception?> _discoveryStarted =
        LoggerMessage.Define<string?>(LogLevel.Debug, new EventId(1, nameof(DiscoveryStarted)),
            "Starting IndieAuth endpoint discovery for {ProfileUrl}");

    private static readonly Action<ILogger, string?, HttpStatusCode, Exception?> _profileFetchFailed =
        LoggerMessage.Define<string?, HttpStatusCode>(LogLevel.Warning, new EventId(2, nameof(ProfileFetchFailed)),
            "Failed to fetch profile URL {ProfileUrl}: {StatusCode}");

    private static readonly Action<ILogger, Uri, Exception?> _profileResolved =
        LoggerMessage.Define<Uri>(LogLevel.Debug, new EventId(3, nameof(ProfileResolved)),
            "Profile URL resolved to {BaseUri} after redirects");

    private static readonly Action<ILogger, string, Exception?> _metadataFoundInLinkHeader =
        LoggerMessage.Define<string>(LogLevel.Debug, new EventId(4, nameof(MetadataFoundInLinkHeader)),
            "Found indieauth-metadata in HTTP Link header: {MetadataUrl}");

    private static readonly Action<ILogger, string, Exception?> _metadataFoundInHtml =
        LoggerMessage.Define<string>(LogLevel.Debug, new EventId(5, nameof(MetadataFoundInHtml)),
            "Found indieauth-metadata in HTML: {MetadataUrl}");

    private static readonly Action<ILogger, string, string, Exception?> _legacyEndpointsFoundInLinkHeaders =
        LoggerMessage.Define<string, string>(LogLevel.Debug, new EventId(6, nameof(LegacyEndpointsFoundInLinkHeaders)),
            "Found legacy endpoints in HTTP Link headers: auth={AuthEndpoint}, token={TokenEndpoint}");

    private static readonly Action<ILogger, string, string, Exception?> _legacyEndpointsFoundInHtml =
        LoggerMessage.Define<string, string>(LogLevel.Debug, new EventId(7, nameof(LegacyEndpointsFoundInHtml)),
            "Found legacy endpoints in HTML: auth={AuthEndpoint}, token={TokenEndpoint}");

    private static readonly Action<ILogger, string?, Exception?> _noEndpointsFound =
        LoggerMessage.Define<string?>(LogLevel.Warning, new EventId(8, nameof(NoEndpointsFound)),
            "No IndieAuth endpoints found for {ProfileUrl}");

    private static readonly Action<ILogger, string, Exception?> _fetchingMetadata =
        LoggerMessage.Define<string>(LogLevel.Debug, new EventId(9, nameof(FetchingMetadata)),
            "Fetching IndieAuth metadata from {MetadataUrl}");

    private static readonly Action<ILogger, string, HttpStatusCode, Exception?> _metadataFetchFailed =
        LoggerMessage.Define<string, HttpStatusCode>(LogLevel.Warning, new EventId(10, nameof(MetadataFetchFailed)),
            "Failed to fetch IndieAuth metadata from {MetadataUrl}: {StatusCode}");

    private static readonly Action<ILogger, string, string, Exception?> _endpointsExtractedFromMetadata =
        LoggerMessage.Define<string, string>(LogLevel.Debug, new EventId(11, nameof(EndpointsExtractedFromMetadata)),
            "Extracted endpoints from metadata: auth={AuthEndpoint}, token={TokenEndpoint}");

    private static readonly Action<ILogger, Exception?> _metadataMissingEndpoints =
        LoggerMessage.Define(LogLevel.Warning, new EventId(12, nameof(MetadataMissingEndpoints)),
            "IndieAuth metadata missing required endpoints");

    private static readonly Action<ILogger, string, Exception?> _metadataParsingFailed =
        LoggerMessage.Define<string>(LogLevel.Warning, new EventId(13, nameof(MetadataParsingFailed)),
            "Failed to parse IndieAuth metadata from {MetadataUrl}");

    // Cache-related logging
    private static readonly Action<ILogger, string, Exception?> _discoveryCacheHit =
        LoggerMessage.Define<string>(LogLevel.Debug, new EventId(14, nameof(DiscoveryCacheHit)),
            "Discovery cache hit for {ProfileUrl}");

    private static readonly Action<ILogger, string, Exception?> _discoveryCacheMiss =
        LoggerMessage.Define<string>(LogLevel.Debug, new EventId(15, nameof(DiscoveryCacheMiss)),
            "Discovery cache miss for {ProfileUrl}");

    private static readonly Action<ILogger, string, TimeSpan, Exception?> _discoveryResultCached =
        LoggerMessage.Define<string, TimeSpan>(LogLevel.Debug, new EventId(16, nameof(DiscoveryResultCached)),
            "Cached discovery result for {ProfileUrl} with expiration {Expiration}");

    // HEAD request optimization logging
    private static readonly Action<ILogger, string, Exception?> _headRequestStarted =
        LoggerMessage.Define<string>(LogLevel.Debug, new EventId(17, nameof(HeadRequestStarted)),
            "Starting HEAD request for {ProfileUrl}");

    private static readonly Action<ILogger, string, Exception?> _headRequestFailed =
        LoggerMessage.Define<string>(LogLevel.Debug, new EventId(18, nameof(HeadRequestFailed)),
            "HEAD request failed for {ProfileUrl}, falling back to GET");

    private static readonly Action<ILogger, string, Exception?> _headRequestFoundMetadata =
        LoggerMessage.Define<string>(LogLevel.Debug, new EventId(19, nameof(HeadRequestFoundMetadata)),
            "HEAD request found indieauth-metadata in Link header: {MetadataUrl}");

    private static readonly Action<ILogger, string, Exception?> _headRequestFallbackToGet =
        LoggerMessage.Define<string>(LogLevel.Debug, new EventId(20, nameof(HeadRequestFallbackToGet)),
            "HEAD request found no Link headers for {ProfileUrl}, falling back to GET");

    // Profile URL validation logging
    private static readonly Action<ILogger, string, string, Exception?> _profileUrlValidationFailed =
        LoggerMessage.Define<string, string>(LogLevel.Warning, new EventId(21, nameof(ProfileUrlValidationFailed)),
            "Profile URL validation failed for {ProfileUrl}: {Reason}");

    // Authorization Server Confirmation logging
    private static readonly Action<ILogger, string, Exception?> _authServerConfirmationExactMatch =
        LoggerMessage.Define<string>(LogLevel.Debug, new EventId(22, nameof(AuthServerConfirmationExactMatch)),
            "Authorization server confirmation: exact match for {ReturnedUrl}");

    private static readonly Action<ILogger, string, string, Exception?> _authServerConfirmationRedirectMatch =
        LoggerMessage.Define<string, string>(LogLevel.Debug, new EventId(23, nameof(AuthServerConfirmationRedirectMatch)),
            "Authorization server confirmation: redirect chain match for {ReturnedUrl} (matched {DiscoveredUrl})");

    private static readonly Action<ILogger, string, Exception?> _authServerConfirmationReDiscovery =
        LoggerMessage.Define<string>(LogLevel.Debug, new EventId(24, nameof(AuthServerConfirmationReDiscovery)),
            "Authorization server confirmation: performing re-discovery for {ReturnedUrl}");

    private static readonly Action<ILogger, string, string?, Exception?> _authServerConfirmationReDiscoveryFailed =
        LoggerMessage.Define<string, string?>(LogLevel.Warning, new EventId(25, nameof(AuthServerConfirmationReDiscoveryFailed)),
            "Authorization server confirmation: re-discovery failed for {ReturnedUrl}: {Error}");

    private static readonly Action<ILogger, string, string, Exception?> _authServerConfirmationReDiscoverySuccess =
        LoggerMessage.Define<string, string>(LogLevel.Debug, new EventId(26, nameof(AuthServerConfirmationReDiscoverySuccess)),
            "Authorization server confirmation: re-discovery confirmed same auth endpoint for {ReturnedUrl}: {AuthEndpoint}");

    private static readonly Action<ILogger, string, string, string, Exception?> _authServerConfirmationMismatch =
        LoggerMessage.Define<string, string, string>(LogLevel.Warning, new EventId(27, nameof(AuthServerConfirmationMismatch)),
            "Authorization server confirmation: endpoint mismatch for {ReturnedUrl}. Original: {OriginalEndpoint}, Returned: {ReturnedEndpoint}");

    internal static void DiscoveryStarted(ILogger logger, string? profileUrl)
        => _discoveryStarted(logger, profileUrl, null);

    internal static void ProfileFetchFailed(ILogger logger, string? profileUrl, HttpStatusCode statusCode)
        => _profileFetchFailed(logger, profileUrl, statusCode, null);

    internal static void ProfileResolved(ILogger logger, Uri baseUri)
        => _profileResolved(logger, baseUri, null);

    internal static void MetadataFoundInLinkHeader(ILogger logger, string metadataUrl)
        => _metadataFoundInLinkHeader(logger, metadataUrl, null);

    internal static void MetadataFoundInHtml(ILogger logger, string metadataUrl)
        => _metadataFoundInHtml(logger, metadataUrl, null);

    internal static void LegacyEndpointsFoundInLinkHeaders(ILogger logger, string authEndpoint, string tokenEndpoint)
        => _legacyEndpointsFoundInLinkHeaders(logger, authEndpoint, tokenEndpoint, null);

    internal static void LegacyEndpointsFoundInHtml(ILogger logger, string authEndpoint, string tokenEndpoint)
        => _legacyEndpointsFoundInHtml(logger, authEndpoint, tokenEndpoint, null);

    internal static void NoEndpointsFound(ILogger logger, string? profileUrl)
        => _noEndpointsFound(logger, profileUrl, null);

    internal static void FetchingMetadata(ILogger logger, string metadataUrl)
        => _fetchingMetadata(logger, metadataUrl, null);

    internal static void MetadataFetchFailed(ILogger logger, string metadataUrl, HttpStatusCode statusCode)
        => _metadataFetchFailed(logger, metadataUrl, statusCode, null);

    internal static void EndpointsExtractedFromMetadata(ILogger logger, string authEndpoint, string tokenEndpoint)
        => _endpointsExtractedFromMetadata(logger, authEndpoint, tokenEndpoint, null);

    internal static void MetadataMissingEndpoints(ILogger logger)
        => _metadataMissingEndpoints(logger, null);

    internal static void MetadataParsingFailed(ILogger logger, Exception exception, string metadataUrl)
        => _metadataParsingFailed(logger, metadataUrl, exception);

    internal static void DiscoveryCacheHit(ILogger logger, string profileUrl)
        => _discoveryCacheHit(logger, profileUrl, null);

    internal static void DiscoveryCacheMiss(ILogger logger, string profileUrl)
        => _discoveryCacheMiss(logger, profileUrl, null);

    internal static void DiscoveryResultCached(ILogger logger, string profileUrl, TimeSpan expiration)
        => _discoveryResultCached(logger, profileUrl, expiration, null);

    internal static void HeadRequestStarted(ILogger logger, string profileUrl)
        => _headRequestStarted(logger, profileUrl, null);

    internal static void HeadRequestFailed(ILogger logger, string profileUrl)
        => _headRequestFailed(logger, profileUrl, null);

    internal static void HeadRequestFoundMetadata(ILogger logger, string metadataUrl)
        => _headRequestFoundMetadata(logger, metadataUrl, null);

    internal static void HeadRequestFallbackToGet(ILogger logger, string profileUrl)
        => _headRequestFallbackToGet(logger, profileUrl, null);

    internal static void ProfileUrlValidationFailed(ILogger logger, string profileUrl, string reason)
        => _profileUrlValidationFailed(logger, profileUrl, reason, null);

    internal static void AuthServerConfirmationExactMatch(ILogger logger, string returnedUrl)
        => _authServerConfirmationExactMatch(logger, returnedUrl, null);

    internal static void AuthServerConfirmationRedirectMatch(ILogger logger, string returnedUrl, string discoveredUrl)
        => _authServerConfirmationRedirectMatch(logger, returnedUrl, discoveredUrl, null);

    internal static void AuthServerConfirmationReDiscovery(ILogger logger, string returnedUrl)
        => _authServerConfirmationReDiscovery(logger, returnedUrl, null);

    internal static void AuthServerConfirmationReDiscoveryFailed(ILogger logger, string returnedUrl, string? error)
        => _authServerConfirmationReDiscoveryFailed(logger, returnedUrl, error, null);

    internal static void AuthServerConfirmationReDiscoverySuccess(ILogger logger, string returnedUrl, string authEndpoint)
        => _authServerConfirmationReDiscoverySuccess(logger, returnedUrl, authEndpoint, null);

    internal static void AuthServerConfirmationMismatch(ILogger logger, string returnedUrl, string originalEndpoint, string returnedEndpoint)
        => _authServerConfirmationMismatch(logger, returnedUrl, originalEndpoint, returnedEndpoint, null);

    // Issuer validation logging
    private static readonly Action<ILogger, string, string, Exception?> _issuerValidationSuccess =
        LoggerMessage.Define<string, string>(LogLevel.Debug, new EventId(28, nameof(IssuerValidationSuccess)),
            "Issuer validation successful: expected={ExpectedIssuer}, received={ReceivedIssuer}");

    private static readonly Action<ILogger, string, string, Exception?> _issuerValidationFailed =
        LoggerMessage.Define<string, string>(LogLevel.Warning, new EventId(29, nameof(IssuerValidationFailed)),
            "Issuer validation failed: expected={ExpectedIssuer}, received={ReceivedIssuer}");

    private static readonly Action<ILogger, Exception?> _issuerValidationSkipped =
        LoggerMessage.Define(LogLevel.Debug, new EventId(30, nameof(IssuerValidationSkipped)),
            "Issuer validation skipped: no issuer available from discovery (legacy endpoints)");

    private static readonly Action<ILogger, string, Exception?> _issuerMissingFromCallback =
        LoggerMessage.Define<string>(LogLevel.Warning, new EventId(31, nameof(IssuerMissingFromCallback)),
            "Issuer parameter missing from callback but expected issuer was {ExpectedIssuer}");

    // Token refresh logging
    private static readonly Action<ILogger, string, Exception?> _tokenRefreshStarted =
        LoggerMessage.Define<string>(LogLevel.Debug, new EventId(32, nameof(TokenRefreshStarted)),
            "Starting token refresh at {TokenEndpoint}");

    private static readonly Action<ILogger, Exception?> _tokenRefreshSuccess =
        LoggerMessage.Define(LogLevel.Debug, new EventId(33, nameof(TokenRefreshSuccess)),
            "Token refresh successful");

    private static readonly Action<ILogger, string, Exception?> _tokenRefreshFailed =
        LoggerMessage.Define<string>(LogLevel.Warning, new EventId(34, nameof(TokenRefreshFailed)),
            "Token refresh failed: {Error}");

    private static readonly Action<ILogger, Exception?> _tokenRefreshNewRefreshToken =
        LoggerMessage.Define(LogLevel.Debug, new EventId(35, nameof(TokenRefreshNewRefreshToken)),
            "Token refresh returned new refresh token, old token should be discarded");

    internal static void IssuerValidationSuccess(ILogger logger, string expectedIssuer, string receivedIssuer)
        => _issuerValidationSuccess(logger, expectedIssuer, receivedIssuer, null);

    internal static void IssuerValidationFailed(ILogger logger, string expectedIssuer, string receivedIssuer)
        => _issuerValidationFailed(logger, expectedIssuer, receivedIssuer, null);

    internal static void IssuerValidationSkipped(ILogger logger)
        => _issuerValidationSkipped(logger, null);

    internal static void IssuerMissingFromCallback(ILogger logger, string expectedIssuer)
        => _issuerMissingFromCallback(logger, expectedIssuer, null);

    internal static void TokenRefreshStarted(ILogger logger, string tokenEndpoint)
        => _tokenRefreshStarted(logger, tokenEndpoint, null);

    internal static void TokenRefreshSuccess(ILogger logger)
        => _tokenRefreshSuccess(logger, null);

    internal static void TokenRefreshFailed(ILogger logger, string error)
        => _tokenRefreshFailed(logger, error, null);

    internal static void TokenRefreshNewRefreshToken(ILogger logger)
        => _tokenRefreshNewRefreshToken(logger, null);
}
