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
}
