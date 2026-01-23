using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AspNet.Security.IndieAuth;

/// <summary>
/// Result of authorization server confirmation.
/// </summary>
public record ConfirmationResult(
    bool Success,
    string? ErrorMessage = null,
    ConfirmationMethod Method = ConfirmationMethod.Unknown);

/// <summary>
/// Indicates how the authorization server was confirmed.
/// </summary>
public enum ConfirmationMethod
{
    /// <summary>Unknown or failed.</summary>
    Unknown,
    /// <summary>Returned URL exactly matched the canonicalized input URL.</summary>
    ExactMatch,
    /// <summary>Returned URL was found in the redirect chain during discovery.</summary>
    RedirectChainMatch,
    /// <summary>Re-discovery confirmed the same authorization endpoint.</summary>
    ReDiscoveryMatch
}

/// <summary>
/// Service for verifying authorization server claims about profile URLs.
/// Implements IndieAuth spec Section 5.4 - Authorization Server Confirmation.
/// </summary>
public class AuthorizationServerConfirmationService
{
    private readonly IndieAuthDiscoveryService _discoveryService;
    private readonly ILogger _logger;

    /// <summary>
    /// Creates a new confirmation service.
    /// </summary>
    public AuthorizationServerConfirmationService(
        IndieAuthDiscoveryService discoveryService,
        ILogger? logger = null)
    {
        _discoveryService = discoveryService ?? throw new ArgumentNullException(nameof(discoveryService));
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Confirms that the authorization server is authorized to make claims about the returned 'me' URL.
    /// </summary>
    /// <param name="originalDiscovery">The discovery result from the initial profile URL.</param>
    /// <param name="returnedMeUrl">The 'me' URL returned from the authorization/token endpoint.</param>
    /// <param name="canonicalizedInputUrl">The canonicalized URL that was initially entered.</param>
    /// <returns>A confirmation result indicating success or failure.</returns>
    public async Task<ConfirmationResult> ConfirmAuthorizationServerAsync(
        DiscoveryResult originalDiscovery,
        string returnedMeUrl,
        string canonicalizedInputUrl)
    {
        if (!originalDiscovery.Success)
        {
            return new ConfirmationResult(false, "Original discovery was not successful");
        }

        if (string.IsNullOrEmpty(returnedMeUrl))
        {
            return new ConfirmationResult(false, "Returned 'me' URL is empty");
        }

        // Canonicalize the returned URL for comparison
        var canonicalizedReturnedUrl = returnedMeUrl.Canonicalize();

        // Step 1: Check for exact match with canonicalized input URL
        if (string.Equals(canonicalizedReturnedUrl, canonicalizedInputUrl, StringComparison.OrdinalIgnoreCase))
        {
            Log.AuthServerConfirmationExactMatch(_logger, returnedMeUrl);
            return new ConfirmationResult(true, Method: ConfirmationMethod.ExactMatch);
        }

        // Step 2: Check if URL was seen during discovery (redirect chain optimization)
        if (originalDiscovery.DiscoveredUrls != null)
        {
            foreach (var discoveredUrl in originalDiscovery.DiscoveredUrls)
            {
                if (string.Equals(canonicalizedReturnedUrl, discoveredUrl.Canonicalize(), StringComparison.OrdinalIgnoreCase))
                {
                    Log.AuthServerConfirmationRedirectMatch(_logger, returnedMeUrl, discoveredUrl);
                    return new ConfirmationResult(true, Method: ConfirmationMethod.RedirectChainMatch);
                }
            }
        }

        // Step 3: Re-discover the returned URL and verify same authorization endpoint
        Log.AuthServerConfirmationReDiscovery(_logger, returnedMeUrl);

        var reDiscoveryResult = await _discoveryService.DiscoverEndpointsAsync(
            canonicalizedReturnedUrl,
            new DiscoveryOptions { BypassCache = false });

        if (!reDiscoveryResult.Success)
        {
            Log.AuthServerConfirmationReDiscoveryFailed(_logger, returnedMeUrl, reDiscoveryResult.ErrorMessage);
            return new ConfirmationResult(false, 
                $"Failed to discover authorization endpoint for returned URL: {reDiscoveryResult.ErrorMessage}");
        }

        // Compare authorization endpoints
        if (string.Equals(
            reDiscoveryResult.AuthorizationEndpoint, 
            originalDiscovery.AuthorizationEndpoint, 
            StringComparison.OrdinalIgnoreCase))
        {
            Log.AuthServerConfirmationReDiscoverySuccess(_logger, returnedMeUrl, reDiscoveryResult.AuthorizationEndpoint);
            return new ConfirmationResult(true, Method: ConfirmationMethod.ReDiscoveryMatch);
        }

        // Authorization endpoints don't match - reject
        Log.AuthServerConfirmationMismatch(_logger, 
            returnedMeUrl, 
            originalDiscovery.AuthorizationEndpoint, 
            reDiscoveryResult.AuthorizationEndpoint);

        return new ConfirmationResult(false, 
            $"Authorization endpoint mismatch: original '{originalDiscovery.AuthorizationEndpoint}' " +
            $"does not match returned URL's endpoint '{reDiscoveryResult.AuthorizationEndpoint}'");
    }
}
