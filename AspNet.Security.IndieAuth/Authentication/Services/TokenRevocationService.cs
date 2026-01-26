using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AspNet.Security.IndieAuth;

/// <summary>
/// Result of a token revocation operation.
/// </summary>
public class TokenRevocationResult
{
    /// <summary>
    /// Whether the revocation was successful.
    /// Per RFC 7009, a successful revocation returns HTTP 200 regardless of
    /// whether the token was valid or already revoked.
    /// </summary>
    public bool Success { get; init; }

    /// <summary>
    /// Error code if the revocation failed.
    /// </summary>
    public string? Error { get; init; }

    /// <summary>
    /// Error description from the server.
    /// </summary>
    public string? ErrorDescription { get; init; }

    /// <summary>
    /// Creates a successful result.
    /// </summary>
    public static TokenRevocationResult Succeeded()
    {
        return new TokenRevocationResult { Success = true };
    }

    /// <summary>
    /// Creates a failed result.
    /// </summary>
    public static TokenRevocationResult Failed(string error, string? errorDescription = null)
    {
        return new TokenRevocationResult
        {
            Success = false,
            Error = error,
            ErrorDescription = errorDescription
        };
    }
}

/// <summary>
/// Service for revoking IndieAuth access tokens.
/// Implements IndieAuth spec Section 7 - Token Revocation (RFC 7009).
/// </summary>
public class TokenRevocationService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;

    /// <summary>
    /// Creates a new token revocation service.
    /// </summary>
    public TokenRevocationService(HttpClient httpClient, ILogger? logger = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Revokes an access token.
    /// Per RFC 7009, the endpoint returns HTTP 200 for both successful revocation
    /// and when the token was already invalid or revoked.
    /// </summary>
    /// <param name="revocationEndpoint">The revocation endpoint URL.</param>
    /// <param name="token">The access token to revoke.</param>
    /// <param name="tokenTypeHint">Optional hint about the token type ("access_token" or "refresh_token").</param>
    /// <returns>The result of the revocation operation.</returns>
    public async Task<TokenRevocationResult> RevokeTokenAsync(
        string revocationEndpoint,
        string token,
        string? tokenTypeHint = null)
    {
        if (string.IsNullOrEmpty(revocationEndpoint))
            return TokenRevocationResult.Failed("invalid_request", "Revocation endpoint is required");
        if (string.IsNullOrEmpty(token))
            return TokenRevocationResult.Failed("invalid_request", "Token is required");

        Log.TokenRevocationStarted(_logger, revocationEndpoint);

        var parameters = new Dictionary<string, string>
        {
            ["token"] = token
        };

        if (!string.IsNullOrEmpty(tokenTypeHint))
        {
            parameters["token_type_hint"] = tokenTypeHint;
        }

        try
        {
            var requestContent = new FormUrlEncodedContent(parameters);
            var requestMessage = new HttpRequestMessage(HttpMethod.Post, revocationEndpoint)
            {
                Content = requestContent
            };
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var response = await _httpClient.SendAsync(requestMessage);

            // Per RFC 7009 Section 2.2, the endpoint returns 200 for success
            if (response.IsSuccessStatusCode)
            {
                Log.TokenRevocationSuccess(_logger);
                return TokenRevocationResult.Succeeded();
            }

            // Handle error responses
            var body = await response.Content.ReadAsStringAsync();
            return ParseErrorResponse(body, response.StatusCode.ToString());
        }
        catch (HttpRequestException ex)
        {
            Log.TokenRevocationFailed(_logger, ex.Message);
            return TokenRevocationResult.Failed("network_error", ex.Message);
        }
        catch (JsonException ex)
        {
            Log.TokenRevocationFailed(_logger, ex.Message);
            return TokenRevocationResult.Failed("invalid_response", "Failed to parse error response");
        }
    }

    /// <summary>
    /// Revokes an access token using the legacy method (action=revoke on token endpoint).
    /// This is for backwards compatibility with older IndieAuth servers.
    /// </summary>
    /// <param name="tokenEndpoint">The token endpoint URL.</param>
    /// <param name="token">The access token to revoke.</param>
    /// <returns>The result of the revocation operation.</returns>
    public async Task<TokenRevocationResult> RevokeTokenLegacyAsync(
        string tokenEndpoint,
        string token)
    {
        if (string.IsNullOrEmpty(tokenEndpoint))
            return TokenRevocationResult.Failed("invalid_request", "Token endpoint is required");
        if (string.IsNullOrEmpty(token))
            return TokenRevocationResult.Failed("invalid_request", "Token is required");

        Log.TokenRevocationStarted(_logger, tokenEndpoint + " (legacy)");

        var parameters = new Dictionary<string, string>
        {
            ["action"] = "revoke",
            ["token"] = token
        };

        try
        {
            var requestContent = new FormUrlEncodedContent(parameters);
            var requestMessage = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
            {
                Content = requestContent
            };
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var response = await _httpClient.SendAsync(requestMessage);

            if (response.IsSuccessStatusCode)
            {
                Log.TokenRevocationSuccess(_logger);
                return TokenRevocationResult.Succeeded();
            }

            var body = await response.Content.ReadAsStringAsync();
            return ParseErrorResponse(body, response.StatusCode.ToString());
        }
        catch (HttpRequestException ex)
        {
            Log.TokenRevocationFailed(_logger, ex.Message);
            return TokenRevocationResult.Failed("network_error", ex.Message);
        }
        catch (JsonException ex)
        {
            Log.TokenRevocationFailed(_logger, ex.Message);
            return TokenRevocationResult.Failed("invalid_response", "Failed to parse error response");
        }
    }

    private TokenRevocationResult ParseErrorResponse(string body, string statusCode)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            var error = root.TryGetProperty("error", out var e) ? e.GetString() : "unknown_error";
            var errorDescription = root.TryGetProperty("error_description", out var ed) ? ed.GetString() : null;

            Log.TokenRevocationFailed(_logger, $"{error}: {errorDescription}");
            return TokenRevocationResult.Failed(error ?? "unknown_error", errorDescription);
        }
        catch
        {
            Log.TokenRevocationFailed(_logger, $"HTTP {statusCode}");
            return TokenRevocationResult.Failed("http_error", $"Revocation endpoint returned {statusCode}");
        }
    }
}
