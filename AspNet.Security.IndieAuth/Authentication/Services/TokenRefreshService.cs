using System.Net.Http.Headers;
using System.Text.Json;
using AspNet.Security.IndieAuth.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AspNet.Security.IndieAuth;

/// <summary>
/// Result of a token refresh operation.
/// </summary>
public class TokenRefreshResult
{
    /// <summary>
    /// Whether the refresh was successful.
    /// </summary>
    public bool Success { get; init; }

    /// <summary>
    /// The new access token.
    /// </summary>
    public string? AccessToken { get; init; }

    /// <summary>
    /// The token type (typically "Bearer").
    /// </summary>
    public string? TokenType { get; init; }

    /// <summary>
    /// A new refresh token, if the server issued one.
    /// The client MUST discard the old refresh token and use this one.
    /// </summary>
    public string? RefreshToken { get; init; }

    /// <summary>
    /// Token validity lifetime in seconds.
    /// </summary>
    public int? ExpiresIn { get; init; }

    /// <summary>
    /// The granted scopes (may be same or fewer than original).
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>
    /// The user's profile URL.
    /// </summary>
    public string? Me { get; init; }

    /// <summary>
    /// Error message if the refresh failed.
    /// </summary>
    public string? Error { get; init; }

    /// <summary>
    /// Error description from the server.
    /// </summary>
    public string? ErrorDescription { get; init; }

    /// <summary>
    /// Creates a successful result.
    /// </summary>
    public static TokenRefreshResult Succeeded(
        string accessToken,
        string? tokenType = null,
        string? refreshToken = null,
        int? expiresIn = null,
        string? scope = null,
        string? me = null)
    {
        return new TokenRefreshResult
        {
            Success = true,
            AccessToken = accessToken,
            TokenType = tokenType,
            RefreshToken = refreshToken,
            ExpiresIn = expiresIn,
            Scope = scope,
            Me = me
        };
    }

    /// <summary>
    /// Creates a failed result.
    /// </summary>
    public static TokenRefreshResult Failed(string error, string? errorDescription = null)
    {
        return new TokenRefreshResult
        {
            Success = false,
            Error = error,
            ErrorDescription = errorDescription
        };
    }
}

/// <summary>
/// Service for refreshing IndieAuth access tokens.
/// Implements IndieAuth spec Section 5.5 - Refresh Tokens.
/// </summary>
public class TokenRefreshService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;

    /// <summary>
    /// Creates a new token refresh service.
    /// </summary>
    public TokenRefreshService(HttpClient httpClient, ILogger? logger = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Refreshes an access token using a refresh token.
    /// </summary>
    /// <param name="tokenEndpoint">The token endpoint URL.</param>
    /// <param name="refreshToken">The refresh token previously issued.</param>
    /// <param name="clientId">The client ID that was used when the refresh token was issued.</param>
    /// <param name="scope">Optional: request same or fewer scopes than original.</param>
    /// <returns>The result of the refresh operation.</returns>
    public async Task<TokenRefreshResult> RefreshTokenAsync(
        string tokenEndpoint,
        string refreshToken,
        string clientId,
        string? scope = null)
    {
        if (string.IsNullOrEmpty(tokenEndpoint))
            return TokenRefreshResult.Failed("invalid_request", "Token endpoint is required");
        if (string.IsNullOrEmpty(refreshToken))
            return TokenRefreshResult.Failed("invalid_request", "Refresh token is required");
        if (string.IsNullOrEmpty(clientId))
            return TokenRefreshResult.Failed("invalid_request", "Client ID is required");

        Log.TokenRefreshStarted(_logger, tokenEndpoint);

        var parameters = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = clientId
        };

        if (!string.IsNullOrEmpty(scope))
        {
            parameters["scope"] = scope;
        }

        try
        {
            var requestContent = new FormUrlEncodedContent(parameters);
            var requestMessage = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
            {
                Content = requestContent
            };
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var response = await _httpClient.SendAsync(requestMessage);
            var body = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                return ParseErrorResponse(body, response.StatusCode.ToString());
            }

            return ParseSuccessResponse(body);
        }
        catch (HttpRequestException ex)
        {
            Log.TokenRefreshFailed(_logger, ex.Message);
            return TokenRefreshResult.Failed("network_error", ex.Message);
        }
        catch (JsonException ex)
        {
            Log.TokenRefreshFailed(_logger, ex.Message);
            return TokenRefreshResult.Failed("invalid_response", "Failed to parse token response");
        }
    }

    private TokenRefreshResult ParseSuccessResponse(string body)
    {
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        var accessToken = root.TryGetProperty("access_token", out var at) ? at.GetString() : null;
        if (string.IsNullOrEmpty(accessToken))
        {
            Log.TokenRefreshFailed(_logger, "Response missing access_token");
            return TokenRefreshResult.Failed("invalid_response", "Response missing access_token");
        }

        var tokenType = root.TryGetProperty("token_type", out var tt) ? tt.GetString() : null;
        var newRefreshToken = root.TryGetProperty("refresh_token", out var rt) ? rt.GetString() : null;
        var scope = root.TryGetProperty("scope", out var sc) ? sc.GetString() : null;
        var me = root.TryGetProperty("me", out var m) ? m.GetString() : null;

        int? expiresIn = null;
        if (root.TryGetProperty("expires_in", out var ei))
        {
            if (ei.ValueKind == JsonValueKind.Number)
                expiresIn = ei.GetInt32();
            else if (ei.ValueKind == JsonValueKind.String && int.TryParse(ei.GetString(), out var parsed))
                expiresIn = parsed;
        }

        if (!string.IsNullOrEmpty(newRefreshToken))
        {
            Log.TokenRefreshNewRefreshToken(_logger);
        }

        Log.TokenRefreshSuccess(_logger);

        return TokenRefreshResult.Succeeded(
            accessToken: accessToken,
            tokenType: tokenType,
            refreshToken: newRefreshToken,
            expiresIn: expiresIn,
            scope: scope,
            me: me);
    }

    private TokenRefreshResult ParseErrorResponse(string body, string statusCode)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            var error = root.TryGetProperty("error", out var e) ? e.GetString() : "unknown_error";
            var errorDescription = root.TryGetProperty("error_description", out var ed) ? ed.GetString() : null;

            Log.TokenRefreshFailed(_logger, $"{error}: {errorDescription}");
            return TokenRefreshResult.Failed(error ?? "unknown_error", errorDescription);
        }
        catch
        {
            Log.TokenRefreshFailed(_logger, $"HTTP {statusCode}");
            return TokenRefreshResult.Failed("http_error", $"Token endpoint returned {statusCode}");
        }
    }
}
