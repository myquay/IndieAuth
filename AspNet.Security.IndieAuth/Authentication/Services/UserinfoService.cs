using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AspNet.Security.IndieAuth;

/// <summary>
/// Result of a userinfo request.
/// </summary>
public class UserinfoResult
{
    /// <summary>
    /// Whether the request was successful.
    /// </summary>
    public bool Success { get; init; }

    /// <summary>
    /// The user's profile information.
    /// Only populated when Success is true.
    /// </summary>
    public IndieAuthProfile? Profile { get; init; }

    /// <summary>
    /// Error code if the request failed.
    /// </summary>
    public string? Error { get; init; }

    /// <summary>
    /// Error description from the server.
    /// </summary>
    public string? ErrorDescription { get; init; }

    /// <summary>
    /// Creates a successful result with profile data.
    /// </summary>
    public static UserinfoResult Succeeded(IndieAuthProfile profile)
    {
        return new UserinfoResult
        {
            Success = true,
            Profile = profile
        };
    }

    /// <summary>
    /// Creates a failed result.
    /// </summary>
    public static UserinfoResult Failed(string error, string? errorDescription = null)
    {
        return new UserinfoResult
        {
            Success = false,
            Error = error,
            ErrorDescription = errorDescription
        };
    }
}

/// <summary>
/// Service for fetching user profile information from the userinfo endpoint.
/// Implements IndieAuth spec Section 9 - User Information.
/// </summary>
public class UserinfoService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;

    /// <summary>
    /// Creates a new userinfo service.
    /// </summary>
    public UserinfoService(HttpClient httpClient, ILogger? logger = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Fetches user profile information from the userinfo endpoint.
    /// Requires an access token issued with the 'profile' and/or 'email' scopes.
    /// </summary>
    /// <param name="userinfoEndpoint">The userinfo endpoint URL (from discovery).</param>
    /// <param name="accessToken">The access token with profile/email scope.</param>
    /// <returns>The result containing profile information or error details.</returns>
    /// <remarks>
    /// The userinfo endpoint is optional. Check that DiscoveryResult.UserinfoEndpoint
    /// is not null before calling this method.
    /// </remarks>
    public async Task<UserinfoResult> GetUserinfoAsync(
        string userinfoEndpoint,
        string accessToken)
    {
        if (string.IsNullOrEmpty(userinfoEndpoint))
            return UserinfoResult.Failed("invalid_request", "Userinfo endpoint is required");
        if (string.IsNullOrEmpty(accessToken))
            return UserinfoResult.Failed("invalid_request", "Access token is required");

        Log.UserinfoStarted(_logger, userinfoEndpoint);

        try
        {
            var requestMessage = new HttpRequestMessage(HttpMethod.Get, userinfoEndpoint);
            requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var response = await _httpClient.SendAsync(requestMessage);
            var body = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                return ParseErrorResponse(body, response.StatusCode);
            }

            return ParseSuccessResponse(body);
        }
        catch (HttpRequestException ex)
        {
            Log.UserinfoFailed(_logger, ex.Message);
            return UserinfoResult.Failed("network_error", ex.Message);
        }
        catch (JsonException ex)
        {
            Log.UserinfoFailed(_logger, ex.Message);
            return UserinfoResult.Failed("invalid_response", "Failed to parse userinfo response");
        }
    }

    private UserinfoResult ParseSuccessResponse(string body)
    {
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        var name = root.TryGetProperty("name", out var n) ? n.GetString() : null;
        var url = root.TryGetProperty("url", out var u) ? u.GetString() : null;
        var photo = root.TryGetProperty("photo", out var p) ? p.GetString() : null;
        var email = root.TryGetProperty("email", out var e) ? e.GetString() : null;

        var profile = new IndieAuthProfile(name, url, photo, email);

        Log.UserinfoSuccess(_logger);
        return UserinfoResult.Succeeded(profile);
    }

    private UserinfoResult ParseErrorResponse(string body, System.Net.HttpStatusCode statusCode)
    {
        // Map HTTP status codes to standard OAuth errors per Section 8.1
        var defaultError = statusCode switch
        {
            System.Net.HttpStatusCode.BadRequest => "invalid_request",
            System.Net.HttpStatusCode.Unauthorized => "invalid_token",
            System.Net.HttpStatusCode.Forbidden => "insufficient_scope",
            _ => "server_error"
        };

        try
        {
            if (!string.IsNullOrWhiteSpace(body))
            {
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;

                var error = root.TryGetProperty("error", out var e) ? e.GetString() : defaultError;
                var errorDescription = root.TryGetProperty("error_description", out var ed) ? ed.GetString() : null;

                Log.UserinfoFailed(_logger, $"{error}: {errorDescription}");
                return UserinfoResult.Failed(error ?? defaultError, errorDescription);
            }
        }
        catch
        {
            // Body is not JSON, use default error
        }

        Log.UserinfoFailed(_logger, $"HTTP {(int)statusCode} {statusCode}");
        return UserinfoResult.Failed(defaultError, $"Userinfo endpoint returned {(int)statusCode} {statusCode}");
    }
}
