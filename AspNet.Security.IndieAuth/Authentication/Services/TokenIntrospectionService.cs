using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AspNet.Security.IndieAuth;

/// <summary>
/// Result of a token introspection request.
/// Per IndieAuth spec Section 6.2.
/// </summary>
public class TokenIntrospectionResult
{
    /// <summary>
    /// Whether the token is currently active.
    /// Required per RFC 7662.
    /// </summary>
    public bool Active { get; init; }

    /// <summary>
    /// The profile URL of the user corresponding to this token.
    /// Required per IndieAuth spec when token is active.
    /// </summary>
    public string? Me { get; init; }

    /// <summary>
    /// The client ID associated with this token.
    /// </summary>
    public string? ClientId { get; init; }

    /// <summary>
    /// A space-separated list of scopes associated with this token.
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>
    /// Timestamp when this token will expire (seconds since epoch).
    /// </summary>
    public long? Exp { get; init; }

    /// <summary>
    /// Timestamp when this token was issued (seconds since epoch).
    /// </summary>
    public long? Iat { get; init; }

    /// <summary>
    /// Error code if the introspection request failed.
    /// </summary>
    public string? Error { get; init; }

    /// <summary>
    /// Error description from the server.
    /// </summary>
    public string? ErrorDescription { get; init; }

    /// <summary>
    /// Whether the introspection request itself succeeded.
    /// Note: A successful request can still return Active=false.
    /// </summary>
    public bool Success { get; init; }

    /// <summary>
    /// The raw JSON response from the introspection endpoint.
    /// Useful for accessing additional properties not in the standard response.
    /// </summary>
    public JsonDocument? RawResponse { get; init; }

    /// <summary>
    /// Creates a successful result with an active token.
    /// </summary>
    public static TokenIntrospectionResult ActiveToken(
        string me,
        string? clientId = null,
        string? scope = null,
        long? exp = null,
        long? iat = null,
        JsonDocument? rawResponse = null)
    {
        return new TokenIntrospectionResult
        {
            Success = true,
            Active = true,
            Me = me,
            ClientId = clientId,
            Scope = scope,
            Exp = exp,
            Iat = iat,
            RawResponse = rawResponse
        };
    }

    /// <summary>
    /// Creates a successful result with an inactive token.
    /// </summary>
    public static TokenIntrospectionResult InactiveToken()
    {
        return new TokenIntrospectionResult
        {
            Success = true,
            Active = false
        };
    }

    /// <summary>
    /// Creates a failed result.
    /// </summary>
    public static TokenIntrospectionResult Failed(string error, string? errorDescription = null)
    {
        return new TokenIntrospectionResult
        {
            Success = false,
            Active = false,
            Error = error,
            ErrorDescription = errorDescription
        };
    }
}

/// <summary>
/// Service for introspecting IndieAuth access tokens.
/// Implements IndieAuth spec Section 6 - Access Token Verification (RFC 7662).
/// </summary>
public class TokenIntrospectionService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;

    /// <summary>
    /// Creates a new token introspection service.
    /// </summary>
    public TokenIntrospectionService(HttpClient httpClient, ILogger? logger = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Introspects an access token to determine if it is valid and get associated metadata.
    /// </summary>
    /// <param name="introspectionEndpoint">The introspection endpoint URL.</param>
    /// <param name="token">The access token to introspect.</param>
    /// <param name="authMethod">The authentication method for the introspection endpoint.</param>
    /// <param name="authToken">Bearer token for auth (when using Bearer method).</param>
    /// <param name="clientId">Client ID (when using ClientCredentials method).</param>
    /// <param name="clientSecret">Client secret (when using ClientCredentials method).</param>
    /// <param name="tokenTypeHint">Optional hint about the token type.</param>
    /// <returns>The introspection result.</returns>
    public async Task<TokenIntrospectionResult> IntrospectTokenAsync(
        string introspectionEndpoint,
        string token,
        IntrospectionAuthMethod authMethod = IntrospectionAuthMethod.None,
        string? authToken = null,
        string? clientId = null,
        string? clientSecret = null,
        string? tokenTypeHint = null)
    {
        if (string.IsNullOrEmpty(introspectionEndpoint))
            return TokenIntrospectionResult.Failed("invalid_request", "Introspection endpoint is required");
        if (string.IsNullOrEmpty(token))
            return TokenIntrospectionResult.Failed("invalid_request", "Token is required");

        Log.TokenIntrospectionStarted(_logger, introspectionEndpoint);

        try
        {
            var parameters = new Dictionary<string, string>
            {
                ["token"] = token
            };

            if (!string.IsNullOrEmpty(tokenTypeHint))
            {
                parameters["token_type_hint"] = tokenTypeHint;
            }

            var request = new HttpRequestMessage(HttpMethod.Post, introspectionEndpoint)
            {
                Content = new FormUrlEncodedContent(parameters)
            };

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            // Add authentication
            switch (authMethod)
            {
                case IntrospectionAuthMethod.Bearer:
                    if (!string.IsNullOrEmpty(authToken))
                    {
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", authToken);
                    }
                    break;

                case IntrospectionAuthMethod.ClientCredentials:
                    if (!string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(clientSecret))
                    {
                        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));
                        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
                    }
                    break;

                case IntrospectionAuthMethod.None:
                default:
                    // No authentication
                    break;
            }

            var response = await _httpClient.SendAsync(request);

            // Handle 401 Unauthorized
            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                Log.TokenIntrospectionUnauthorized(_logger, introspectionEndpoint);
                return TokenIntrospectionResult.Failed("unauthorized", "Introspection endpoint returned 401 Unauthorized");
            }

            // Per RFC 7662, even invalid tokens return 200 with active=false
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                Log.TokenIntrospectionFailed(_logger, introspectionEndpoint, (int)response.StatusCode, errorContent);
                return TokenIntrospectionResult.Failed("server_error", $"Introspection endpoint returned {(int)response.StatusCode}");
            }

            var content = await response.Content.ReadAsStringAsync();
            Log.TokenIntrospectionResponse(_logger, content);

            using var document = JsonDocument.Parse(content);
            var root = document.RootElement;

            // Check active status (required per RFC 7662)
            if (!root.TryGetProperty("active", out var activeElement))
            {
                return TokenIntrospectionResult.Failed("invalid_response", "Response missing required 'active' property");
            }

            bool active;
            if (activeElement.ValueKind == JsonValueKind.True)
            {
                active = true;
            }
            else if (activeElement.ValueKind == JsonValueKind.False)
            {
                active = false;
            }
            else if (activeElement.ValueKind == JsonValueKind.String)
            {
                // Some servers return "true"/"false" as strings
                active = activeElement.GetString()?.Equals("true", StringComparison.OrdinalIgnoreCase) ?? false;
            }
            else
            {
                return TokenIntrospectionResult.Failed("invalid_response", "'active' property has invalid type");
            }

            if (!active)
            {
                Log.TokenIntrospectionInactive(_logger);
                return TokenIntrospectionResult.InactiveToken();
            }

            // For active tokens, 'me' is required per IndieAuth spec
            string? me = null;
            if (root.TryGetProperty("me", out var meElement) && meElement.ValueKind == JsonValueKind.String)
            {
                me = meElement.GetString();
            }

            if (string.IsNullOrEmpty(me))
            {
                Log.TokenIntrospectionMissingMe(_logger);
                return TokenIntrospectionResult.Failed("invalid_response", "Active token response missing required 'me' property");
            }

            // Optional properties
            string? tokenClientId = null;
            if (root.TryGetProperty("client_id", out var clientIdElement) && clientIdElement.ValueKind == JsonValueKind.String)
            {
                tokenClientId = clientIdElement.GetString();
            }

            string? scope = null;
            if (root.TryGetProperty("scope", out var scopeElement) && scopeElement.ValueKind == JsonValueKind.String)
            {
                scope = scopeElement.GetString();
            }

            long? exp = null;
            if (root.TryGetProperty("exp", out var expElement))
            {
                if (expElement.ValueKind == JsonValueKind.Number)
                {
                    exp = expElement.GetInt64();
                }
                else if (expElement.ValueKind == JsonValueKind.String && long.TryParse(expElement.GetString(), out var expValue))
                {
                    exp = expValue;
                }
            }

            long? iat = null;
            if (root.TryGetProperty("iat", out var iatElement))
            {
                if (iatElement.ValueKind == JsonValueKind.Number)
                {
                    iat = iatElement.GetInt64();
                }
                else if (iatElement.ValueKind == JsonValueKind.String && long.TryParse(iatElement.GetString(), out var iatValue))
                {
                    iat = iatValue;
                }
            }

            Log.TokenIntrospectionSuccess(_logger, me);

            // Clone the document for the result (since we're disposing the original)
            var rawResponse = JsonDocument.Parse(content);

            return TokenIntrospectionResult.ActiveToken(me, tokenClientId, scope, exp, iat, rawResponse);
        }
        catch (HttpRequestException ex)
        {
            Log.TokenIntrospectionException(_logger, ex);
            return TokenIntrospectionResult.Failed("network_error", ex.Message);
        }
        catch (JsonException ex)
        {
            Log.TokenIntrospectionJsonError(_logger, ex);
            return TokenIntrospectionResult.Failed("invalid_response", "Failed to parse introspection response");
        }
        catch (Exception ex)
        {
            Log.TokenIntrospectionException(_logger, ex);
            return TokenIntrospectionResult.Failed("error", ex.Message);
        }
    }
}
