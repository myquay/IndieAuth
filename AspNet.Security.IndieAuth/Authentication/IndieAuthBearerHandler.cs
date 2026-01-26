using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNet.Security.IndieAuth;

/// <summary>
/// Authentication handler for validating IndieAuth bearer tokens.
/// Uses token introspection (RFC 7662) to validate tokens.
/// </summary>
public class IndieAuthBearerHandler : AuthenticationHandler<IndieAuthBearerOptions>
{
    private readonly IMemoryCache? _cache;
    private TokenIntrospectionService? _introspectionService;

    /// <summary>
    /// Creates a new instance of <see cref="IndieAuthBearerHandler"/>.
    /// </summary>
    public IndieAuthBearerHandler(
        IOptionsMonitor<IndieAuthBearerOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        IMemoryCache? cache = null)
        : base(options, logger, encoder, clock)
    {
        _cache = cache;
    }

    /// <inheritdoc />
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            // Extract bearer token from Authorization header
            var token = ExtractBearerToken();
            if (string.IsNullOrEmpty(token))
            {
                Log.BearerTokenMissing(Logger);
                return AuthenticateResult.NoResult();
            }

            Log.BearerTokenExtracted(Logger, token.Length);

            // Raise TokenReceived event
            var tokenReceivedContext = new TokenReceivedContext(Context, Scheme, Options)
            {
                Token = token
            };
            await Options.Events.TokenReceived(tokenReceivedContext);

            if (tokenReceivedContext.Result != null)
            {
                return tokenReceivedContext.Result;
            }

            token = tokenReceivedContext.Token;
            if (string.IsNullOrEmpty(token))
            {
                return AuthenticateResult.NoResult();
            }

            // Check cache first
            TokenIntrospectionResult? introspectionResult = null;
            string? tokenHash = null;

            if (Options.CacheIntrospectionResults && _cache != null)
            {
                tokenHash = ComputeTokenHash(token);
                if (_cache.TryGetValue(tokenHash, out TokenIntrospectionResult? cachedResult))
                {
                    Log.IntrospectionCacheHit(Logger, tokenHash);
                    introspectionResult = cachedResult;
                }
                else
                {
                    Log.IntrospectionCacheMiss(Logger, tokenHash);
                }
            }

            // Introspect token if not in cache
            if (introspectionResult == null)
            {
                var introspectionEndpoint = await GetIntrospectionEndpointAsync();
                if (string.IsNullOrEmpty(introspectionEndpoint))
                {
                    return AuthenticateResult.Fail("Unable to determine introspection endpoint");
                }

                _introspectionService ??= new TokenIntrospectionService(Options.Backchannel!, Logger);

                introspectionResult = await _introspectionService.IntrospectTokenAsync(
                    introspectionEndpoint,
                    token,
                    Options.IntrospectionAuthenticationMethod,
                    Options.IntrospectionToken,
                    Options.ClientId,
                    Options.ClientSecret,
                    Options.TokenTypeHint);

                // Cache the result
                if (Options.CacheIntrospectionResults && _cache != null && tokenHash != null && introspectionResult.Success)
                {
                    var cacheExpiration = CalculateCacheExpiration(introspectionResult);
                    _cache.Set(tokenHash, introspectionResult, cacheExpiration);
                }
            }

            // Handle introspection failure
            if (!introspectionResult.Success)
            {
                var failedContext = new AuthenticationFailedContext(Context, Scheme, Options)
                {
                    Exception = new InvalidOperationException(introspectionResult.ErrorDescription ?? introspectionResult.Error ?? "Token introspection failed")
                };
                await Options.Events.AuthenticationFailed(failedContext);

                if (failedContext.Result != null)
                {
                    return failedContext.Result;
                }

                return AuthenticateResult.Fail(introspectionResult.ErrorDescription ?? introspectionResult.Error ?? "Token introspection failed");
            }

            // Handle inactive token
            if (!introspectionResult.Active)
            {
                return AuthenticateResult.Fail("Token is not active");
            }

            // Build claims identity
            var claims = new List<Claim>();

            // Required: me claim
            if (!string.IsNullOrEmpty(introspectionResult.Me))
            {
                claims.Add(new Claim("me", introspectionResult.Me));
                claims.Add(new Claim(Options.NameClaimType, introspectionResult.Me));
            }

            // Optional: client_id
            if (!string.IsNullOrEmpty(introspectionResult.ClientId))
            {
                claims.Add(new Claim("client_id", introspectionResult.ClientId));
            }

            // Optional: scope
            if (!string.IsNullOrEmpty(introspectionResult.Scope))
            {
                claims.Add(new Claim("scope", introspectionResult.Scope));

                // Also add individual scope claims for easier policy checks
                foreach (var scope in introspectionResult.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                {
                    claims.Add(new Claim("scope", scope));
                }
            }

            // Optional: exp (expiration)
            if (introspectionResult.Exp.HasValue)
            {
                claims.Add(new Claim("exp", introspectionResult.Exp.Value.ToString(CultureInfo.InvariantCulture)));
            }

            // Optional: iat (issued at)
            if (introspectionResult.Iat.HasValue)
            {
                claims.Add(new Claim("iat", introspectionResult.Iat.Value.ToString(CultureInfo.InvariantCulture)));
            }

            var identity = new ClaimsIdentity(claims, Scheme.Name, Options.NameClaimType, Options.RoleClaimType);

            // Apply custom claim actions
            if (introspectionResult.RawResponse != null)
            {
                foreach (var action in Options.ClaimActions)
                {
                    action.Run(introspectionResult.RawResponse.RootElement, identity, Scheme.Name);
                }
            }

            var principal = new ClaimsPrincipal(identity);
            var properties = new AuthenticationProperties();

            // Raise TokenValidated event
            var tokenValidatedContext = new TokenValidatedContext(Context, Scheme, Options)
            {
                IntrospectionResult = introspectionResult,
                Principal = principal
            };
            await Options.Events.TokenValidated(tokenValidatedContext);

            if (tokenValidatedContext.Result != null)
            {
                return tokenValidatedContext.Result;
            }

            return AuthenticateResult.Success(new AuthenticationTicket(principal, properties, Scheme.Name));
        }
        catch (Exception ex)
        {
            var failedContext = new AuthenticationFailedContext(Context, Scheme, Options)
            {
                Exception = ex
            };
            await Options.Events.AuthenticationFailed(failedContext);

            if (failedContext.Result != null)
            {
                return failedContext.Result;
            }

            throw;
        }
    }

    /// <inheritdoc />
    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var challengeContext = new IndieAuthBearerChallengeContext(Context, Scheme, Options, properties);
        await Options.Events.Challenge(challengeContext);

        if (challengeContext.Handled)
        {
            return;
        }

        Response.StatusCode = 401;

        var wwwAuthenticate = new StringBuilder("Bearer");

        if (!string.IsNullOrEmpty(challengeContext.Error))
        {
            wwwAuthenticate.Append(" error=\"");
            wwwAuthenticate.Append(challengeContext.Error);
            wwwAuthenticate.Append('"');
        }

        if (!string.IsNullOrEmpty(challengeContext.ErrorDescription))
        {
            wwwAuthenticate.Append(", error_description=\"");
            wwwAuthenticate.Append(challengeContext.ErrorDescription);
            wwwAuthenticate.Append('"');
        }

        Response.Headers["WWW-Authenticate"] = wwwAuthenticate.ToString();
    }

    /// <inheritdoc />
    protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        var forbiddenContext = new ForbiddenContext(Context, Scheme, Options);
        await Options.Events.Forbidden(forbiddenContext);

        // ForbiddenContext extends ResultContext - check if it was marked as handled
        if (forbiddenContext.Result != null)
        {
            return;
        }

        Response.StatusCode = 403;
        Response.Headers["WWW-Authenticate"] = "Bearer error=\"insufficient_scope\"";
    }

    private string? ExtractBearerToken()
    {
        var authorization = Request.Headers["Authorization"].FirstOrDefault();
        if (string.IsNullOrEmpty(authorization))
        {
            return null;
        }

        if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return authorization.Substring("Bearer ".Length).Trim();
        }

        return null;
    }

    private async Task<string?> GetIntrospectionEndpointAsync()
    {
        // Use explicit endpoint if configured
        if (!string.IsNullOrEmpty(Options.IntrospectionEndpoint))
        {
            return Options.IntrospectionEndpoint;
        }

        // Discover from authority
        if (!string.IsNullOrEmpty(Options.Authority))
        {
            var discoveryService = new IndieAuthDiscoveryService(Options.Backchannel!, Logger);
            var result = await discoveryService.DiscoverEndpointsAsync(Options.Authority);

            if (result.Success && !string.IsNullOrEmpty(result.IntrospectionEndpoint))
            {
                return result.IntrospectionEndpoint;
            }
        }

        return null;
    }

    private static string ComputeTokenHash(string token)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(token);
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToBase64String(hash);
    }

    private TimeSpan CalculateCacheExpiration(TokenIntrospectionResult result)
    {
        var configuredExpiration = Options.IntrospectionCacheExpiration;

        if (result.Exp.HasValue)
        {
            var tokenExpiration = DateTimeOffset.FromUnixTimeSeconds(result.Exp.Value);
            var timeUntilExpiry = tokenExpiration - DateTimeOffset.UtcNow;

            if (timeUntilExpiry > TimeSpan.Zero)
            {
                return timeUntilExpiry < configuredExpiration ? timeUntilExpiry : configuredExpiration;
            }
        }

        return configuredExpiration;
    }
}
