using System.Security.Claims;
using AspNet.Security.IndieAuth.Infrastructure;
using Microsoft.AspNetCore.Authentication;

namespace AspNet.Security.IndieAuth;

/// <summary>
/// Method used to authenticate with the introspection endpoint.
/// </summary>
public enum IntrospectionAuthMethod
{
    /// <summary>
    /// No authentication. Not recommended but allowed by spec.
    /// </summary>
    None,

    /// <summary>
    /// Use a bearer token in the Authorization header.
    /// Common for resource servers that have their own token.
    /// </summary>
    Bearer,

    /// <summary>
    /// Use client_id and client_secret with HTTP Basic authentication.
    /// </summary>
    ClientCredentials
}

/// <summary>
/// Configuration options for IndieAuth bearer token validation.
/// Used by resource servers to validate access tokens via token introspection.
/// </summary>
public class IndieAuthBearerOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Gets or sets the introspection endpoint URL.
    /// If not set, will be discovered from <see cref="Authority"/>.
    /// </summary>
    public string? IntrospectionEndpoint { get; set; }

    /// <summary>
    /// Gets or sets the authority URL (a profile URL) to discover the introspection endpoint from.
    /// Used when <see cref="IntrospectionEndpoint"/> is not explicitly set.
    /// </summary>
    public string? Authority { get; set; }

    /// <summary>
    /// Gets or sets the authentication method for the introspection endpoint.
    /// Default: <see cref="IntrospectionAuthMethod.Bearer"/>.
    /// </summary>
    public IntrospectionAuthMethod IntrospectionAuthenticationMethod { get; set; } = IntrospectionAuthMethod.Bearer;

    /// <summary>
    /// Gets or sets the bearer token to use for introspection endpoint authentication.
    /// Only used when <see cref="IntrospectionAuthenticationMethod"/> is <see cref="IntrospectionAuthMethod.Bearer"/>.
    /// </summary>
    public string? IntrospectionToken { get; set; }

    /// <summary>
    /// Gets or sets the client ID for introspection endpoint authentication.
    /// Used when <see cref="IntrospectionAuthenticationMethod"/> is <see cref="IntrospectionAuthMethod.ClientCredentials"/>.
    /// </summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// Gets or sets the client secret for introspection endpoint authentication.
    /// Used when <see cref="IntrospectionAuthenticationMethod"/> is <see cref="IntrospectionAuthMethod.ClientCredentials"/>.
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Gets or sets whether to cache introspection results.
    /// Default: true.
    /// </summary>
    public bool CacheIntrospectionResults { get; set; } = true;

    /// <summary>
    /// Gets or sets the cache duration for introspection results.
    /// If the token has an 'exp' claim, the cache will expire at the earlier of this duration or the token expiration.
    /// Default: 5 minutes.
    /// </summary>
    public TimeSpan IntrospectionCacheExpiration { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets the token type hint to send with introspection requests.
    /// Default: "access_token".
    /// </summary>
    public string TokenTypeHint { get; set; } = "access_token";

    /// <summary>
    /// Gets or sets the claim type used for the user's name.
    /// Default: <see cref="ClaimTypes.Name"/>.
    /// </summary>
    public string NameClaimType { get; set; } = ClaimTypes.Name;

    /// <summary>
    /// Gets or sets the claim type used for roles.
    /// Default: <see cref="ClaimTypes.Role"/>.
    /// </summary>
    public string RoleClaimType { get; set; } = ClaimTypes.Role;

    /// <summary>
    /// Gets or sets whether HTTPS is required for the introspection endpoint.
    /// Default: true. Set to false only for development scenarios.
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>
    /// A collection of claim actions used to map introspection response to claims.
    /// </summary>
    public ClaimActionCollection ClaimActions { get; } = new ClaimActionCollection();

    /// <summary>
    /// Gets or sets the backchannel HTTP client used for introspection requests.
    /// </summary>
    public HttpClient? Backchannel { get; set; }

    /// <summary>
    /// Gets or sets the backchannel timeout.
    /// Default: 60 seconds.
    /// </summary>
    public TimeSpan BackchannelTimeout { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Gets or sets the handler used to create the backchannel HTTP client.
    /// </summary>
    public HttpMessageHandler? BackchannelHttpHandler { get; set; }

    /// <summary>
    /// Gets or sets the events used to handle authentication lifecycle events.
    /// </summary>
    public new IndieAuthBearerEvents Events
    {
        get => (IndieAuthBearerEvents)base.Events!;
        set => base.Events = value;
    }

    /// <summary>
    /// Initializes a new instance of <see cref="IndieAuthBearerOptions"/>.
    /// </summary>
    public IndieAuthBearerOptions()
    {
        Events = new IndieAuthBearerEvents();
    }

    /// <inheritdoc />
    public override void Validate()
    {
        base.Validate();

        if (string.IsNullOrEmpty(IntrospectionEndpoint) && string.IsNullOrEmpty(Authority))
        {
            throw new ArgumentException(
                $"Either {nameof(IntrospectionEndpoint)} or {nameof(Authority)} must be configured.");
        }

        if (IntrospectionAuthenticationMethod == IntrospectionAuthMethod.Bearer &&
            string.IsNullOrEmpty(IntrospectionToken))
        {
            throw new ArgumentException(
                $"{nameof(IntrospectionToken)} is required when using Bearer authentication.");
        }

        if (IntrospectionAuthenticationMethod == IntrospectionAuthMethod.ClientCredentials)
        {
            if (string.IsNullOrEmpty(ClientId))
                throw new ArgumentException($"{nameof(ClientId)} is required when using ClientCredentials authentication.");
            if (string.IsNullOrEmpty(ClientSecret))
                throw new ArgumentException($"{nameof(ClientSecret)} is required when using ClientCredentials authentication.");
        }

        if (!string.IsNullOrEmpty(IntrospectionEndpoint))
        {
            if (!Uri.TryCreate(IntrospectionEndpoint, UriKind.Absolute, out var uri))
                throw new ArgumentException($"{nameof(IntrospectionEndpoint)} must be a valid absolute URL.");

            if (RequireHttpsMetadata && uri.Scheme != "https")
                throw new ArgumentException($"{nameof(IntrospectionEndpoint)} must use HTTPS when {nameof(RequireHttpsMetadata)} is true.");
        }
    }
}

/// <summary>
/// Events for IndieAuth bearer token authentication.
/// </summary>
public class IndieAuthBearerEvents
{
    /// <summary>
    /// Invoked when a token is received and before introspection.
    /// Can be used to reject tokens early or modify the token.
    /// </summary>
    public Func<TokenReceivedContext, Task> OnTokenReceived { get; set; } = _ => Task.CompletedTask;

    /// <summary>
    /// Invoked after successful token introspection.
    /// Can be used to add additional claims or reject the authentication.
    /// </summary>
    public Func<TokenValidatedContext, Task> OnTokenValidated { get; set; } = _ => Task.CompletedTask;

    /// <summary>
    /// Invoked when authentication fails.
    /// </summary>
    public Func<AuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = _ => Task.CompletedTask;

    /// <summary>
    /// Invoked before a challenge response is sent.
    /// </summary>
    public Func<IndieAuthBearerChallengeContext, Task> OnChallenge { get; set; } = _ => Task.CompletedTask;

    /// <summary>
    /// Invoked before a forbidden response is sent.
    /// </summary>
    public Func<ForbiddenContext, Task> OnForbidden { get; set; } = _ => Task.CompletedTask;

    /// <summary>
    /// Called when a token is received.
    /// </summary>
    public virtual Task TokenReceived(TokenReceivedContext context) => OnTokenReceived(context);

    /// <summary>
    /// Called when a token has been validated.
    /// </summary>
    public virtual Task TokenValidated(TokenValidatedContext context) => OnTokenValidated(context);

    /// <summary>
    /// Called when authentication fails.
    /// </summary>
    public virtual Task AuthenticationFailed(AuthenticationFailedContext context) => OnAuthenticationFailed(context);

    /// <summary>
    /// Called before a challenge is sent.
    /// </summary>
    public virtual Task Challenge(IndieAuthBearerChallengeContext context) => OnChallenge(context);

    /// <summary>
    /// Called before a forbidden response is sent.
    /// </summary>
    public virtual Task Forbidden(ForbiddenContext context) => OnForbidden(context);
}

/// <summary>
/// Context for the TokenReceived event.
/// </summary>
public class TokenReceivedContext : ResultContext<IndieAuthBearerOptions>
{
    /// <summary>
    /// The token that was received.
    /// </summary>
    public string? Token { get; set; }

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    public TokenReceivedContext(
        Microsoft.AspNetCore.Http.HttpContext context,
        AuthenticationScheme scheme,
        IndieAuthBearerOptions options)
        : base(context, scheme, options)
    {
    }
}

/// <summary>
/// Context for the TokenValidated event.
/// </summary>
public class TokenValidatedContext : ResultContext<IndieAuthBearerOptions>
{
    /// <summary>
    /// The introspection result.
    /// </summary>
    public TokenIntrospectionResult? IntrospectionResult { get; set; }

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    public TokenValidatedContext(
        Microsoft.AspNetCore.Http.HttpContext context,
        AuthenticationScheme scheme,
        IndieAuthBearerOptions options)
        : base(context, scheme, options)
    {
    }
}

/// <summary>
/// Context for the AuthenticationFailed event.
/// </summary>
public class AuthenticationFailedContext : ResultContext<IndieAuthBearerOptions>
{
    /// <summary>
    /// The exception that caused the failure.
    /// </summary>
    public Exception? Exception { get; set; }

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    public AuthenticationFailedContext(
        Microsoft.AspNetCore.Http.HttpContext context,
        AuthenticationScheme scheme,
        IndieAuthBearerOptions options)
        : base(context, scheme, options)
    {
    }
}

/// <summary>
/// Context for the Challenge event.
/// </summary>
public class IndieAuthBearerChallengeContext : PropertiesContext<IndieAuthBearerOptions>
{
    /// <summary>
    /// The error to include in the WWW-Authenticate header.
    /// </summary>
    public string? Error { get; set; }

    /// <summary>
    /// The error description to include in the WWW-Authenticate header.
    /// </summary>
    public string? ErrorDescription { get; set; }

    /// <summary>
    /// Whether the challenge has been handled.
    /// </summary>
    public bool Handled { get; private set; }

    /// <summary>
    /// Mark the challenge as handled.
    /// </summary>
    public void HandleResponse() => Handled = true;

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    public IndieAuthBearerChallengeContext(
        Microsoft.AspNetCore.Http.HttpContext context,
        AuthenticationScheme scheme,
        IndieAuthBearerOptions options,
        AuthenticationProperties properties)
        : base(context, scheme, options, properties)
    {
    }
}

/// <summary>
/// Context for the Forbidden event.
/// </summary>
public class ForbiddenContext : ResultContext<IndieAuthBearerOptions>
{
    /// <summary>
    /// Creates a new instance.
    /// </summary>
    public ForbiddenContext(
        Microsoft.AspNetCore.Http.HttpContext context,
        AuthenticationScheme scheme,
        IndieAuthBearerOptions options)
        : base(context, scheme, options)
    {
    }
}
