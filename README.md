# IndieAuth .NET

An ASP.NET Core authentication handler adding support for authenticating visitors using the [IndieAuth protocol](https://indieauth.spec.indieweb.org/).

[![NuGet](https://img.shields.io/nuget/v/AspNet.Security.IndieAuth.svg)](https://www.nuget.org/packages/AspNet.Security.IndieAuth/)

## Features

- ✅ Full IndieAuth specification compliance
- ✅ Discovery via `indieauth-metadata` and legacy `authorization_endpoint` 
- ✅ PKCE (S256) for secure authorization
- ✅ Issuer validation (RFC 9207)
- ✅ Authorization Server Confirmation (Section 5.4)
- ✅ Profile Information parsing (Section 5.3.4)
- ✅ Token Refresh support (Section 5.5)
- ✅ Token Revocation support (Section 7)
- ✅ Token Introspection support (Section 6)
- ✅ Bearer Token Authentication for APIs
- ✅ Userinfo Endpoint support (Section 9)
- ✅ Discovery result caching
- ✅ HEAD request optimization for discovery

## Installation

This library is distributed as a NuGet package. To install with the .NET CLI:

```bash
dotnet add package AspNet.Security.IndieAuth
```

## Quick Start

Configure authentication at startup:

```csharp
var authBuilder = builder.Services.AddAuthentication()
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.LoginPath = "/account/sign-in";
    })
    .AddIndieAuth(IndieAuthDefaults.AuthenticationScheme, options =>
    {
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.ClientId = config.IndieAuth.ClientId;
        options.CallbackPath = "/authentication/indie-auth/callback";
    });
```

Trigger authentication by issuing a challenge:

```csharp
return Challenge(new IndieAuthChallengeProperties
{
    Me = domain,
    Scope = new[] { "profile", "create" },
    RedirectUri = ReturnUrl
}, IndieAuthDefaults.AuthenticationScheme);
```

## Bearer Token Authentication for APIs

To protect API endpoints with IndieAuth tokens (using token introspection):

```csharp
builder.Services.AddAuthentication()
    .AddIndieAuthBearer("IndieAuthBearer", options =>
    {
        // Option 1: Explicit introspection endpoint
        options.IntrospectionEndpoint = "https://auth.example.com/introspect";
        
        // Option 2: Discover from authority URL
        options.Authority = "https://example.com/";
        
        // Authentication for introspection endpoint
        options.IntrospectionAuthenticationMethod = IntrospectionAuthMethod.Bearer;
        options.IntrospectionToken = "resource-server-token";
        
        // Or use client credentials
        options.IntrospectionAuthenticationMethod = IntrospectionAuthMethod.ClientCredentials;
        options.ClientId = "my-resource-server";
        options.ClientSecret = "secret";
        
        // Caching (optional)
        options.CacheIntrospectionResults = true;
        options.IntrospectionCacheExpiration = TimeSpan.FromMinutes(5);
    });
```

Use the `[Authorize]` attribute to protect controllers:

```csharp
[Authorize(AuthenticationSchemes = "IndieAuthBearer")]
public class MicropubController : Controller
{
    public IActionResult Post()
    {
        var me = User.FindFirst("me")?.Value;
        var scopes = User.FindFirst("scope")?.Value?.Split(' ');
        // ...
    }
}
```

## Configuration Options

### IndieAuthOptions

| Option | Default | Description |
|--------|---------|-------------|
| `ClientId` | Required | URI where the IndieAuth server can fetch client details |
| `CallbackPath` | Required | Path where the middleware intercepts the callback |
| `SignInScheme` | Required | Scheme used to persist the session (e.g., cookies) |
| `SaveTokens` | `false` | Store access/refresh tokens in auth properties |
| `CacheDiscoveryResults` | `true` | Enable discovery result caching |
| `DiscoveryCacheExpiration` | 5 min | Cache TTL for discovery results |
| `UseHeadRequestForDiscovery` | `false` | Use HEAD request optimization |
| `StrictProfileUrlValidation` | `true` | Enforce strict profile URL validation (Section 3.2) |
| `EnableAuthorizationServerConfirmation` | `true` | Verify auth server claims about `me` URL (Section 5.4) |
| `ValidateIssuer` | `true` | Validate `iss` parameter per RFC 9207 |
| `MapProfileToClaims` | `true` | Map profile data to OIDC-compatible claims |

### IndieAuthChallengeProperties

| Property | Description |
|----------|-------------|
| `Me` | The domain/URL the visitor is authenticating with |
| `Scope` | Array of scopes to request (e.g., `profile`, `email`, `create`) |
| `RedirectUri` | Where to redirect after authentication |

## Standalone Services

The library provides standalone services for token management:

### Token Introspection

```csharp
var introspectionService = new TokenIntrospectionService(httpClient);
var result = await introspectionService.IntrospectTokenAsync(
    "https://auth.example.com/introspect",
    accessToken,
    IntrospectionAuthMethod.Bearer,
    authToken: "resource-server-token");

if (result.Success && result.Active)
{
    var userUrl = result.Me;
    var scopes = result.Scope;
    var clientId = result.ClientId;
}
```

### Token Refresh

```csharp
var refreshService = new TokenRefreshService(httpClient);
var result = await refreshService.RefreshTokenAsync(
    tokenEndpoint, refreshToken, clientId, scope);

if (result.Success)
{
    var newAccessToken = result.AccessToken;
    var newRefreshToken = result.RefreshToken; // May be rotated
}
```

### Token Revocation

```csharp
var revocationService = new TokenRevocationService(httpClient);

// Standard revocation endpoint
var result = await revocationService.RevokeTokenAsync(
    revocationEndpoint, accessToken, tokenTypeHint: "access_token");

// Legacy method (for older servers)
var result = await revocationService.RevokeTokenLegacyAsync(
    tokenEndpoint, accessToken);
```

### Userinfo

```csharp
if (!string.IsNullOrEmpty(discoveryResult.UserinfoEndpoint))
{
    var userinfoService = new UserinfoService(httpClient);
    var result = await userinfoService.GetUserinfoAsync(
        discoveryResult.UserinfoEndpoint, accessToken);

    if (result.Success)
    {
        var name = result.Profile?.Name;
        var email = result.Profile?.Email;
    }
}
```

### Discovery

```csharp
var discoveryService = new IndieAuthDiscoveryService(httpClient);
var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");

if (result.Success)
{
    var authEndpoint = result.AuthorizationEndpoint;
    var tokenEndpoint = result.TokenEndpoint;
    var issuer = result.Issuer;
}
```

## URL Utilities

### Canonicalization (Section 3.4)

```csharp
// Transforms user input to valid URL
"example.com".Canonicalize();           // → "https://example.com/"
"https://EXAMPLE.COM".Canonicalize();   // → "https://example.com/"
```

### Profile URL Validation (Section 3.2)

```csharp
var result = "https://example.com/user".IsValidProfileUrl();
if (!result.IsValid)
{
    Console.WriteLine($"Invalid: {result.ErrorMessage}");
}
```

## Claims

When `MapProfileToClaims` is enabled, profile data is mapped to standard claims:

| Profile Field | Claim Type |
|---------------|------------|
| `me` | `me` (custom) |
| `name` | `name` |
| `url` | `website` |
| `photo` | `picture` |
| `email` | `email` |
| - | `email_verified` (always `false` per spec) |

## Specification Compliance

This library implements the [IndieAuth Living Standard](https://indieauth.spec.indieweb.org/) (July 2024):

| Section | Feature | Status |
|---------|---------|--------|
| 3.2 | Profile URL Validation | ✅ |
| 3.4 | URL Canonicalization | ✅ |
| 4.1 | Discovery by Clients | ✅ |
| 5.2 | PKCE (S256) | ✅ |
| 5.2.1 | Issuer Validation (RFC 9207) | ✅ |
| 5.3.4 | Profile Information | ✅ |
| 5.4 | Authorization Server Confirmation | ✅ |
| 5.5 | Token Refresh | ✅ |
| 6 | Token Introspection | ✅ |
| 7 | Token Revocation | ✅ |
| 9 | Userinfo Endpoint | ✅ |

## Contributing

Contributions are very welcome!

### Ways to contribute

* Fix an existing issue and submit a pull request
* Review open pull requests
* Report a new issue
* Make a suggestion / contribute to a discussion

## Acknowledgments

This project is based on the [OAuth handler](https://github.com/dotnet/aspnetcore/tree/main/src/Security/Authentication/OAuth/src) in the [aspnetcore repository](https://github.com/dotnet/aspnetcore).

## License

MIT

