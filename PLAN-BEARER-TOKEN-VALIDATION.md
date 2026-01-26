# Plan: Add IndieAuth Bearer Token Validation Support

## Status: ✅ IMPLEMENTED

## Overview

This plan adds support for validating IndieAuth tokens on resource servers (APIs), enabling .NET applications to protect endpoints with IndieAuth tokens using the standard ASP.NET Core authentication pattern similar to `AddJwtBearer()`. The implementation follows the IndieAuth spec Section 6 (Token Introspection) and RFC 7662.

## Steps

### 1. Create `IndieAuthBearerOptions`
**File**: `AspNet.Security.IndieAuth/Authentication/IndieAuthBearerOptions.cs`

Create options class for bearer token validation:
- `IntrospectionEndpoint` (string) - explicit introspection endpoint URL
- `Authority` (string) - the `me` URL to discover introspection endpoint from
- `ClientId` and `ClientSecret` for introspection endpoint authentication
- `IntrospectionAuthenticationMethod` enum (Bearer, ClientCredentials)
- `CacheIntrospectionResults` (bool, default: true) - enable result caching
- `IntrospectionCacheExpiration` (TimeSpan, default: 5 min)
- `TokenTypeHint` (string, default: "access_token")
- `NameClaimType` and `RoleClaimType` for claim mapping
- `ClaimActions` collection for custom claims transformation
- `RequireHttpsMetadata` (bool, default: true)

### 2. Create `TokenIntrospectionService`
**File**: `AspNet.Security.IndieAuth/Authentication/Services/TokenIntrospectionService.cs`

Implement token introspection per spec Section 6:
- Create `TokenIntrospectionResult` class with:
  - `Active` (bool, required)
  - `Me` (string, required when active)
  - `ClientId` (string, optional)
  - `Scope` (string, optional)
  - `Exp` (long?, optional)
  - `Iat` (long?, optional)
- Implement `IntrospectTokenAsync()` method
- Support Bearer token authentication for introspection endpoint
- Support client_id/client_secret authentication (Basic auth)
- Handle both active and inactive token responses
- Add logging consistent with other services

### 3. Create `IndieAuthBearerHandler`
**File**: `AspNet.Security.IndieAuth/Authentication/IndieAuthBearerHandler.cs`

Implement authentication handler:
- Inherit from `AuthenticationHandler<IndieAuthBearerOptions>`
- Extract bearer token from `Authorization` header
- Call `TokenIntrospectionService` to validate token
- Build `ClaimsPrincipal` from introspection response
- Map `me`, `scope`, `client_id` to claims
- Apply custom `ClaimActions`
- Implement optional result caching using `IMemoryCache`
- Handle 401 challenges with `WWW-Authenticate: Bearer` header
- Implement `HandleForbiddenAsync` for 403 responses

### 4. Create extension methods
**File**: `AspNet.Security.IndieAuth/Extensions/IndieAuthExtensions.cs`

Add `AddIndieAuthBearer()` extension methods:
- `AddIndieAuthBearer(Action<IndieAuthBearerOptions>)`
- `AddIndieAuthBearer(string scheme, Action<IndieAuthBearerOptions>)`
- `AddIndieAuthBearer(string scheme, string displayName, Action<IndieAuthBearerOptions>)`
- Register handler and post-configure options
- Support named schemes like `AddJwtBearer()`

### 5. Create `IndieAuthBearerPostConfigureOptions`
**File**: `AspNet.Security.IndieAuth/Authentication/IndieAuthBearerPostConfigureOptions.cs`

Implement post-configuration:
- Create backchannel `HttpClient` if not provided
- Discover introspection endpoint from `Authority` if not explicitly configured
- Validate required options (must have either `IntrospectionEndpoint` or `Authority`)

### 6. Create `IndieAuthBearerDefaults`
**File**: `AspNet.Security.IndieAuth/Authentication/IndieAuthBearerDefaults.cs`

Define defaults:
- `AuthenticationScheme = "IndieAuthBearer"`
- `DisplayName = "IndieAuth Bearer"`

### 7. Add unit tests
**File**: `AspNet.Security.IndieAuth.Tests/Authentication/TokenIntrospectionTests.cs`

Test cases:
- Active token introspection with full response
- Inactive token response
- Missing `me` claim in active response
- 401 unauthorized response from introspection endpoint
- Claim mapping from introspection response
- Bearer token extraction from header
- Invalid token format handling
- Caching behavior (cache hit, cache miss, expiration)
- Discovery of introspection endpoint from Authority

## Design Decisions

### 1. Introspection Authentication
Support configurable authentication via `IntrospectionAuthenticationMethod` enum:
- `Bearer` - Use a configured bearer token (common for resource servers)
- `ClientCredentials` - Use client_id/client_secret with Basic auth
- `None` - No authentication (not recommended but spec allows)

Default: `Bearer`

### 2. Endpoint Discovery vs Explicit Config
Support both approaches:
- Explicit `IntrospectionEndpoint` takes precedence
- If not set, discover from `Authority` URL using existing `IndieAuthDiscoveryService`
- At least one must be configured

### 3. Claims Transformation
Include `ClaimActionCollection` for consistency with existing `IndieAuthOptions`:
- Default mappings: `me` → `me`, `scope` → `scope`, `client_id` → `client_id`
- Users can customize with additional claim actions

### 4. Caching Strategy
- Cache introspection results by token hash (SHA256)
- Respect `exp` claim if present (don't cache beyond expiration)
- Configurable cache duration (default 5 minutes)
- Use `IMemoryCache` from DI

## Usage Example

```csharp
// Protect API endpoints with IndieAuth tokens
builder.Services.AddAuthentication()
    .AddIndieAuthBearer("IndieAuthBearer", options =>
    {
        // Option 1: Explicit endpoint
        options.IntrospectionEndpoint = "https://auth.example.com/introspect";
        
        // Option 2: Discover from authority
        options.Authority = "https://example.com/";
        
        // Authentication for introspection endpoint
        options.IntrospectionAuthenticationMethod = IntrospectionAuthMethod.Bearer;
        options.IntrospectionToken = "resource-server-token";
        
        // Or use client credentials
        options.IntrospectionAuthenticationMethod = IntrospectionAuthMethod.ClientCredentials;
        options.ClientId = "my-resource-server";
        options.ClientSecret = "secret";
        
        // Caching
        options.CacheIntrospectionResults = true;
        options.IntrospectionCacheExpiration = TimeSpan.FromMinutes(5);
    });

// Use on controllers
[Authorize(AuthenticationSchemes = "IndieAuthBearer")]
public class MicropubController : Controller
{
    // Access claims
    var me = User.FindFirst("me")?.Value;
    var scopes = User.FindFirst("scope")?.Value?.Split(' ');
}
```

## Files to Create/Modify

| File | Action |
|------|--------|
| `Authentication/IndieAuthBearerOptions.cs` | Create |
| `Authentication/IndieAuthBearerHandler.cs` | Create |
| `Authentication/IndieAuthBearerDefaults.cs` | Create |
| `Authentication/IndieAuthBearerPostConfigureOptions.cs` | Create |
| `Authentication/Services/TokenIntrospectionService.cs` | Create |
| `Extensions/IndieAuthExtensions.cs` | Modify |
| `Tests/Authentication/TokenIntrospectionTests.cs` | Create |
| `README.md` | Update |
| `COMPLIANCE.md` | Update |
