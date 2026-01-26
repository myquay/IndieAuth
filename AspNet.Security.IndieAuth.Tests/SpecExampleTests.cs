using System.Net;
using System.Text.Json;
using AspNet.Security.IndieAuth;
using AspNet.Security.IndieAuth.Infrastructure;
using AspNet.Security.IndieAuth.Tests.Helpers;
using Microsoft.Extensions.Logging.Abstractions;

namespace AspNet.Security.IndieAuth.Tests;

/// <summary>
/// Unit tests that validate compliance with the exact examples from the IndieAuth Specification.
/// Each test references the specific example number from https://indieauth.spec.indieweb.org/
/// </summary>
[TestClass]
public class SpecExampleTests
{
    #region Example 1 - Server Metadata (Section 4.1.1)

    [TestMethod]
    [Description("Spec Example 1: Server metadata JSON format from Section 4.1.1")]
    public async Task Example1_ServerMetadata_ParsesCorrectly()
    {
        // Arrange - Exact JSON from spec Example 1
        var metadataJson = @"{
            ""issuer"": ""https://indieauth.example.com/"",
            ""authorization_endpoint"": ""https://indieauth.example.com/auth"",
            ""token_endpoint"": ""https://indieauth.example.com/token"",
            ""code_challenge_methods_supported"": [""S256""]
        }";

        var mockHandler = new MockHttpMessageHandler();
        
        // Profile page with metadata link
        mockHandler.QueueResponseWithLinkHeader(
            HttpStatusCode.OK,
            "<html><head></head><body></body></html>",
            "<https://indieauth.example.com/.well-known/oauth-authorization-server>; rel=\"indieauth-metadata\"");
        
        // Metadata response
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, metadataJson);

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient);

        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual("https://indieauth.example.com/", result.Issuer);
        Assert.AreEqual("https://indieauth.example.com/auth", result.AuthorizationEndpoint);
        Assert.AreEqual("https://indieauth.example.com/token", result.TokenEndpoint);
        Assert.IsNotNull(result.CodeChallengeMethods);
        Assert.IsTrue(result.CodeChallengeMethods.Contains("S256"));
    }

    #endregion

    #region Example 3 - Discovery Link Header (Section 5.1)

    [TestMethod]
    [Description("Spec Example 3: Link header with indieauth-metadata from Section 5.1")]
    public void Example3_LinkHeaderFormat_ParsesCorrectly()
    {
        // Arrange - Exact Link header format from spec Example 3
        var linkHeader = "<https://indieauth.example.com/.well-known/oauth-authorization-server>; rel=\"indieauth-metadata\"";

        // Act
        var result = LinkHeaderParser.Parse(new[] { linkHeader }).ToList();

        // Assert
        Assert.AreEqual(1, result.Count);
        Assert.AreEqual("indieauth-metadata", result[0].Rel);
        Assert.AreEqual("https://indieauth.example.com/.well-known/oauth-authorization-server", result[0].Url);
    }

    #endregion

    #region Example 4 - Metadata JSON Response (Section 5.1)

    [TestMethod]
    [Description("Spec Example 4: Metadata JSON response from Section 5.1")]
    public async Task Example4_MetadataJsonResponse_ParsesCorrectly()
    {
        // Arrange - Exact JSON from spec Example 4
        var metadataJson = @"{
            ""issuer"": ""https://indieauth.example.com/"",
            ""authorization_endpoint"": ""https://indieauth.example.com/auth"",
            ""token_endpoint"": ""https://indieauth.example.com/token"",
            ""code_challenge_methods_supported"": [""S256""]
        }";

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponseWithLinkHeader(
            HttpStatusCode.OK,
            "<html></html>",
            "<https://indieauth.example.com/metadata>; rel=\"indieauth-metadata\"");
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, metadataJson);

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient);

        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual("https://indieauth.example.com/", result.Issuer);
        Assert.AreEqual("https://indieauth.example.com/auth", result.AuthorizationEndpoint);
        Assert.AreEqual("https://indieauth.example.com/token", result.TokenEndpoint);
    }

    #endregion

    #region Example 9 - Profile URL Response (Section 5.3.2)

    [TestMethod]
    [Description("Spec Example 9: Profile URL response from authorization endpoint (Section 5.3.2)")]
    public void Example9_ProfileUrlResponse_ParsesCorrectly()
    {
        // Arrange - Exact JSON from spec Example 9
        // This is the response when client exchanges code at authorization endpoint
        // (no scope requested, so no access token - just profile URL)
        var json = @"{
            ""me"": ""https://user.example.net/""
        }";

        // Act
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var me = root.GetProperty("me").GetString();

        // Assert
        Assert.AreEqual("https://user.example.net/", me);
    }

    #endregion

    #region Example 10 - Access Token Response (Section 5.3.3)

    [TestMethod]
    [Description("Spec Example 10: Access token response from Section 5.3.3")]
    public void Example10_AccessTokenResponse_ParsesCorrectly()
    {
        // Arrange - Exact JSON from spec Example 10
        var json = @"{
            ""access_token"": ""XXXXXX"",
            ""token_type"": ""Bearer"",
            ""scope"": ""create update delete"",
            ""me"": ""https://user.example.net/""
        }";

        // Act
        using var response = IndieAuthTokenResponse.Success(JsonDocument.Parse(json));

        // Assert
        Assert.AreEqual("XXXXXX", response.AccessToken);
        Assert.AreEqual("Bearer", response.TokenType);
        Assert.AreEqual("https://user.example.net/", response.Me);
        Assert.IsNull(response.Profile); // No profile in this example
    }

    #endregion

    #region Example 11 - Full Profile Response (Section 5.3.4)

    [TestMethod]
    [Description("Spec Example 11: Token response with full profile from Section 5.3.4")]
    public void Example11_TokenResponseWithProfile_ParsesCorrectly()
    {
        // Arrange - Exact JSON from spec Example 11
        var json = @"{
            ""access_token"": ""XXXXXX"",
            ""token_type"": ""Bearer"",
            ""scope"": ""profile email create"",
            ""me"": ""https://user.example.net/"",
            ""profile"": {
                ""name"": ""Example User"",
                ""url"": ""https://user.example.net/"",
                ""photo"": ""https://user.example.net/photo.jpg"",
                ""email"": ""user@example.net""
            }
        }";

        // Act
        using var response = IndieAuthTokenResponse.Success(JsonDocument.Parse(json));

        // Assert
        Assert.AreEqual("XXXXXX", response.AccessToken);
        Assert.AreEqual("Bearer", response.TokenType);
        Assert.AreEqual("https://user.example.net/", response.Me);
        
        Assert.IsNotNull(response.Profile);
        Assert.AreEqual("Example User", response.Profile.Name);
        Assert.AreEqual("https://user.example.net/", response.Profile.Url);
        Assert.AreEqual("https://user.example.net/photo.jpg", response.Profile.Photo);
        Assert.AreEqual("user@example.net", response.Profile.Email);
    }

    #endregion

    #region Example 12 - Refresh Token Request (Section 5.5.1)

    [TestMethod]
    [Description("Spec Example 12: Refresh token request format from Section 5.5.1")]
    public async Task Example12_RefreshTokenRequest_FormatsCorrectly()
    {
        // Arrange - Verify request format matches spec Example 12
        // POST https://example.org/token
        // Content-type: application/x-www-form-urlencoded
        // Accept: application/json
        //
        // grant_type=refresh_token
        // &refresh_token=xxxxxxxx
        // &client_id=https://app.example.com

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, @"{
            ""access_token"": ""new_token"",
            ""token_type"": ""Bearer""
        }");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRefreshService(httpClient, NullLogger.Instance);

        // Act
        await service.RefreshTokenAsync(
            tokenEndpoint: "https://example.org/token",
            refreshToken: "xxxxxxxx",
            clientId: "https://app.example.com/");

        // Assert - Verify request format
        var request = mockHandler.Requests[0];
        Assert.AreEqual(HttpMethod.Post, request.Method);
        Assert.AreEqual("https://example.org/token", request.RequestUri!.ToString());
        
        var content = await request.Content!.ReadAsStringAsync();
        Assert.IsTrue(content.Contains("grant_type=refresh_token"));
        Assert.IsTrue(content.Contains("refresh_token=xxxxxxxx"));
        Assert.IsTrue(content.Contains("client_id="));
    }

    #endregion

    #region Example 16 - Token Revocation Request (Section 7.1)

    [TestMethod]
    [Description("Spec Example 16: Token revocation request from Section 7.1")]
    public async Task Example16_TokenRevocationRequest_FormatsCorrectly()
    {
        // Arrange - Verify request format matches spec Example 16
        // POST https://indieauth.example.com/revoke
        // Content-type: application/x-www-form-urlencoded
        // Accept: application/json
        //
        // token=xxxxxxxx

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(HttpStatusCode.OK, "");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        await service.RevokeTokenAsync(
            revocationEndpoint: "https://indieauth.example.com/revoke",
            token: "xxxxxxxx");

        // Assert - Verify request format
        var request = mockHandler.Requests[0];
        Assert.AreEqual(HttpMethod.Post, request.Method);
        Assert.AreEqual("https://indieauth.example.com/revoke", request.RequestUri!.ToString());
        
        var content = await request.Content!.ReadAsStringAsync();
        Assert.IsTrue(content.Contains("token=xxxxxxxx"));
    }

    #endregion

    #region Examples 17 & 18 - Userinfo Request and Response (Section 9)

    [TestMethod]
    [Description("Spec Example 17: Userinfo GET request format from Section 9")]
    public async Task Example17_UserinfoRequest_FormatsCorrectly()
    {
        // Arrange - Verify request format matches spec Example 17
        // GET /userinfo HTTP/1.1
        // Host: indieauth.example.com
        // Authorization: Bearer xxxxxxxxxxx

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, "{}");

        var httpClient = new HttpClient(mockHandler);
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        await service.GetUserinfoAsync(
            userinfoEndpoint: "https://indieauth.example.com/userinfo",
            accessToken: "xxxxxxxxxxx");

        // Assert - Verify request format
        var request = mockHandler.Requests[0];
        Assert.AreEqual(HttpMethod.Get, request.Method);
        Assert.AreEqual("https://indieauth.example.com/userinfo", request.RequestUri!.ToString());
        Assert.AreEqual("Bearer", request.Headers.Authorization?.Scheme);
        Assert.AreEqual("xxxxxxxxxxx", request.Headers.Authorization?.Parameter);
    }

    [TestMethod]
    [Description("Spec Example 18: Userinfo response format from Section 9")]
    public async Task Example18_UserinfoResponse_ParsesCorrectly()
    {
        // Arrange - Exact JSON from spec Example 18
        var json = @"{
            ""name"": ""Example User"",
            ""url"": ""https://user.example.net/"",
            ""photo"": ""https://user.example.net/photo.jpg"",
            ""email"": ""user@example.net""
        }";

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, json);

        var httpClient = new HttpClient(mockHandler);
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.GetUserinfoAsync(
            "https://indieauth.example.com/userinfo",
            "valid_token");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.IsNotNull(result.Profile);
        Assert.AreEqual("Example User", result.Profile.Name);
        Assert.AreEqual("https://user.example.net/", result.Profile.Url);
        Assert.AreEqual("https://user.example.net/photo.jpg", result.Profile.Photo);
        Assert.AreEqual("user@example.net", result.Profile.Email);
    }

    #endregion

    #region URL Canonicalization Examples (Section 3.4)

    [TestMethod]
    [Description("Spec Section 3.4: Host-only input transforms to valid URL")]
    public void Section3_4_HostOnlyInput_TransformsToValidUrl()
    {
        // From spec: "if the user enters example.com, the client transforms it into http://example.com/"
        // Our implementation defaults to https for security
        
        // Arrange
        var input = "example.com";

        // Act
        var result = input.Canonicalize();

        // Assert - We use https by default (more secure)
        Assert.AreEqual("https://example.com/", result);
    }

    [TestMethod]
    [Description("Spec Section 3.4: URL with no path must be treated as having path /")]
    public void Section3_4_NoPath_AddsTrailingSlash()
    {
        // From spec: "if a URL with no path component is ever encountered, 
        // it MUST be treated as if it had the path /"

        // Arrange
        var input = "https://example.com";

        // Act
        var result = input.Canonicalize();

        // Assert
        Assert.AreEqual("https://example.com/", result);
    }

    [TestMethod]
    [Description("Spec Section 3.4: Host must be converted to lowercase")]
    public void Section3_4_HostUppercase_ConvertsToLowercase()
    {
        // From spec: "the host component of the URL MUST be compared case insensitively. 
        // Implementations SHOULD convert the host to lowercase"

        // Arrange
        var input = "https://EXAMPLE.COM/";

        // Act
        var result = input.Canonicalize();

        // Assert
        Assert.AreEqual("https://example.com/", result);
    }

    #endregion

    #region Profile URL Validation Examples (Section 3.2)

    [TestMethod]
    [Description("Spec Section 3.2: https://example.com/ is valid")]
    public void Section3_2_ValidExample_RootPath()
    {
        var result = "https://example.com/".IsValidProfileUrl();
        Assert.IsTrue(result.IsValid);
    }

    [TestMethod]
    [Description("Spec Section 3.2: https://example.com/username is valid")]
    public void Section3_2_ValidExample_WithPath()
    {
        var result = "https://example.com/username".IsValidProfileUrl();
        Assert.IsTrue(result.IsValid);
    }

    [TestMethod]
    [Description("Spec Section 3.2: https://example.com/users?id=100 is valid")]
    public void Section3_2_ValidExample_WithQueryString()
    {
        var result = "https://example.com/users?id=100".IsValidProfileUrl();
        Assert.IsTrue(result.IsValid);
    }

    [TestMethod]
    [Description("Spec Section 3.2: example.com is invalid (missing scheme)")]
    public void Section3_2_InvalidExample_MissingScheme()
    {
        var result = "example.com".IsValidProfileUrl();
        Assert.IsFalse(result.IsValid);
    }

    [TestMethod]
    [Description("Spec Section 3.2: mailto:user@example.com is invalid (wrong scheme)")]
    public void Section3_2_InvalidExample_MailtoScheme()
    {
        var result = "mailto:user@example.com".IsValidProfileUrl();
        Assert.IsFalse(result.IsValid);
    }

    [TestMethod]
    [Description("Spec Section 3.2: https://example.com/foo/../bar is invalid (double-dot path)")]
    public void Section3_2_InvalidExample_DoubleDotPath()
    {
        var result = "https://example.com/foo/../bar".IsValidProfileUrl();
        Assert.IsFalse(result.IsValid);
    }

    [TestMethod]
    [Description("Spec Section 3.2: https://example.com/#me is invalid (fragment)")]
    public void Section3_2_InvalidExample_Fragment()
    {
        var result = "https://example.com/#me".IsValidProfileUrl();
        Assert.IsFalse(result.IsValid);
    }

    [TestMethod]
    [Description("Spec Section 3.2: https://user:pass@example.com/ is invalid (credentials)")]
    public void Section3_2_InvalidExample_Credentials()
    {
        var result = "https://user:pass@example.com/".IsValidProfileUrl();
        Assert.IsFalse(result.IsValid);
    }

    [TestMethod]
    [Description("Spec Section 3.2: https://example.com:8443/ is invalid (port)")]
    public void Section3_2_InvalidExample_Port()
    {
        var result = "https://example.com:8443/".IsValidProfileUrl();
        Assert.IsFalse(result.IsValid);
    }

    [TestMethod]
    [Description("Spec Section 3.2: https://172.28.92.51/ is invalid (IP address)")]
    public void Section3_2_InvalidExample_IpAddress()
    {
        var result = "https://172.28.92.51/".IsValidProfileUrl();
        Assert.IsFalse(result.IsValid);
    }

    #endregion
}
