using AspNet.Security.IndieAuth;
using AspNet.Security.IndieAuth.Tests.Helpers;
using Microsoft.Extensions.Logging.Abstractions;
using System.Net;

namespace AspNet.Security.IndieAuth.Tests.Authentication;

/// <summary>
/// Unit tests for Token Refresh per IndieAuth Section 5.5.
/// </summary>
[TestClass]
public class TokenRefreshTests
{
    #region Successful Refresh Tests

    [TestMethod]
    public async Task RefreshToken_ValidRequest_ReturnsNewAccessToken()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, @"{
            ""access_token"": ""new_access_token_123"",
            ""token_type"": ""Bearer"",
            ""expires_in"": 3600,
            ""me"": ""https://example.com/""
        }");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRefreshService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RefreshTokenAsync(
            tokenEndpoint: "https://example.com/token",
            refreshToken: "old_refresh_token",
            clientId: "https://app.example.com/");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual("new_access_token_123", result.AccessToken);
        Assert.AreEqual("Bearer", result.TokenType);
        Assert.AreEqual(3600, result.ExpiresIn);
        Assert.AreEqual("https://example.com/", result.Me);
        Assert.IsNull(result.RefreshToken); // No new refresh token issued
    }

    [TestMethod]
    public async Task RefreshToken_WithNewRefreshToken_ReturnsNewRefreshToken()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, @"{
            ""access_token"": ""new_access_token"",
            ""token_type"": ""Bearer"",
            ""refresh_token"": ""new_refresh_token"",
            ""expires_in"": 3600
        }");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRefreshService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RefreshTokenAsync(
            "https://example.com/token",
            "old_refresh_token",
            "https://app.example.com/");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual("new_access_token", result.AccessToken);
        Assert.AreEqual("new_refresh_token", result.RefreshToken);
    }

    [TestMethod]
    public async Task RefreshToken_WithScope_IncludesScopeInRequest()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, @"{
            ""access_token"": ""token"",
            ""scope"": ""profile""
        }");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRefreshService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RefreshTokenAsync(
            "https://example.com/token",
            "refresh_token",
            "https://app.example.com/",
            scope: "profile");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual("profile", result.Scope);

        // Verify request included scope
        var request = mockHandler.Requests[0];
        var content = await request.Content!.ReadAsStringAsync();
        Assert.IsTrue(content.Contains("scope=profile"));
    }

    #endregion

    #region Error Handling Tests

    [TestMethod]
    public async Task RefreshToken_InvalidToken_ReturnsError()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.BadRequest, @"{
            ""error"": ""invalid_grant"",
            ""error_description"": ""The refresh token is invalid or expired""
        }");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRefreshService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RefreshTokenAsync(
            "https://example.com/token",
            "invalid_refresh_token",
            "https://app.example.com/");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_grant", result.Error);
        Assert.AreEqual("The refresh token is invalid or expired", result.ErrorDescription);
    }

    [TestMethod]
    public async Task RefreshToken_ServerError_ReturnsError()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new StringContent("Internal Server Error")
        });

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRefreshService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RefreshTokenAsync(
            "https://example.com/token",
            "refresh_token",
            "https://app.example.com/");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.IsNotNull(result.Error);
    }

    [TestMethod]
    public async Task RefreshToken_MissingAccessToken_ReturnsError()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, @"{
            ""token_type"": ""Bearer""
        }");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRefreshService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RefreshTokenAsync(
            "https://example.com/token",
            "refresh_token",
            "https://app.example.com/");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_response", result.Error);
    }

    #endregion

    #region Validation Tests

    [TestMethod]
    public async Task RefreshToken_EmptyTokenEndpoint_ReturnsError()
    {
        var service = new TokenRefreshService(new HttpClient(), NullLogger.Instance);

        var result = await service.RefreshTokenAsync(
            tokenEndpoint: "",
            refreshToken: "token",
            clientId: "client");

        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_request", result.Error);
    }

    [TestMethod]
    public async Task RefreshToken_EmptyRefreshToken_ReturnsError()
    {
        var service = new TokenRefreshService(new HttpClient(), NullLogger.Instance);

        var result = await service.RefreshTokenAsync(
            tokenEndpoint: "https://example.com/token",
            refreshToken: "",
            clientId: "client");

        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_request", result.Error);
    }

    [TestMethod]
    public async Task RefreshToken_EmptyClientId_ReturnsError()
    {
        var service = new TokenRefreshService(new HttpClient(), NullLogger.Instance);

        var result = await service.RefreshTokenAsync(
            tokenEndpoint: "https://example.com/token",
            refreshToken: "token",
            clientId: "");

        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_request", result.Error);
    }

    #endregion

    #region Request Format Tests

    [TestMethod]
    public async Task RefreshToken_RequestFormat_MatchesSpec()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, @"{""access_token"": ""token""}");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRefreshService(httpClient, NullLogger.Instance);

        // Act
        await service.RefreshTokenAsync(
            "https://example.com/token",
            "my_refresh_token",
            "https://app.example.com/");

        // Assert
        var request = mockHandler.Requests[0];
        Assert.AreEqual(HttpMethod.Post, request.Method);
        Assert.AreEqual("https://example.com/token", request.RequestUri?.ToString());

        var content = await request.Content!.ReadAsStringAsync();
        Assert.IsTrue(content.Contains("grant_type=refresh_token"));
        Assert.IsTrue(content.Contains("refresh_token=my_refresh_token"));
        Assert.IsTrue(content.Contains("client_id=https%3A%2F%2Fapp.example.com%2F"));
    }

    #endregion
}
