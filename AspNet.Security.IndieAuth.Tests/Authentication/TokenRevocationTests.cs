using AspNet.Security.IndieAuth;
using AspNet.Security.IndieAuth.Tests.Helpers;
using Microsoft.Extensions.Logging.Abstractions;
using System.Net;

namespace AspNet.Security.IndieAuth.Tests.Authentication;

/// <summary>
/// Unit tests for Token Revocation per IndieAuth Section 7 (RFC 7009).
/// </summary>
[TestClass]
public class TokenRevocationTests
{
    #region Successful Revocation Tests

    [TestMethod]
    public async Task RevokeToken_ValidRequest_ReturnsSuccess()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(HttpStatusCode.OK, "");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RevokeTokenAsync(
            revocationEndpoint: "https://example.com/revocation",
            token: "access_token_123");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.IsNull(result.Error);
        Assert.IsNull(result.ErrorDescription);
    }

    [TestMethod]
    public async Task RevokeToken_AlreadyRevokedToken_StillReturnsSuccess()
    {
        // Per RFC 7009 Section 2.2: The authorization server responds with HTTP 200
        // for both the case where the token was successfully revoked, or if the 
        // submitted token was invalid.
        
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(HttpStatusCode.OK, "");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RevokeTokenAsync(
            "https://example.com/revocation",
            "already_revoked_token");

        // Assert
        Assert.IsTrue(result.Success);
    }

    [TestMethod]
    public async Task RevokeToken_WithTokenTypeHint_IncludesHintInRequest()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(HttpStatusCode.OK, "");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RevokeTokenAsync(
            "https://example.com/revocation",
            "access_token_123",
            tokenTypeHint: "access_token");

        // Assert
        Assert.IsTrue(result.Success);

        // Verify request included token_type_hint
        var request = mockHandler.Requests[0];
        var content = await request.Content!.ReadAsStringAsync();
        Assert.IsTrue(content.Contains("token_type_hint=access_token"));
        Assert.IsTrue(content.Contains("token=access_token_123"));
    }

    [TestMethod]
    public async Task RevokeToken_WithRefreshTokenHint_IncludesCorrectHint()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(HttpStatusCode.OK, "");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RevokeTokenAsync(
            "https://example.com/revocation",
            "refresh_token_xyz",
            tokenTypeHint: "refresh_token");

        // Assert
        Assert.IsTrue(result.Success);

        var request = mockHandler.Requests[0];
        var content = await request.Content!.ReadAsStringAsync();
        Assert.IsTrue(content.Contains("token_type_hint=refresh_token"));
    }

    #endregion

    #region Missing Parameter Tests

    [TestMethod]
    public async Task RevokeToken_MissingEndpoint_ReturnsError()
    {
        // Arrange
        var httpClient = new HttpClient();
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RevokeTokenAsync(
            revocationEndpoint: "",
            token: "some_token");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_request", result.Error);
        Assert.AreEqual("Revocation endpoint is required", result.ErrorDescription);
    }

    [TestMethod]
    public async Task RevokeToken_NullEndpoint_ReturnsError()
    {
        // Arrange
        var httpClient = new HttpClient();
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RevokeTokenAsync(
            revocationEndpoint: null!,
            token: "some_token");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_request", result.Error);
    }

    [TestMethod]
    public async Task RevokeToken_MissingToken_ReturnsError()
    {
        // Arrange
        var httpClient = new HttpClient();
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RevokeTokenAsync(
            revocationEndpoint: "https://example.com/revocation",
            token: "");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_request", result.Error);
        Assert.AreEqual("Token is required", result.ErrorDescription);
    }

    [TestMethod]
    public async Task RevokeToken_NullToken_ReturnsError()
    {
        // Arrange
        var httpClient = new HttpClient();
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RevokeTokenAsync(
            revocationEndpoint: "https://example.com/revocation",
            token: null!);

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_request", result.Error);
    }

    #endregion

    #region Error Response Tests

    [TestMethod]
    public async Task RevokeToken_ServerReturnsError_ParsesErrorResponse()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.BadRequest, @"{
            ""error"": ""invalid_token"",
            ""error_description"": ""The token format is invalid""
        }");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RevokeTokenAsync(
            "https://example.com/revocation",
            "malformed_token");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_token", result.Error);
        Assert.AreEqual("The token format is invalid", result.ErrorDescription);
    }

    [TestMethod]
    public async Task RevokeToken_ServerReturns500_ReturnsHttpError()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(HttpStatusCode.InternalServerError, "Internal Server Error");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RevokeTokenAsync(
            "https://example.com/revocation",
            "some_token");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("http_error", result.Error);
        // StatusCode.ToString() returns the enum name, not the numeric code
        Assert.IsTrue(result.ErrorDescription!.Contains("InternalServerError") || 
                      result.ErrorDescription!.Contains("500"));
    }

    [TestMethod]
    public async Task RevokeToken_ServerReturnsNonJsonError_HandlesGracefully()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(HttpStatusCode.BadRequest, "Plain text error");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RevokeTokenAsync(
            "https://example.com/revocation",
            "some_token");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("http_error", result.Error);
    }

    #endregion

    #region Legacy Revocation Tests

    [TestMethod]
    public async Task RevokeTokenLegacy_ValidRequest_ReturnsSuccess()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(HttpStatusCode.OK, "");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RevokeTokenLegacyAsync(
            tokenEndpoint: "https://example.com/token",
            token: "access_token_123");

        // Assert
        Assert.IsTrue(result.Success);
    }

    [TestMethod]
    public async Task RevokeTokenLegacy_IncludesActionParameter()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(HttpStatusCode.OK, "");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        await service.RevokeTokenLegacyAsync(
            "https://example.com/token",
            "access_token_123");

        // Assert - verify action=revoke is included
        var request = mockHandler.Requests[0];
        var content = await request.Content!.ReadAsStringAsync();
        Assert.IsTrue(content.Contains("action=revoke"));
        Assert.IsTrue(content.Contains("token=access_token_123"));
    }

    [TestMethod]
    public async Task RevokeTokenLegacy_MissingEndpoint_ReturnsError()
    {
        // Arrange
        var httpClient = new HttpClient();
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RevokeTokenLegacyAsync(
            tokenEndpoint: "",
            token: "some_token");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_request", result.Error);
        Assert.AreEqual("Token endpoint is required", result.ErrorDescription);
    }

    [TestMethod]
    public async Task RevokeTokenLegacy_MissingToken_ReturnsError()
    {
        // Arrange
        var httpClient = new HttpClient();
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RevokeTokenLegacyAsync(
            tokenEndpoint: "https://example.com/token",
            token: "");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_request", result.Error);
        Assert.AreEqual("Token is required", result.ErrorDescription);
    }

    [TestMethod]
    public async Task RevokeTokenLegacy_ServerReturnsError_ParsesErrorResponse()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.BadRequest, @"{
            ""error"": ""unsupported_action"",
            ""error_description"": ""The action parameter is not supported""
        }");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.RevokeTokenLegacyAsync(
            "https://example.com/token",
            "some_token");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("unsupported_action", result.Error);
        Assert.AreEqual("The action parameter is not supported", result.ErrorDescription);
    }

    #endregion

    #region Request Format Tests

    [TestMethod]
    public async Task RevokeToken_UsesCorrectHttpMethod()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(HttpStatusCode.OK, "");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        await service.RevokeTokenAsync(
            "https://example.com/revocation",
            "token");

        // Assert
        Assert.AreEqual(HttpMethod.Post, mockHandler.Requests[0].Method);
    }

    [TestMethod]
    public async Task RevokeToken_SetsAcceptHeader()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(HttpStatusCode.OK, "");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        await service.RevokeTokenAsync(
            "https://example.com/revocation",
            "token");

        // Assert
        var request = mockHandler.Requests[0];
        Assert.IsTrue(request.Headers.Accept.Any(h => h.MediaType == "application/json"));
    }

    [TestMethod]
    public async Task RevokeToken_UsesFormUrlEncodedContent()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(HttpStatusCode.OK, "");

        var httpClient = new HttpClient(mockHandler);
        var service = new TokenRevocationService(httpClient, NullLogger.Instance);

        // Act
        await service.RevokeTokenAsync(
            "https://example.com/revocation",
            "token");

        // Assert
        var request = mockHandler.Requests[0];
        Assert.IsNotNull(request.Content);
        Assert.AreEqual("application/x-www-form-urlencoded", 
            request.Content.Headers.ContentType?.MediaType);
    }

    #endregion

    #region Constructor Tests

    [TestMethod]
    public void Constructor_WithNullHttpClient_ThrowsArgumentNullException()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
            new TokenRevocationService(null!, NullLogger.Instance));
    }

    [TestMethod]
    public void Constructor_WithNullLogger_UsesNullLogger()
    {
        // Should not throw
        var httpClient = new HttpClient();
        var service = new TokenRevocationService(httpClient, null);
        Assert.IsNotNull(service);
    }

    #endregion
}
