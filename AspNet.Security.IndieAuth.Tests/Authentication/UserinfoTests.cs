using AspNet.Security.IndieAuth;
using AspNet.Security.IndieAuth.Tests.Helpers;
using Microsoft.Extensions.Logging.Abstractions;
using System.Net;

namespace AspNet.Security.IndieAuth.Tests.Authentication;

/// <summary>
/// Unit tests for Userinfo Endpoint per IndieAuth Section 9.
/// </summary>
[TestClass]
public class UserinfoTests
{
    #region Successful Response Tests

    [TestMethod]
    public async Task GetUserinfo_AllFields_ReturnsFullProfile()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, @"{
            ""name"": ""Example User"",
            ""url"": ""https://user.example.net/"",
            ""photo"": ""https://user.example.net/photo.jpg"",
            ""email"": ""user@example.net""
        }");

        var httpClient = new HttpClient(mockHandler);
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.GetUserinfoAsync(
            userinfoEndpoint: "https://example.com/userinfo",
            accessToken: "valid_token");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.IsNotNull(result.Profile);
        Assert.AreEqual("Example User", result.Profile.Name);
        Assert.AreEqual("https://user.example.net/", result.Profile.Url);
        Assert.AreEqual("https://user.example.net/photo.jpg", result.Profile.Photo);
        Assert.AreEqual("user@example.net", result.Profile.Email);
        Assert.IsNull(result.Error);
    }

    [TestMethod]
    public async Task GetUserinfo_PartialFields_ReturnsPartialProfile()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, @"{
            ""name"": ""Test User""
        }");

        var httpClient = new HttpClient(mockHandler);
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.GetUserinfoAsync(
            "https://example.com/userinfo",
            "valid_token");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.IsNotNull(result.Profile);
        Assert.AreEqual("Test User", result.Profile.Name);
        Assert.IsNull(result.Profile.Url);
        Assert.IsNull(result.Profile.Photo);
        Assert.IsNull(result.Profile.Email);
    }

    [TestMethod]
    public async Task GetUserinfo_EmptyProfile_ReturnsEmptyProfile()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, @"{}");

        var httpClient = new HttpClient(mockHandler);
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.GetUserinfoAsync(
            "https://example.com/userinfo",
            "valid_token");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.IsNotNull(result.Profile);
        Assert.IsFalse(result.Profile.HasData);
    }

    [TestMethod]
    public async Task GetUserinfo_OnlyEmail_ReturnsEmailOnly()
    {
        // Email-only response (when only 'email' scope was granted)
        
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, @"{
            ""email"": ""user@example.com""
        }");

        var httpClient = new HttpClient(mockHandler);
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.GetUserinfoAsync(
            "https://example.com/userinfo",
            "valid_token");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.IsNotNull(result.Profile);
        Assert.AreEqual("user@example.com", result.Profile.Email);
        Assert.IsNull(result.Profile.Name);
    }

    #endregion

    #region Error Response Tests

    [TestMethod]
    public async Task GetUserinfo_Unauthorized_ReturnsInvalidTokenError()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.Unauthorized, @"{
            ""error"": ""invalid_token"",
            ""error_description"": ""The access token is expired""
        }");

        var httpClient = new HttpClient(mockHandler);
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.GetUserinfoAsync(
            "https://example.com/userinfo",
            "expired_token");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_token", result.Error);
        Assert.AreEqual("The access token is expired", result.ErrorDescription);
        Assert.IsNull(result.Profile);
    }

    [TestMethod]
    public async Task GetUserinfo_Forbidden_ReturnsInsufficientScopeError()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.Forbidden, @"{
            ""error"": ""insufficient_scope"",
            ""error_description"": ""The token does not have the profile scope""
        }");

        var httpClient = new HttpClient(mockHandler);
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.GetUserinfoAsync(
            "https://example.com/userinfo",
            "token_without_scope");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("insufficient_scope", result.Error);
        Assert.AreEqual("The token does not have the profile scope", result.ErrorDescription);
    }

    [TestMethod]
    public async Task GetUserinfo_BadRequest_ReturnsInvalidRequestError()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.BadRequest, @"{
            ""error"": ""invalid_request""
        }");

        var httpClient = new HttpClient(mockHandler);
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.GetUserinfoAsync(
            "https://example.com/userinfo",
            "some_token");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_request", result.Error);
    }

    [TestMethod]
    public async Task GetUserinfo_ServerError_ReturnsServerError()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(HttpStatusCode.InternalServerError, "Internal Server Error");

        var httpClient = new HttpClient(mockHandler);
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.GetUserinfoAsync(
            "https://example.com/userinfo",
            "some_token");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("server_error", result.Error);
    }

    [TestMethod]
    public async Task GetUserinfo_UnauthorizedWithoutBody_UsesDefaultError()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(HttpStatusCode.Unauthorized, "");

        var httpClient = new HttpClient(mockHandler);
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.GetUserinfoAsync(
            "https://example.com/userinfo",
            "invalid_token");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_token", result.Error);
    }

    [TestMethod]
    public async Task GetUserinfo_ForbiddenWithoutBody_UsesDefaultError()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(HttpStatusCode.Forbidden, "");

        var httpClient = new HttpClient(mockHandler);
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.GetUserinfoAsync(
            "https://example.com/userinfo",
            "token_no_scope");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("insufficient_scope", result.Error);
    }

    #endregion

    #region Missing Parameter Tests

    [TestMethod]
    public async Task GetUserinfo_MissingEndpoint_ReturnsError()
    {
        // Arrange
        var httpClient = new HttpClient();
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.GetUserinfoAsync(
            userinfoEndpoint: "",
            accessToken: "some_token");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_request", result.Error);
        Assert.AreEqual("Userinfo endpoint is required", result.ErrorDescription);
    }

    [TestMethod]
    public async Task GetUserinfo_NullEndpoint_ReturnsError()
    {
        // Arrange
        var httpClient = new HttpClient();
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.GetUserinfoAsync(
            userinfoEndpoint: null!,
            accessToken: "some_token");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_request", result.Error);
    }

    [TestMethod]
    public async Task GetUserinfo_MissingAccessToken_ReturnsError()
    {
        // Arrange
        var httpClient = new HttpClient();
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.GetUserinfoAsync(
            userinfoEndpoint: "https://example.com/userinfo",
            accessToken: "");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_request", result.Error);
        Assert.AreEqual("Access token is required", result.ErrorDescription);
    }

    [TestMethod]
    public async Task GetUserinfo_NullAccessToken_ReturnsError()
    {
        // Arrange
        var httpClient = new HttpClient();
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.GetUserinfoAsync(
            userinfoEndpoint: "https://example.com/userinfo",
            accessToken: null!);

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_request", result.Error);
    }

    #endregion

    #region Request Format Tests

    [TestMethod]
    public async Task GetUserinfo_UsesGetMethod()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, @"{}");

        var httpClient = new HttpClient(mockHandler);
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        await service.GetUserinfoAsync(
            "https://example.com/userinfo",
            "token");

        // Assert
        Assert.AreEqual(HttpMethod.Get, mockHandler.Requests[0].Method);
    }

    [TestMethod]
    public async Task GetUserinfo_SetsBearerAuthorizationHeader()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, @"{}");

        var httpClient = new HttpClient(mockHandler);
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        await service.GetUserinfoAsync(
            "https://example.com/userinfo",
            "my_access_token");

        // Assert
        var request = mockHandler.Requests[0];
        Assert.IsNotNull(request.Headers.Authorization);
        Assert.AreEqual("Bearer", request.Headers.Authorization.Scheme);
        Assert.AreEqual("my_access_token", request.Headers.Authorization.Parameter);
    }

    [TestMethod]
    public async Task GetUserinfo_SetsAcceptHeader()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, @"{}");

        var httpClient = new HttpClient(mockHandler);
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        await service.GetUserinfoAsync(
            "https://example.com/userinfo",
            "token");

        // Assert
        var request = mockHandler.Requests[0];
        Assert.IsTrue(request.Headers.Accept.Any(h => h.MediaType == "application/json"));
    }

    #endregion

    #region Constructor Tests

    [TestMethod]
    public void Constructor_WithNullHttpClient_ThrowsArgumentNullException()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
            new UserinfoService(null!, NullLogger.Instance));
    }

    [TestMethod]
    public void Constructor_WithNullLogger_UsesNullLogger()
    {
        // Should not throw
        var httpClient = new HttpClient();
        var service = new UserinfoService(httpClient, null);
        Assert.IsNotNull(service);
    }

    #endregion

    #region Spec Example Tests

    [TestMethod]
    public async Task GetUserinfo_SpecExample_ParsesCorrectly()
    {
        // Test with exact example from IndieAuth spec Section 9
        
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, @"{
            ""name"": ""Example User"",
            ""url"": ""https://user.example.net/"",
            ""photo"": ""https://user.example.net/photo.jpg"",
            ""email"": ""user@example.net""
        }");

        var httpClient = new HttpClient(mockHandler);
        var service = new UserinfoService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.GetUserinfoAsync(
            "https://indieauth.example.com/userinfo",
            "xxxxxxxxxxx");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.IsNotNull(result.Profile);
        Assert.AreEqual("Example User", result.Profile.Name);
        Assert.AreEqual("https://user.example.net/", result.Profile.Url);
        Assert.AreEqual("https://user.example.net/photo.jpg", result.Profile.Photo);
        Assert.AreEqual("user@example.net", result.Profile.Email);
        Assert.IsTrue(result.Profile.HasData);
    }

    #endregion
}
