using System.Net;
using System.Text;
using AspNet.Security.IndieAuth;
using AspNet.Security.IndieAuth.Tests.Helpers;
using Microsoft.Extensions.Logging.Abstractions;

namespace AspNet.Security.IndieAuth.Tests.Authentication;

/// <summary>
/// Unit tests for Token Introspection per IndieAuth Section 6 (RFC 7662).
/// </summary>
[TestClass]
public class TokenIntrospectionTests
{
    #region Active Token Tests

    [TestMethod]
    public async Task IntrospectToken_ActiveToken_ReturnsActiveResult()
    {
        // Arrange - Example 14 from spec
        var responseJson = @"{
            ""active"": true,
            ""me"": ""https://user.example.net/"",
            ""client_id"": ""https://app.example.com/"",
            ""scope"": ""create update delete"",
            ""exp"": 1632443647,
            ""iat"": 1632443147
        }";

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, responseJson);
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.IntrospectTokenAsync(
            "https://auth.example.com/introspect",
            "test-token");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.IsTrue(result.Active);
        Assert.AreEqual("https://user.example.net/", result.Me);
        Assert.AreEqual("https://app.example.com/", result.ClientId);
        Assert.AreEqual("create update delete", result.Scope);
        Assert.AreEqual(1632443647L, result.Exp);
        Assert.AreEqual(1632443147L, result.Iat);
    }

    [TestMethod]
    public async Task IntrospectToken_ActiveTokenWithStringActive_ReturnsActiveResult()
    {
        // Some servers return "true" as a string
        var responseJson = @"{
            ""active"": ""true"",
            ""me"": ""https://user.example.net/""
        }";

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, responseJson);
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.IntrospectTokenAsync(
            "https://auth.example.com/introspect",
            "test-token");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.IsTrue(result.Active);
        Assert.AreEqual("https://user.example.net/", result.Me);
    }

    [TestMethod]
    public async Task IntrospectToken_ActiveTokenWithStringNumbers_ParsesCorrectly()
    {
        // Some servers return exp/iat as strings
        var responseJson = @"{
            ""active"": true,
            ""me"": ""https://user.example.net/"",
            ""exp"": ""1632443647"",
            ""iat"": ""1632443147""
        }";

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, responseJson);
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.IntrospectTokenAsync(
            "https://auth.example.com/introspect",
            "test-token");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual(1632443647L, result.Exp);
        Assert.AreEqual(1632443147L, result.Iat);
    }

    #endregion

    #region Inactive Token Tests

    [TestMethod]
    public async Task IntrospectToken_InactiveToken_ReturnsInactiveResult()
    {
        // Arrange - Example 15 from spec
        var responseJson = @"{ ""active"": false }";

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, responseJson);
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.IntrospectTokenAsync(
            "https://auth.example.com/introspect",
            "test-token");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.IsFalse(result.Active);
        Assert.IsNull(result.Me);
    }

    [TestMethod]
    public async Task IntrospectToken_InactiveTokenWithStringFalse_ReturnsInactiveResult()
    {
        var responseJson = @"{ ""active"": ""false"" }";

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, responseJson);
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.IntrospectTokenAsync(
            "https://auth.example.com/introspect",
            "test-token");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.IsFalse(result.Active);
    }

    #endregion

    #region Error Response Tests

    [TestMethod]
    public async Task IntrospectToken_Unauthorized_ReturnsFailure()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(HttpStatusCode.Unauthorized, "");
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.IntrospectTokenAsync(
            "https://auth.example.com/introspect",
            "test-token");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("unauthorized", result.Error);
    }

    [TestMethod]
    public async Task IntrospectToken_ServerError_ReturnsFailure()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(HttpStatusCode.InternalServerError, "Internal Server Error");
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.IntrospectTokenAsync(
            "https://auth.example.com/introspect",
            "test-token");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("server_error", result.Error);
    }

    [TestMethod]
    public async Task IntrospectToken_MissingActiveProperty_ReturnsFailure()
    {
        // Arrange
        var responseJson = @"{ ""me"": ""https://user.example.net/"" }";

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, responseJson);
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.IntrospectTokenAsync(
            "https://auth.example.com/introspect",
            "test-token");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_response", result.Error);
        Assert.IsTrue(result.ErrorDescription?.Contains("active") == true);
    }

    [TestMethod]
    public async Task IntrospectToken_ActiveTrueButMissingMe_ReturnsFailure()
    {
        // Per IndieAuth spec, 'me' is required for active tokens
        var responseJson = @"{
            ""active"": true,
            ""client_id"": ""https://app.example.com/"",
            ""scope"": ""create""
        }";

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, responseJson);
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.IntrospectTokenAsync(
            "https://auth.example.com/introspect",
            "test-token");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_response", result.Error);
        Assert.IsTrue(result.ErrorDescription?.Contains("me") == true);
    }

    [TestMethod]
    public async Task IntrospectToken_InvalidJson_ReturnsFailure()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, "not valid json");
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.IntrospectTokenAsync(
            "https://auth.example.com/introspect",
            "test-token");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_response", result.Error);
    }

    #endregion

    #region Input Validation Tests

    [TestMethod]
    public async Task IntrospectToken_NullEndpoint_ReturnsFailure()
    {
        var mockHandler = new MockHttpMessageHandler();
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        var result = await service.IntrospectTokenAsync(
            null!,
            "test-token");

        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_request", result.Error);
    }

    [TestMethod]
    public async Task IntrospectToken_EmptyEndpoint_ReturnsFailure()
    {
        var mockHandler = new MockHttpMessageHandler();
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        var result = await service.IntrospectTokenAsync(
            "",
            "test-token");

        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_request", result.Error);
    }

    [TestMethod]
    public async Task IntrospectToken_NullToken_ReturnsFailure()
    {
        var mockHandler = new MockHttpMessageHandler();
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        var result = await service.IntrospectTokenAsync(
            "https://auth.example.com/introspect",
            null!);

        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_request", result.Error);
    }

    [TestMethod]
    public async Task IntrospectToken_EmptyToken_ReturnsFailure()
    {
        var mockHandler = new MockHttpMessageHandler();
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        var result = await service.IntrospectTokenAsync(
            "https://auth.example.com/introspect",
            "");

        Assert.IsFalse(result.Success);
        Assert.AreEqual("invalid_request", result.Error);
    }

    #endregion

    #region Authentication Method Tests

    [TestMethod]
    public async Task IntrospectToken_BearerAuth_SendsAuthorizationHeader()
    {
        // Arrange
        var responseJson = @"{ ""active"": true, ""me"": ""https://user.example.net/"" }";

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, responseJson);
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        // Act
        await service.IntrospectTokenAsync(
            "https://auth.example.com/introspect",
            "test-token",
            IntrospectionAuthMethod.Bearer,
            authToken: "resource-server-token");

        // Assert
        var request = mockHandler.Requests[0];
        Assert.IsNotNull(request.Headers.Authorization);
        Assert.AreEqual("Bearer", request.Headers.Authorization.Scheme);
        Assert.AreEqual("resource-server-token", request.Headers.Authorization.Parameter);
    }

    [TestMethod]
    public async Task IntrospectToken_ClientCredentialsAuth_SendsBasicHeader()
    {
        // Arrange
        var responseJson = @"{ ""active"": true, ""me"": ""https://user.example.net/"" }";

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, responseJson);
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        // Act
        await service.IntrospectTokenAsync(
            "https://auth.example.com/introspect",
            "test-token",
            IntrospectionAuthMethod.ClientCredentials,
            clientId: "my-client",
            clientSecret: "my-secret");

        // Assert
        var request = mockHandler.Requests[0];
        Assert.IsNotNull(request.Headers.Authorization);
        Assert.AreEqual("Basic", request.Headers.Authorization.Scheme);

        var expectedCredentials = Convert.ToBase64String(Encoding.UTF8.GetBytes("my-client:my-secret"));
        Assert.AreEqual(expectedCredentials, request.Headers.Authorization.Parameter);
    }

    [TestMethod]
    public async Task IntrospectToken_NoAuth_NoAuthorizationHeader()
    {
        // Arrange
        var responseJson = @"{ ""active"": true, ""me"": ""https://user.example.net/"" }";

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, responseJson);
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        // Act
        await service.IntrospectTokenAsync(
            "https://auth.example.com/introspect",
            "test-token",
            IntrospectionAuthMethod.None);

        // Assert
        var request = mockHandler.Requests[0];
        Assert.IsNull(request.Headers.Authorization);
    }

    #endregion

    #region Request Format Tests

    [TestMethod]
    public async Task IntrospectToken_SendsTokenInBody()
    {
        // Arrange
        var responseJson = @"{ ""active"": true, ""me"": ""https://user.example.net/"" }";

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, responseJson);
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        // Act
        await service.IntrospectTokenAsync(
            "https://auth.example.com/introspect",
            "my-access-token");

        // Assert
        var request = mockHandler.Requests[0];
        Assert.AreEqual(HttpMethod.Post, request.Method);

        var content = await request.Content!.ReadAsStringAsync();
        Assert.IsTrue(content.Contains("token=my-access-token"));
    }

    [TestMethod]
    public async Task IntrospectToken_WithTokenTypeHint_IncludesHint()
    {
        // Arrange
        var responseJson = @"{ ""active"": true, ""me"": ""https://user.example.net/"" }";

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, responseJson);
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        // Act
        await service.IntrospectTokenAsync(
            "https://auth.example.com/introspect",
            "test-token",
            tokenTypeHint: "access_token");

        // Assert
        var request = mockHandler.Requests[0];
        var content = await request.Content!.ReadAsStringAsync();
        Assert.IsTrue(content.Contains("token_type_hint=access_token"));
    }

    [TestMethod]
    public async Task IntrospectToken_AcceptsJson()
    {
        // Arrange
        var responseJson = @"{ ""active"": true, ""me"": ""https://user.example.net/"" }";

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, responseJson);
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        // Act
        await service.IntrospectTokenAsync(
            "https://auth.example.com/introspect",
            "test-token");

        // Assert
        var request = mockHandler.Requests[0];
        Assert.IsTrue(request.Headers.Accept.Any(h => h.MediaType == "application/json"));
    }

    #endregion

    #region RawResponse Tests

    [TestMethod]
    public async Task IntrospectToken_ActiveToken_IncludesRawResponse()
    {
        // Arrange
        var responseJson = @"{
            ""active"": true,
            ""me"": ""https://user.example.net/"",
            ""custom_field"": ""custom_value""
        }";

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, responseJson);
        var httpClient = new HttpClient(mockHandler);
        var service = new TokenIntrospectionService(httpClient, NullLogger.Instance);

        // Act
        var result = await service.IntrospectTokenAsync(
            "https://auth.example.com/introspect",
            "test-token");

        // Assert
        Assert.IsNotNull(result.RawResponse);
        Assert.IsTrue(result.RawResponse.RootElement.TryGetProperty("custom_field", out var customField));
        Assert.AreEqual("custom_value", customField.GetString());
    }

    #endregion
}
