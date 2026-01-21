using System.Net;
using AspNet.Security.IndieAuth.Tests.Helpers;

namespace AspNet.Security.IndieAuth.Tests.Authentication;

/// <summary>
/// Integration tests for IndieAuth endpoint discovery.
/// Tests compliance with IndieAuth spec Section 4.1 - Discovery by Clients.
/// </summary>
[TestClass]
public class DiscoveryTests
{
    #region HTTP Link Header Discovery Tests

    [TestMethod]
    public async Task DiscoverEndpoints_MetadataInHttpLinkHeader_ReturnsEndpoints()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        
        // Profile page with metadata in Link header
        mockHandler.QueueResponseWithLinkHeader(
            HttpStatusCode.OK,
            HttpResponseBuilder.MinimalHtml(),
            "<https://auth.example.com/.well-known/oauth-authorization-server>; rel=\"indieauth-metadata\"");
        
        // Metadata response
        mockHandler.QueueJsonResponse(
            HttpStatusCode.OK,
            HttpResponseBuilder.MetadataJson(
                "https://auth.example.com/",
                "https://auth.example.com/authorize",
                "https://auth.example.com/token"));

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient);
        
        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual("https://auth.example.com/authorize", result.AuthorizationEndpoint);
        Assert.AreEqual("https://auth.example.com/token", result.TokenEndpoint);
    }

    [TestMethod]
    public async Task DiscoverEndpoints_MetadataInHtmlOnly_ReturnsEndpoints()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        
        // Profile page with metadata only in HTML (no Link header)
        mockHandler.QueueResponse(
            HttpStatusCode.OK,
            HttpResponseBuilder.HtmlWithMetadataLink("https://auth.example.com/.well-known/oauth-authorization-server"));
        
        // Metadata response
        mockHandler.QueueJsonResponse(
            HttpStatusCode.OK,
            HttpResponseBuilder.MetadataJson(
                "https://auth.example.com/",
                "https://auth.example.com/authorize",
                "https://auth.example.com/token"));

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient);
        
        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual("https://auth.example.com/authorize", result.AuthorizationEndpoint);
        Assert.AreEqual("https://auth.example.com/token", result.TokenEndpoint);
    }

    [TestMethod]
    public async Task DiscoverEndpoints_BothHttpAndHtmlMetadata_HttpTakesPrecedence()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        
        // Profile page with DIFFERENT metadata URLs in Link header vs HTML
        var response = HttpResponseBuilder.Create()
            .WithOk()
            .WithIndieAuthMetadataLink("https://http-header.example.com/metadata")
            .WithHtmlContent(HttpResponseBuilder.HtmlWithMetadataLink("https://html-link.example.com/metadata"))
            .Build();
        
        mockHandler.QueueResponse(response);
        
        // Metadata response - should come from HTTP Link header URL
        mockHandler.QueueJsonResponse(
            HttpStatusCode.OK,
            HttpResponseBuilder.MetadataJson(
                "https://http-header.example.com/",
                "https://http-header.example.com/authorize",
                "https://http-header.example.com/token"));

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient);
        
        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Assert - Should use endpoints from HTTP Link header metadata
        Assert.IsTrue(result.Success);
        Assert.AreEqual("https://http-header.example.com/authorize", result.AuthorizationEndpoint);
        Assert.AreEqual("https://http-header.example.com/token", result.TokenEndpoint);
        
        // Verify only 2 requests were made (profile + metadata from Link header)
        Assert.AreEqual(2, mockHandler.Requests.Count);
    }

    #endregion

    #region Legacy Endpoint Discovery Tests

    [TestMethod]
    public async Task DiscoverEndpoints_LegacyEndpointsInHttpLinkHeader_ReturnsEndpoints()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        
        var response = HttpResponseBuilder.Create()
            .WithOk()
            .WithAuthorizationEndpointLink("https://example.com/auth")
            .WithTokenEndpointLink("https://example.com/token")
            .WithHtmlContent(HttpResponseBuilder.MinimalHtml())
            .Build();
        
        mockHandler.QueueResponse(response);

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient);
        
        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual("https://example.com/auth", result.AuthorizationEndpoint);
        Assert.AreEqual("https://example.com/token", result.TokenEndpoint);
    }

    [TestMethod]
    public async Task DiscoverEndpoints_LegacyEndpointsInHtmlOnly_ReturnsEndpoints()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        
        mockHandler.QueueResponse(
            HttpStatusCode.OK,
            HttpResponseBuilder.HtmlWithLegacyEndpoints(
                "https://example.com/auth",
                "https://example.com/token"));

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient);
        
        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual("https://example.com/auth", result.AuthorizationEndpoint);
        Assert.AreEqual("https://example.com/token", result.TokenEndpoint);
    }

    #endregion

    #region Relative URL Resolution Tests

    [TestMethod]
    public async Task DiscoverEndpoints_RelativeMetadataUrl_ResolvesCorrectly()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        
        // Profile page with relative metadata URL in Link header
        mockHandler.QueueResponseWithLinkHeader(
            HttpStatusCode.OK,
            HttpResponseBuilder.MinimalHtml(),
            "</.well-known/oauth-authorization-server>; rel=\"indieauth-metadata\"");
        
        // Metadata response
        mockHandler.QueueJsonResponse(
            HttpStatusCode.OK,
            HttpResponseBuilder.MetadataJson(
                "https://example.com/",
                "https://example.com/authorize",
                "https://example.com/token"));

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient);
        
        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual("https://example.com/authorize", result.AuthorizationEndpoint);
        Assert.AreEqual("https://example.com/token", result.TokenEndpoint);
    }

    [TestMethod]
    public async Task DiscoverEndpoints_RelativeLegacyEndpoints_ResolvesCorrectly()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        
        var response = HttpResponseBuilder.Create()
            .WithOk()
            .WithLinkHeader("/auth", "authorization_endpoint")
            .WithLinkHeader("/token", "token_endpoint")
            .WithHtmlContent(HttpResponseBuilder.MinimalHtml())
            .Build();
        
        mockHandler.QueueResponse(response);

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient);
        
        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/user/profile");
        
        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual("https://example.com/auth", result.AuthorizationEndpoint);
        Assert.AreEqual("https://example.com/token", result.TokenEndpoint);
    }

    #endregion

    #region Error Handling Tests

    [TestMethod]
    public async Task DiscoverEndpoints_ProfileUrlReturns404_ReturnsFailure()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(HttpStatusCode.NotFound, "Not Found");

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient);
        
        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual(string.Empty, result.AuthorizationEndpoint);
        Assert.AreEqual(string.Empty, result.TokenEndpoint);
        Assert.IsTrue(result.ErrorMessage?.Contains("NotFound") ?? false);
    }

    [TestMethod]
    public async Task DiscoverEndpoints_MetadataUrlReturns500_ReturnsFailure()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        
        // Profile succeeds with metadata link
        mockHandler.QueueResponseWithLinkHeader(
            HttpStatusCode.OK,
            HttpResponseBuilder.MinimalHtml(),
            "<https://auth.example.com/metadata>; rel=\"indieauth-metadata\"");
        
        // Metadata fails
        mockHandler.QueueResponse(HttpStatusCode.InternalServerError, "Server Error");

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient);
        
        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Assert
        Assert.IsFalse(result.Success);
        Assert.IsTrue(result.ErrorMessage?.Contains("InternalServerError") ?? false);
    }

    [TestMethod]
    public async Task DiscoverEndpoints_InvalidMetadataJson_ReturnsFailure()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        
        mockHandler.QueueResponseWithLinkHeader(
            HttpStatusCode.OK,
            HttpResponseBuilder.MinimalHtml(),
            "<https://auth.example.com/metadata>; rel=\"indieauth-metadata\"");
        
        // Invalid JSON
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, "{ invalid json }");

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient);
        
        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Assert
        Assert.IsFalse(result.Success);
        Assert.IsTrue(result.ErrorMessage?.Contains("Invalid metadata JSON") ?? false);
    }

    [TestMethod]
    public async Task DiscoverEndpoints_MetadataMissingEndpoints_ReturnsFailure()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        
        mockHandler.QueueResponseWithLinkHeader(
            HttpStatusCode.OK,
            HttpResponseBuilder.MinimalHtml(),
            "<https://auth.example.com/metadata>; rel=\"indieauth-metadata\"");
        
        // Metadata with missing endpoints
        mockHandler.QueueJsonResponse(HttpStatusCode.OK, "{ \"issuer\": \"https://auth.example.com/\" }");

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient);
        
        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Assert
        Assert.IsFalse(result.Success);
        Assert.IsTrue(result.ErrorMessage?.Contains("missing") ?? false);
    }

    [TestMethod]
    public async Task DiscoverEndpoints_NoEndpointsFound_ReturnsFailure()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(HttpStatusCode.OK, HttpResponseBuilder.MinimalHtml());

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient);
        
        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Assert
        Assert.IsFalse(result.Success);
        Assert.AreEqual(string.Empty, result.AuthorizationEndpoint);
        Assert.AreEqual(string.Empty, result.TokenEndpoint);
        Assert.IsTrue(result.ErrorMessage?.Contains("No IndieAuth endpoints found") ?? false);
    }

    [TestMethod]
    public async Task DiscoverEndpoints_EmptyProfileUrl_ReturnsFailure()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient);
        
        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("");
        
        // Assert
        Assert.IsFalse(result.Success);
        Assert.IsTrue(result.ErrorMessage?.Contains("required") ?? false);
    }

    #endregion
}
