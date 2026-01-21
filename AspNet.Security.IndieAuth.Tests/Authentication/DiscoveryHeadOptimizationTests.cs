using System.Net;
using AspNet.Security.IndieAuth.Tests.Helpers;

namespace AspNet.Security.IndieAuth.Tests.Authentication;

/// <summary>
/// Tests for HEAD request optimization in IndieAuth discovery.
/// Tests compliance with IndieAuth spec Section 4.1 which states:
/// "Clients MAY initially make an HTTP HEAD request to follow redirects and check for the Link header before making a GET request."
/// </summary>
[TestClass]
public class DiscoveryHeadOptimizationTests
{
    #region HEAD Request Success Tests

    [TestMethod]
    public async Task DiscoverEndpoints_HeadRequestEnabled_FindsMetadataInLinkHeader_SkipsGetRequest()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        
        // HEAD request returns Link header with metadata
        mockHandler.QueueResponseWithLinkHeader(
            HttpStatusCode.OK,
            string.Empty, // HEAD has no body
            "<https://auth.example.com/metadata>; rel=\"indieauth-metadata\"",
            true); // isHeadRequest
        
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
        var result = await discoveryService.DiscoverEndpointsAsync(
            "https://example.com/", 
            new DiscoveryOptions { UseHeadRequest = true });
        
        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual("https://auth.example.com/authorize", result.AuthorizationEndpoint);
        Assert.AreEqual("https://auth.example.com/token", result.TokenEndpoint);
        Assert.AreEqual(DiscoveryMethod.MetadataLinkHeader, result.Method);
        
        // Verify: 1 HEAD + 1 metadata GET = 2 requests (no profile GET)
        Assert.AreEqual(2, mockHandler.Requests.Count);
        Assert.AreEqual(HttpMethod.Head, mockHandler.Requests[0].Method);
        Assert.AreEqual(HttpMethod.Get, mockHandler.Requests[1].Method);
    }

    [TestMethod]
    public async Task DiscoverEndpoints_HeadRequestEnabled_FindsLegacyEndpointsInLinkHeader_SkipsGetRequest()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        
        // HEAD request returns Link headers with legacy endpoints
        var response = HttpResponseBuilder.Create()
            .WithOk()
            .WithAuthorizationEndpointLink("https://example.com/auth")
            .WithTokenEndpointLink("https://example.com/token")
            .Build();
        
        // Modify for HEAD request (no body)
        response.Content = new StringContent(string.Empty);
        mockHandler.QueueResponse(response);

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient);
        
        // Act
        var result = await discoveryService.DiscoverEndpointsAsync(
            "https://example.com/", 
            new DiscoveryOptions { UseHeadRequest = true });
        
        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual("https://example.com/auth", result.AuthorizationEndpoint);
        Assert.AreEqual("https://example.com/token", result.TokenEndpoint);
        Assert.AreEqual(DiscoveryMethod.LegacyLinkHeader, result.Method);
        
        // Only 1 request (HEAD found legacy endpoints)
        Assert.AreEqual(1, mockHandler.Requests.Count);
    }

    #endregion

    #region HEAD Request Fallback Tests

    [TestMethod]
    public async Task DiscoverEndpoints_HeadRequestEnabled_NoLinkHeaders_FallsBackToGet()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        
        // HEAD request returns no Link headers
        mockHandler.QueueResponse(HttpStatusCode.OK, string.Empty);
        
        // GET request returns HTML with metadata link
        mockHandler.QueueResponse(
            HttpStatusCode.OK,
            HttpResponseBuilder.HtmlWithMetadataLink("https://auth.example.com/metadata"));
        
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
        var result = await discoveryService.DiscoverEndpointsAsync(
            "https://example.com/", 
            new DiscoveryOptions { UseHeadRequest = true });
        
        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual(DiscoveryMethod.MetadataHtmlLink, result.Method);
        
        // Verify: 1 HEAD + 1 GET + 1 metadata = 3 requests
        Assert.AreEqual(3, mockHandler.Requests.Count);
    }

    [TestMethod]
    public async Task DiscoverEndpoints_HeadRequestFails_FallsBackToGet()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        
        // HEAD request fails with error
        mockHandler.QueueResponse(HttpStatusCode.MethodNotAllowed, "Method Not Allowed");
        
        // GET request succeeds
        mockHandler.QueueResponseWithLinkHeader(
            HttpStatusCode.OK,
            HttpResponseBuilder.MinimalHtml(),
            "<https://auth.example.com/metadata>; rel=\"indieauth-metadata\"");
        
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
        var result = await discoveryService.DiscoverEndpointsAsync(
            "https://example.com/", 
            new DiscoveryOptions { UseHeadRequest = true });
        
        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual("https://auth.example.com/authorize", result.AuthorizationEndpoint);
    }

    #endregion

    #region HEAD Request Disabled Tests

    [TestMethod]
    public async Task DiscoverEndpoints_HeadRequestDisabled_UsesGetDirectly()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        
        // GET request with Link header
        mockHandler.QueueResponseWithLinkHeader(
            HttpStatusCode.OK,
            HttpResponseBuilder.MinimalHtml(),
            "<https://auth.example.com/metadata>; rel=\"indieauth-metadata\"");
        
        // Metadata response
        mockHandler.QueueJsonResponse(
            HttpStatusCode.OK,
            HttpResponseBuilder.MetadataJson(
                "https://auth.example.com/",
                "https://auth.example.com/authorize",
                "https://auth.example.com/token"));

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient);
        
        // Act - Default is HEAD disabled
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Assert
        Assert.IsTrue(result.Success);
        
        // Verify: No HEAD request, only GET requests
        Assert.AreEqual(2, mockHandler.Requests.Count);
        Assert.IsTrue(mockHandler.Requests.All(r => r.Method == HttpMethod.Get));
    }

    [TestMethod]
    public async Task DiscoverEndpoints_HeadRequestExplicitlyDisabled_UsesGetDirectly()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        
        mockHandler.QueueResponseWithLinkHeader(
            HttpStatusCode.OK,
            HttpResponseBuilder.MinimalHtml(),
            "<https://auth.example.com/metadata>; rel=\"indieauth-metadata\"");
        
        mockHandler.QueueJsonResponse(
            HttpStatusCode.OK,
            HttpResponseBuilder.MetadataJson(
                "https://auth.example.com/",
                "https://auth.example.com/authorize",
                "https://auth.example.com/token"));

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient);
        
        // Act - Explicitly disable HEAD
        var result = await discoveryService.DiscoverEndpointsAsync(
            "https://example.com/",
            new DiscoveryOptions { UseHeadRequest = false });
        
        // Assert
        Assert.IsTrue(result.Success);
        Assert.IsTrue(mockHandler.Requests.All(r => r.Method == HttpMethod.Get));
    }

    #endregion
}
