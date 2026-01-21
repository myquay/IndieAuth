using System.Net;
using AspNet.Security.IndieAuth.Infrastructure;
using AspNet.Security.IndieAuth.Tests.Helpers;

namespace AspNet.Security.IndieAuth.Tests.Authentication;

/// <summary>
/// Tests for discovery result caching in IndieAuth discovery.
/// </summary>
[TestClass]
public class DiscoveryCachingTests
{
    #region Cache Hit Tests

    [TestMethod]
    public async Task DiscoverEndpoints_CacheHit_ReturnsCachedResult()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        var cache = new InMemoryDiscoveryCache();
        
        // Pre-populate cache
        var cachedResult = new DiscoveryResult(
            Success: true,
            AuthorizationEndpoint: "https://cached.example.com/auth",
            TokenEndpoint: "https://cached.example.com/token",
            Method: DiscoveryMethod.MetadataLinkHeader);
        await cache.SetAsync("https://example.com/", cachedResult);

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient, cache: cache);
        
        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual("https://cached.example.com/auth", result.AuthorizationEndpoint);
        Assert.AreEqual("https://cached.example.com/token", result.TokenEndpoint);
        Assert.AreEqual(DiscoveryMethod.Cached, result.Method); // Method should indicate cached
        
        // Verify no HTTP requests were made
        Assert.AreEqual(0, mockHandler.Requests.Count);
    }

    [TestMethod]
    public async Task DiscoverEndpoints_CacheHit_PreservesEnhancedFields()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        var cache = new InMemoryDiscoveryCache();
        
        var cachedResult = new DiscoveryResult(
            Success: true,
            AuthorizationEndpoint: "https://example.com/auth",
            TokenEndpoint: "https://example.com/token",
            Issuer: "https://example.com/",
            UserinfoEndpoint: "https://example.com/userinfo",
            ScopesSupported: new List<string> { "profile", "email" },
            Method: DiscoveryMethod.MetadataLinkHeader,
            DiscoveredAt: DateTimeOffset.UtcNow.AddMinutes(-1));
        await cache.SetAsync("https://example.com/", cachedResult);

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient, cache: cache);
        
        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Assert
        Assert.AreEqual("https://example.com/", result.Issuer);
        Assert.AreEqual("https://example.com/userinfo", result.UserinfoEndpoint);
        Assert.IsNotNull(result.ScopesSupported);
        Assert.AreEqual(2, result.ScopesSupported.Count);
    }

    #endregion

    #region Cache Miss Tests

    [TestMethod]
    public async Task DiscoverEndpoints_CacheMiss_PerformsDiscovery()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        var cache = new InMemoryDiscoveryCache();
        
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
        var discoveryService = new IndieAuthDiscoveryService(httpClient, cache: cache);
        
        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual("https://auth.example.com/authorize", result.AuthorizationEndpoint);
        Assert.AreNotEqual(DiscoveryMethod.Cached, result.Method);
        
        // Verify HTTP requests were made
        Assert.AreEqual(2, mockHandler.Requests.Count);
    }

    [TestMethod]
    public async Task DiscoverEndpoints_CacheMiss_CachesResult()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        var cache = new InMemoryDiscoveryCache();
        
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
        var discoveryService = new IndieAuthDiscoveryService(httpClient, cache: cache);
        
        // Act
        await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Assert - Result should now be cached
        var cachedResult = await cache.GetAsync("https://example.com/");
        Assert.IsNotNull(cachedResult);
        Assert.AreEqual("https://auth.example.com/authorize", cachedResult.AuthorizationEndpoint);
    }

    #endregion

    #region Bypass Cache Tests

    [TestMethod]
    public async Task DiscoverEndpoints_BypassCache_IgnoresCachedResult()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        var cache = new InMemoryDiscoveryCache();
        
        // Pre-populate cache with old data
        var cachedResult = new DiscoveryResult(
            Success: true,
            AuthorizationEndpoint: "https://old.example.com/auth",
            TokenEndpoint: "https://old.example.com/token");
        await cache.SetAsync("https://example.com/", cachedResult);
        
        // Queue fresh response
        mockHandler.QueueResponseWithLinkHeader(
            HttpStatusCode.OK,
            HttpResponseBuilder.MinimalHtml(),
            "<https://new.example.com/metadata>; rel=\"indieauth-metadata\"");
        
        mockHandler.QueueJsonResponse(
            HttpStatusCode.OK,
            HttpResponseBuilder.MetadataJson(
                "https://new.example.com/",
                "https://new.example.com/authorize",
                "https://new.example.com/token"));

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient, cache: cache);
        
        // Act - Bypass cache
        var result = await discoveryService.DiscoverEndpointsAsync(
            "https://example.com/",
            new DiscoveryOptions { BypassCache = true });
        
        // Assert - Should get fresh data, not cached
        Assert.AreEqual("https://new.example.com/authorize", result.AuthorizationEndpoint);
        Assert.AreNotEqual(DiscoveryMethod.Cached, result.Method);
        
        // Verify HTTP requests were made
        Assert.AreEqual(2, mockHandler.Requests.Count);
    }

    [TestMethod]
    public async Task DiscoverEndpoints_BypassCache_UpdatesCache()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        var cache = new InMemoryDiscoveryCache();
        
        // Pre-populate cache with old data
        var oldResult = new DiscoveryResult(
            Success: true,
            AuthorizationEndpoint: "https://old.example.com/auth",
            TokenEndpoint: "https://old.example.com/token");
        await cache.SetAsync("https://example.com/", oldResult);
        
        // Queue fresh response
        mockHandler.QueueResponseWithLinkHeader(
            HttpStatusCode.OK,
            HttpResponseBuilder.MinimalHtml(),
            "<https://new.example.com/metadata>; rel=\"indieauth-metadata\"");
        
        mockHandler.QueueJsonResponse(
            HttpStatusCode.OK,
            HttpResponseBuilder.MetadataJson(
                "https://new.example.com/",
                "https://new.example.com/authorize",
                "https://new.example.com/token"));

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient, cache: cache);
        
        // Act - Bypass cache
        await discoveryService.DiscoverEndpointsAsync(
            "https://example.com/",
            new DiscoveryOptions { BypassCache = true });
        
        // Assert - Cache should be updated with new data
        var cachedResult = await cache.GetAsync("https://example.com/");
        Assert.IsNotNull(cachedResult);
        Assert.AreEqual("https://new.example.com/authorize", cachedResult.AuthorizationEndpoint);
    }

    #endregion

    #region No Cache Tests

    [TestMethod]
    public async Task DiscoverEndpoints_NullCache_PerformsDiscoveryWithoutCaching()
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
        var discoveryService = new IndieAuthDiscoveryService(httpClient, cache: null);
        
        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual("https://auth.example.com/authorize", result.AuthorizationEndpoint);
    }

    #endregion

    #region Failed Discovery Caching Tests

    [TestMethod]
    public async Task DiscoverEndpoints_FailedDiscovery_DoesNotCache()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        var cache = new InMemoryDiscoveryCache();
        
        // Profile URL returns 404
        mockHandler.QueueResponse(HttpStatusCode.NotFound, "Not Found");

        using var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient, cache: cache);
        
        // Act
        var result = await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Assert
        Assert.IsFalse(result.Success);
        
        // Verify result was not cached
        var cachedResult = await cache.GetAsync("https://example.com/");
        Assert.IsNull(cachedResult);
    }

    #endregion

    #region Second Request Uses Cache Tests

    [TestMethod]
    public async Task DiscoverEndpoints_SecondRequest_UsesCachedResult()
    {
        // Arrange
        var mockHandler = new MockHttpMessageHandler();
        var cache = new InMemoryDiscoveryCache();
        
        // Only queue one set of responses
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
        var discoveryService = new IndieAuthDiscoveryService(httpClient, cache: cache);
        
        // Act - First request
        var result1 = await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Act - Second request (should hit cache)
        var result2 = await discoveryService.DiscoverEndpointsAsync("https://example.com/");
        
        // Assert
        Assert.IsTrue(result1.Success);
        Assert.IsTrue(result2.Success);
        Assert.AreNotEqual(DiscoveryMethod.Cached, result1.Method);
        Assert.AreEqual(DiscoveryMethod.Cached, result2.Method);
        
        // Verify only 2 HTTP requests were made (both for first discovery)
        Assert.AreEqual(2, mockHandler.Requests.Count);
    }

    #endregion
}
