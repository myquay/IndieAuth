using AspNet.Security.IndieAuth.Infrastructure;
using Microsoft.Extensions.Caching.Memory;

namespace AspNet.Security.IndieAuth.Tests.Infrastructure;

/// <summary>
/// Unit tests for <see cref="InMemoryDiscoveryCache"/>.
/// </summary>
[TestClass]
public class DiscoveryCacheTests
{
    private const string TestProfileUrl = "https://example.com/";
    private static readonly DiscoveryResult TestResult = new(
        Success: true,
        AuthorizationEndpoint: "https://example.com/auth",
        TokenEndpoint: "https://example.com/token");

    #region GetAsync Tests

    [TestMethod]
    public async Task GetAsync_EmptyCache_ReturnsNull()
    {
        // Arrange
        var cache = new InMemoryDiscoveryCache();

        // Act
        var result = await cache.GetAsync(TestProfileUrl);

        // Assert
        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task GetAsync_NullUrl_ReturnsNull()
    {
        // Arrange
        var cache = new InMemoryDiscoveryCache();

        // Act
        var result = await cache.GetAsync(null!);

        // Assert
        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task GetAsync_EmptyUrl_ReturnsNull()
    {
        // Arrange
        var cache = new InMemoryDiscoveryCache();

        // Act
        var result = await cache.GetAsync(string.Empty);

        // Assert
        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task GetAsync_CachedItem_ReturnsItem()
    {
        // Arrange
        var cache = new InMemoryDiscoveryCache();
        await cache.SetAsync(TestProfileUrl, TestResult);

        // Act
        var result = await cache.GetAsync(TestProfileUrl);

        // Assert
        Assert.IsNotNull(result);
        Assert.IsTrue(result.Success);
        Assert.AreEqual("https://example.com/auth", result.AuthorizationEndpoint);
        Assert.AreEqual("https://example.com/token", result.TokenEndpoint);
    }

    [TestMethod]
    public async Task GetAsync_CaseInsensitiveUrl_ReturnsItem()
    {
        // Arrange
        var cache = new InMemoryDiscoveryCache();
        await cache.SetAsync("https://EXAMPLE.COM/", TestResult);

        // Act
        var result = await cache.GetAsync("https://example.com/");

        // Assert
        Assert.IsNotNull(result);
    }

    [TestMethod]
    public async Task GetAsync_TrailingSlashNormalization_ReturnsItem()
    {
        // Arrange
        var cache = new InMemoryDiscoveryCache();
        await cache.SetAsync("https://example.com", TestResult);

        // Act
        var result = await cache.GetAsync("https://example.com/");

        // Assert
        Assert.IsNotNull(result);
    }

    #endregion

    #region SetAsync Tests

    [TestMethod]
    public async Task SetAsync_NullUrl_DoesNotThrow()
    {
        // Arrange
        var cache = new InMemoryDiscoveryCache();

        // Act - Should not throw
        await cache.SetAsync(null!, TestResult);

        // Assert - No exception
    }

    [TestMethod]
    public async Task SetAsync_EmptyUrl_DoesNotThrow()
    {
        // Arrange
        var cache = new InMemoryDiscoveryCache();

        // Act - Should not throw
        await cache.SetAsync(string.Empty, TestResult);

        // Assert - No exception
    }

    [TestMethod]
    public async Task SetAsync_WithExpiration_ItemExpires()
    {
        // Arrange
        var cache = new InMemoryDiscoveryCache();
        var shortExpiration = TimeSpan.FromMilliseconds(50);

        // Act
        await cache.SetAsync(TestProfileUrl, TestResult, shortExpiration);

        // Wait for expiration
        await Task.Delay(100);

        var result = await cache.GetAsync(TestProfileUrl);

        // Assert
        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task SetAsync_OverwritesExistingEntry()
    {
        // Arrange
        var cache = new InMemoryDiscoveryCache();
        var originalResult = new DiscoveryResult(true, "https://original.com/auth", "https://original.com/token");
        var updatedResult = new DiscoveryResult(true, "https://updated.com/auth", "https://updated.com/token");

        // Act
        await cache.SetAsync(TestProfileUrl, originalResult);
        await cache.SetAsync(TestProfileUrl, updatedResult);
        var result = await cache.GetAsync(TestProfileUrl);

        // Assert
        Assert.IsNotNull(result);
        Assert.AreEqual("https://updated.com/auth", result.AuthorizationEndpoint);
    }

    #endregion

    #region RemoveAsync Tests

    [TestMethod]
    public async Task RemoveAsync_ExistingItem_RemovesItem()
    {
        // Arrange
        var cache = new InMemoryDiscoveryCache();
        await cache.SetAsync(TestProfileUrl, TestResult);

        // Act
        await cache.RemoveAsync(TestProfileUrl);
        var result = await cache.GetAsync(TestProfileUrl);

        // Assert
        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task RemoveAsync_NonExistingItem_DoesNotThrow()
    {
        // Arrange
        var cache = new InMemoryDiscoveryCache();

        // Act - Should not throw
        await cache.RemoveAsync(TestProfileUrl);

        // Assert - No exception
    }

    [TestMethod]
    public async Task RemoveAsync_NullUrl_DoesNotThrow()
    {
        // Arrange
        var cache = new InMemoryDiscoveryCache();

        // Act - Should not throw
        await cache.RemoveAsync(null!);

        // Assert - No exception
    }

    #endregion

    #region ClearAsync Tests

    [TestMethod]
    public async Task ClearAsync_WithItems_ClearsAllItems()
    {
        // Arrange
        var cache = new InMemoryDiscoveryCache();
        await cache.SetAsync("https://example1.com/", TestResult);
        await cache.SetAsync("https://example2.com/", TestResult);
        await cache.SetAsync("https://example3.com/", TestResult);

        // Act
        await cache.ClearAsync();

        // Assert
        Assert.IsNull(await cache.GetAsync("https://example1.com/"));
        Assert.IsNull(await cache.GetAsync("https://example2.com/"));
        Assert.IsNull(await cache.GetAsync("https://example3.com/"));
    }

    #endregion

    #region Constructor Tests

    [TestMethod]
    public void Constructor_WithCustomExpiration_UsesCustomExpiration()
    {
        // Arrange & Act
        var cache = new InMemoryDiscoveryCache(TimeSpan.FromMinutes(10));

        // Assert - No exception, cache is created
        Assert.IsNotNull(cache);
    }

    [TestMethod]
    public void Constructor_WithExternalMemoryCache_UsesProvidedCache()
    {
        // Arrange
        var memoryCache = new MemoryCache(new MemoryCacheOptions());
        var cache = new InMemoryDiscoveryCache(memoryCache);

        // Act & Assert - No exception
        Assert.IsNotNull(cache);
    }

    [TestMethod]
    public void Constructor_WithNullMemoryCache_ThrowsArgumentNullException()
    {
        // Arrange & Act & Assert
        Assert.ThrowsException<ArgumentNullException>(() => new InMemoryDiscoveryCache((IMemoryCache)null!));
    }

    #endregion

    #region Enhanced Result Caching Tests

    [TestMethod]
    public async Task SetAsync_EnhancedResult_PreservesAllFields()
    {
        // Arrange
        var cache = new InMemoryDiscoveryCache();
        var enhancedResult = new DiscoveryResult(
            Success: true,
            AuthorizationEndpoint: "https://example.com/auth",
            TokenEndpoint: "https://example.com/token",
            ErrorMessage: null,
            Issuer: "https://example.com/",
            UserinfoEndpoint: "https://example.com/userinfo",
            RevocationEndpoint: "https://example.com/revoke",
            IntrospectionEndpoint: "https://example.com/introspect",
            ScopesSupported: new List<string> { "profile", "email" },
            CodeChallengeMethods: new List<string> { "S256" },
            Method: DiscoveryMethod.MetadataLinkHeader,
            DiscoveredAt: DateTimeOffset.UtcNow);

        // Act
        await cache.SetAsync(TestProfileUrl, enhancedResult);
        var result = await cache.GetAsync(TestProfileUrl);

        // Assert
        Assert.IsNotNull(result);
        Assert.AreEqual("https://example.com/", result.Issuer);
        Assert.AreEqual("https://example.com/userinfo", result.UserinfoEndpoint);
        Assert.AreEqual("https://example.com/revoke", result.RevocationEndpoint);
        Assert.AreEqual("https://example.com/introspect", result.IntrospectionEndpoint);
        Assert.IsNotNull(result.ScopesSupported);
        Assert.AreEqual(2, result.ScopesSupported.Count);
        Assert.IsNotNull(result.CodeChallengeMethods);
        Assert.AreEqual(1, result.CodeChallengeMethods.Count);
        Assert.AreEqual(DiscoveryMethod.MetadataLinkHeader, result.Method);
        Assert.IsNotNull(result.DiscoveredAt);
    }

    #endregion
}
