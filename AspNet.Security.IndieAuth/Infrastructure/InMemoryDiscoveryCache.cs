using Microsoft.Extensions.Caching.Memory;

namespace AspNet.Security.IndieAuth.Infrastructure;

/// <summary>
/// Default in-memory implementation of <see cref="IDiscoveryCache"/>.
/// Uses <see cref="IMemoryCache"/> for thread-safe caching.
/// </summary>
public class InMemoryDiscoveryCache : IDiscoveryCache, IDisposable
{
    private readonly IMemoryCache _cache;
    private readonly TimeSpan _defaultExpiration;
    private readonly bool _ownedCache;
    private bool _disposed;
    private const string CacheKeyPrefix = "IndieAuth_Discovery_";

    /// <summary>
    /// Creates a new instance with a dedicated memory cache.
    /// </summary>
    /// <param name="defaultExpiration">Default cache expiration. Defaults to 5 minutes.</param>
    public InMemoryDiscoveryCache(TimeSpan? defaultExpiration = null)
    {
        _cache = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = 1000 // Limit to 1000 cached entries
        });
        _defaultExpiration = defaultExpiration ?? TimeSpan.FromMinutes(5);
        _ownedCache = true; // We created it, we own it
    }

    /// <summary>
    /// Creates a new instance using an existing memory cache.
    /// </summary>
    /// <param name="cache">The memory cache to use.</param>
    /// <param name="defaultExpiration">Default cache expiration. Defaults to 5 minutes.</param>
    public InMemoryDiscoveryCache(IMemoryCache cache, TimeSpan? defaultExpiration = null)
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _defaultExpiration = defaultExpiration ?? TimeSpan.FromMinutes(5);
        _ownedCache = false; // Caller owns it
    }

    /// <inheritdoc />
    public Task<DiscoveryResult?> GetAsync(string profileUrl)
    {
        if (string.IsNullOrEmpty(profileUrl))
            return Task.FromResult<DiscoveryResult?>(null);

        var key = GetCacheKey(profileUrl);
        _cache.TryGetValue(key, out DiscoveryResult? result);
        return Task.FromResult(result);
    }

    /// <inheritdoc />
    public Task SetAsync(string profileUrl, DiscoveryResult result, TimeSpan? expiration = null)
    {
        if (string.IsNullOrEmpty(profileUrl))
            return Task.CompletedTask;

        var key = GetCacheKey(profileUrl);
        var options = new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = expiration ?? _defaultExpiration,
            Size = 1 // Each entry counts as 1 toward the size limit
        };

        _cache.Set(key, result, options);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RemoveAsync(string profileUrl)
    {
        if (string.IsNullOrEmpty(profileUrl))
            return Task.CompletedTask;

        var key = GetCacheKey(profileUrl);
        _cache.Remove(key);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task ClearAsync()
    {
        // IMemoryCache doesn't have a Clear method, so we need to dispose and recreate
        // This is a limitation of using IMemoryCache directly
        // For production use with clear requirements, consider a custom implementation
        if (_cache is MemoryCache memoryCache)
        {
            memoryCache.Compact(1.0); // Remove all entries
        }
        return Task.CompletedTask;
    }

    /// <summary>
    /// Disposes the cache if it was created by this instance.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes the cache if it was created by this instance.
    /// </summary>
    /// <param name="disposing">True if called from Dispose(), false if from finalizer.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        if (disposing && _ownedCache && _cache is IDisposable disposableCache)
        {
            disposableCache.Dispose();
        }

        _disposed = true;
    }

    private static string GetCacheKey(string profileUrl)
    {
        // Normalize the URL for consistent cache keys
        return CacheKeyPrefix + profileUrl.ToLowerInvariant().TrimEnd('/');
    }
}
