namespace AspNet.Security.IndieAuth.Infrastructure;

/// <summary>
/// Interface for caching IndieAuth discovery results.
/// </summary>
public interface IDiscoveryCache
{
    /// <summary>
    /// Gets a cached discovery result for the specified profile URL.
    /// </summary>
    /// <param name="profileUrl">The profile URL to look up.</param>
    /// <returns>The cached result, or null if not found or expired.</returns>
    Task<DiscoveryResult?> GetAsync(string profileUrl);

    /// <summary>
    /// Stores a discovery result in the cache.
    /// </summary>
    /// <param name="profileUrl">The profile URL as the cache key.</param>
    /// <param name="result">The discovery result to cache.</param>
    /// <param name="expiration">Optional expiration time. Uses default if not specified.</param>
    Task SetAsync(string profileUrl, DiscoveryResult result, TimeSpan? expiration = null);

    /// <summary>
    /// Removes a cached discovery result.
    /// </summary>
    /// <param name="profileUrl">The profile URL to remove from cache.</param>
    Task RemoveAsync(string profileUrl);

    /// <summary>
    /// Clears all cached discovery results.
    /// </summary>
    Task ClearAsync();
}
