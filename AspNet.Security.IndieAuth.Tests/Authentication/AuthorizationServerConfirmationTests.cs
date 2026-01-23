using AspNet.Security.IndieAuth;
using AspNet.Security.IndieAuth.Tests.Helpers;
using Microsoft.Extensions.Logging.Abstractions;

namespace AspNet.Security.IndieAuth.Tests.Authentication;

/// <summary>
/// Unit tests for Authorization Server Confirmation per IndieAuth spec Section 5.4.
/// Tests cover all examples from the specification.
/// </summary>
[TestClass]
public class AuthorizationServerConfirmationTests
{
    #region Spec Example 1: Basic Redirect

    [TestMethod]
    [Description("Spec Example 1: Basic redirect - returned URL matches URL in redirect chain")]
    public async Task ConfirmAuthServer_BasicRedirect_AcceptsRedirectChainMatch()
    {
        // Arrange
        // User enters www.example.com, redirects to https://example.com/, auth endpoint found there
        // Returned me: https://example.com/
        var originalDiscovery = new DiscoveryResult(
            Success: true,
            AuthorizationEndpoint: "https://example.com/auth",
            TokenEndpoint: "https://example.com/token",
            DiscoveredUrls: new List<string> 
            { 
                "http://www.example.com/",
                "https://example.com/" 
            },
            OriginalUrl: "http://www.example.com/");

        var mockHandler = new MockHttpMessageHandler();
        var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient, NullLogger.Instance);
        var confirmationService = new AuthorizationServerConfirmationService(discoveryService, NullLogger.Instance);

        // Act
        var result = await confirmationService.ConfirmAuthorizationServerAsync(
            originalDiscovery,
            returnedMeUrl: "https://example.com/",
            canonicalizedInputUrl: "https://www.example.com/");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual(ConfirmationMethod.RedirectChainMatch, result.Method);
    }

    #endregion

    #region Spec Example 2: Service Domain to Subdomain

    [TestMethod]
    [Description("Spec Example 2: Service domain to subdomain - re-discovery confirms same auth endpoint")]
    public async Task ConfirmAuthServer_ServiceDomainToSubdomain_AcceptsAfterReDiscovery()
    {
        // Arrange
        // User enters example.com, auth endpoint is https://login.example.com
        // Returned me: https://username.example.com/
        // Re-discovery of username.example.com finds same auth endpoint
        var originalDiscovery = new DiscoveryResult(
            Success: true,
            AuthorizationEndpoint: "https://login.example.com/auth",
            TokenEndpoint: "https://login.example.com/token",
            DiscoveredUrls: new List<string> 
            { 
                "http://example.com/",
                "https://example.com/" 
            },
            OriginalUrl: "http://example.com/");

        var mockHandler = new MockHttpMessageHandler();
        // Configure re-discovery response for username.example.com
        mockHandler.QueueResponse(
            System.Net.HttpStatusCode.OK,
            "<html><head><link rel=\"authorization_endpoint\" href=\"https://login.example.com/auth\">" +
            "<link rel=\"token_endpoint\" href=\"https://login.example.com/token\"></head></html>");

        var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient, NullLogger.Instance);
        var confirmationService = new AuthorizationServerConfirmationService(discoveryService, NullLogger.Instance);

        // Act
        var result = await confirmationService.ConfirmAuthorizationServerAsync(
            originalDiscovery,
            returnedMeUrl: "https://username.example.com/",
            canonicalizedInputUrl: "https://example.com/");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual(ConfirmationMethod.ReDiscoveryMatch, result.Method);
    }

    #endregion

    #region Spec Example 3: Service Domain to Path

    [TestMethod]
    [Description("Spec Example 3: Service domain to path - re-discovery confirms same auth endpoint")]
    public async Task ConfirmAuthServer_ServiceDomainToPath_AcceptsAfterReDiscovery()
    {
        // Arrange
        // User enters example.com, auth endpoint is https://login.example.com
        // Returned me: https://example.com/username
        var originalDiscovery = new DiscoveryResult(
            Success: true,
            AuthorizationEndpoint: "https://login.example.com/auth",
            TokenEndpoint: "https://login.example.com/token",
            DiscoveredUrls: new List<string> 
            { 
                "http://example.com/",
                "https://example.com/" 
            },
            OriginalUrl: "http://example.com/");

        var mockHandler = new MockHttpMessageHandler();
        // Configure re-discovery response for example.com/username
        mockHandler.QueueResponse(
            System.Net.HttpStatusCode.OK,
            "<html><head><link rel=\"authorization_endpoint\" href=\"https://login.example.com/auth\">" +
            "<link rel=\"token_endpoint\" href=\"https://login.example.com/token\"></head></html>");

        var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient, NullLogger.Instance);
        var confirmationService = new AuthorizationServerConfirmationService(discoveryService, NullLogger.Instance);

        // Act
        var result = await confirmationService.ConfirmAuthorizationServerAsync(
            originalDiscovery,
            returnedMeUrl: "https://example.com/username",
            canonicalizedInputUrl: "https://example.com/");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual(ConfirmationMethod.ReDiscoveryMatch, result.Method);
    }

    #endregion

    #region Spec Example 4: Email-like Identifier

    [TestMethod]
    [Description("Spec Example 4: Email-like identifier - re-discovery confirms same auth endpoint")]
    public async Task ConfirmAuthServer_EmailLikeIdentifier_AcceptsAfterReDiscovery()
    {
        // Arrange
        // User enters user@example.com, canonicalized to http://user@example.com/
        // Auth endpoint is https://login.example.com
        // Returned me: https://example.com/username
        var originalDiscovery = new DiscoveryResult(
            Success: true,
            AuthorizationEndpoint: "https://login.example.com/auth",
            TokenEndpoint: "https://login.example.com/token",
            DiscoveredUrls: new List<string> 
            { 
                "https://example.com/" 
            },
            OriginalUrl: "http://user@example.com/");

        var mockHandler = new MockHttpMessageHandler();
        mockHandler.QueueResponse(
            System.Net.HttpStatusCode.OK,
            "<html><head><link rel=\"authorization_endpoint\" href=\"https://login.example.com/auth\">" +
            "<link rel=\"token_endpoint\" href=\"https://login.example.com/token\"></head></html>");

        var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient, NullLogger.Instance);
        var confirmationService = new AuthorizationServerConfirmationService(discoveryService, NullLogger.Instance);

        // Act
        var result = await confirmationService.ConfirmAuthorizationServerAsync(
            originalDiscovery,
            returnedMeUrl: "https://example.com/username",
            canonicalizedInputUrl: "https://example.com/");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual(ConfirmationMethod.ReDiscoveryMatch, result.Method);
    }

    #endregion

    #region Exact Match Tests

    [TestMethod]
    public async Task ConfirmAuthServer_ExactMatch_AcceptsImmediately()
    {
        // Arrange
        var originalDiscovery = new DiscoveryResult(
            Success: true,
            AuthorizationEndpoint: "https://example.com/auth",
            TokenEndpoint: "https://example.com/token");

        var mockHandler = new MockHttpMessageHandler();
        var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient, NullLogger.Instance);
        var confirmationService = new AuthorizationServerConfirmationService(discoveryService, NullLogger.Instance);

        // Act
        var result = await confirmationService.ConfirmAuthorizationServerAsync(
            originalDiscovery,
            returnedMeUrl: "https://example.com/",
            canonicalizedInputUrl: "https://example.com/");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual(ConfirmationMethod.ExactMatch, result.Method);
    }

    [TestMethod]
    public async Task ConfirmAuthServer_ExactMatchCaseInsensitive_Accepts()
    {
        // Arrange
        var originalDiscovery = new DiscoveryResult(
            Success: true,
            AuthorizationEndpoint: "https://example.com/auth",
            TokenEndpoint: "https://example.com/token");

        var mockHandler = new MockHttpMessageHandler();
        var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient, NullLogger.Instance);
        var confirmationService = new AuthorizationServerConfirmationService(discoveryService, NullLogger.Instance);

        // Act
        var result = await confirmationService.ConfirmAuthorizationServerAsync(
            originalDiscovery,
            returnedMeUrl: "https://EXAMPLE.COM/",
            canonicalizedInputUrl: "https://example.com/");

        // Assert
        Assert.IsTrue(result.Success);
        Assert.AreEqual(ConfirmationMethod.ExactMatch, result.Method);
    }

    #endregion

    #region Failure Cases

    [TestMethod]
    public async Task ConfirmAuthServer_MismatchedAuthEndpoint_Rejects()
    {
        // Arrange
        var originalDiscovery = new DiscoveryResult(
            Success: true,
            AuthorizationEndpoint: "https://auth.example.com/authorize",
            TokenEndpoint: "https://auth.example.com/token",
            DiscoveredUrls: new List<string> { "https://example.com/" });

        var mockHandler = new MockHttpMessageHandler();
        // Different auth endpoint on the returned URL
        mockHandler.QueueResponse(
            System.Net.HttpStatusCode.OK,
            "<html><head><link rel=\"authorization_endpoint\" href=\"https://evil.com/auth\">" +
            "<link rel=\"token_endpoint\" href=\"https://evil.com/token\"></head></html>");

        var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient, NullLogger.Instance);
        var confirmationService = new AuthorizationServerConfirmationService(discoveryService, NullLogger.Instance);

        // Act
        var result = await confirmationService.ConfirmAuthorizationServerAsync(
            originalDiscovery,
            returnedMeUrl: "https://malicious.example.com/",
            canonicalizedInputUrl: "https://example.com/");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.IsTrue(result.ErrorMessage!.Contains("mismatch"));
    }

    [TestMethod]
    public async Task ConfirmAuthServer_ReDiscoveryFails_Rejects()
    {
        // Arrange
        var originalDiscovery = new DiscoveryResult(
            Success: true,
            AuthorizationEndpoint: "https://auth.example.com/authorize",
            TokenEndpoint: "https://auth.example.com/token",
            DiscoveredUrls: new List<string> { "https://example.com/" });

        var mockHandler = new MockHttpMessageHandler();
        // Re-discovery returns 404
        mockHandler.QueueResponse(new HttpResponseMessage(System.Net.HttpStatusCode.NotFound));

        var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient, NullLogger.Instance);
        var confirmationService = new AuthorizationServerConfirmationService(discoveryService, NullLogger.Instance);

        // Act
        var result = await confirmationService.ConfirmAuthorizationServerAsync(
            originalDiscovery,
            returnedMeUrl: "https://nonexistent.example.com/",
            canonicalizedInputUrl: "https://example.com/");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.IsTrue(result.ErrorMessage!.Contains("Failed to discover"));
    }

    [TestMethod]
    public async Task ConfirmAuthServer_EmptyReturnedMe_Rejects()
    {
        // Arrange
        var originalDiscovery = new DiscoveryResult(
            Success: true,
            AuthorizationEndpoint: "https://example.com/auth",
            TokenEndpoint: "https://example.com/token");

        var mockHandler = new MockHttpMessageHandler();
        var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient, NullLogger.Instance);
        var confirmationService = new AuthorizationServerConfirmationService(discoveryService, NullLogger.Instance);

        // Act
        var result = await confirmationService.ConfirmAuthorizationServerAsync(
            originalDiscovery,
            returnedMeUrl: "",
            canonicalizedInputUrl: "https://example.com/");

        // Assert
        Assert.IsFalse(result.Success);
        Assert.IsTrue(result.ErrorMessage!.Contains("empty"));
    }

    [TestMethod]
    public async Task ConfirmAuthServer_OriginalDiscoveryFailed_Rejects()
    {
        // Arrange
        var originalDiscovery = new DiscoveryResult(
            Success: false,
            AuthorizationEndpoint: "",
            TokenEndpoint: "",
            ErrorMessage: "Discovery failed");

        var mockHandler = new MockHttpMessageHandler();
        var httpClient = new HttpClient(mockHandler);
        var discoveryService = new IndieAuthDiscoveryService(httpClient, NullLogger.Instance);
        var confirmationService = new AuthorizationServerConfirmationService(discoveryService, NullLogger.Instance);

        // Act
        var result = await confirmationService.ConfirmAuthorizationServerAsync(
            originalDiscovery,
            returnedMeUrl: "https://example.com/",
            canonicalizedInputUrl: "https://example.com/");

        // Assert
        Assert.IsFalse(result.Success);
    }

    #endregion
}
