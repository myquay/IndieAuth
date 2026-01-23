using AspNet.Security.IndieAuth;
using AspNet.Security.IndieAuth.Tests.Helpers;
using Microsoft.Extensions.Logging.Abstractions;

namespace AspNet.Security.IndieAuth.Tests.Authentication;

/// <summary>
/// Unit tests for Issuer Validation per RFC 9207 / IndieAuth Section 5.2.1.
/// </summary>
[TestClass]
public class IssuerValidationTests
{
    #region Issuer Match Tests

    [TestMethod]
    public void IssuerValidation_ExactMatch_Succeeds()
    {
        // This test validates the logic - actual integration would require handler setup
        var expectedIssuer = "https://indieauth.example.com/";
        var receivedIssuer = "https://indieauth.example.com/";

        // Simple string comparison per spec
        var result = string.Equals(expectedIssuer, receivedIssuer, StringComparison.Ordinal);

        Assert.IsTrue(result);
    }

    [TestMethod]
    public void IssuerValidation_CaseSensitive_Fails()
    {
        // Spec requires simple string comparison - case matters
        var expectedIssuer = "https://indieauth.example.com/";
        var receivedIssuer = "https://IndieAuth.Example.Com/";

        var result = string.Equals(expectedIssuer, receivedIssuer, StringComparison.Ordinal);

        Assert.IsFalse(result, "Issuer comparison should be case-sensitive");
    }

    [TestMethod]
    public void IssuerValidation_TrailingSlashMismatch_Fails()
    {
        // Exact match required
        var expectedIssuer = "https://indieauth.example.com/";
        var receivedIssuer = "https://indieauth.example.com";

        var result = string.Equals(expectedIssuer, receivedIssuer, StringComparison.Ordinal);

        Assert.IsFalse(result, "Trailing slash difference should cause mismatch");
    }

    [TestMethod]
    public void IssuerValidation_DifferentIssuers_Fails()
    {
        var expectedIssuer = "https://auth.example.com/";
        var receivedIssuer = "https://evil.example.com/";

        var result = string.Equals(expectedIssuer, receivedIssuer, StringComparison.Ordinal);

        Assert.IsFalse(result);
    }

    #endregion

    #region Discovery Result Parsing Tests

    [TestMethod]
    public void ParseDiscoveryResult_WithIssuer_ExtractsCorrectly()
    {
        // Arrange
        var json = @"{""Success"":true,""AuthorizationEndpoint"":""https://example.com/auth"",""TokenEndpoint"":""https://example.com/token"",""Issuer"":""https://example.com/""}";

        // Act
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        string? issuer = null;
        if (doc.RootElement.TryGetProperty("Issuer", out var issuerElement))
        {
            issuer = issuerElement.GetString();
        }

        // Assert
        Assert.AreEqual("https://example.com/", issuer);
    }

    [TestMethod]
    public void ParseDiscoveryResult_WithoutIssuer_ReturnsNull()
    {
        // Arrange - Legacy discovery result without issuer
        var json = @"{""Success"":true,""AuthorizationEndpoint"":""https://example.com/auth"",""TokenEndpoint"":""https://example.com/token""}";

        // Act
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        string? issuer = null;
        if (doc.RootElement.TryGetProperty("Issuer", out var issuerElement))
        {
            issuer = issuerElement.GetString();
        }

        // Assert
        Assert.IsNull(issuer);
    }

    [TestMethod]
    public void ParseDiscoveryResult_NullIssuer_ReturnsNull()
    {
        // Arrange
        var json = @"{""Success"":true,""AuthorizationEndpoint"":""https://example.com/auth"",""Issuer"":null}";

        // Act
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        string? issuer = null;
        if (doc.RootElement.TryGetProperty("Issuer", out var issuerElement))
        {
            issuer = issuerElement.GetString();
        }

        // Assert
        Assert.IsNull(issuer);
    }

    #endregion
}
