using AspNet.Security.IndieAuth.Infrastructure;

namespace AspNet.Security.IndieAuth.Tests.Infrastructure;

/// <summary>
/// Unit tests for <see cref="LinkHeaderParser"/>.
/// Tests compliance with RFC 8288 Link header parsing.
/// </summary>
[TestClass]
public class LinkHeaderParserTests
{
    #region Parse Tests

    [TestMethod]
    public void Parse_NullInput_ReturnsEmpty()
    {
        // Arrange & Act
        var result = LinkHeaderParser.Parse(null).ToList();

        // Assert
        Assert.AreEqual(0, result.Count);
    }

    [TestMethod]
    public void Parse_EmptyEnumerable_ReturnsEmpty()
    {
        // Arrange
        var input = Enumerable.Empty<string>();

        // Act
        var result = LinkHeaderParser.Parse(input).ToList();

        // Assert
        Assert.AreEqual(0, result.Count);
    }

    [TestMethod]
    public void Parse_SingleLinkHeader_ReturnsOneEntry()
    {
        // Arrange
        var input = new[] { "<https://example.com/metadata>; rel=\"indieauth-metadata\"" };

        // Act
        var result = LinkHeaderParser.Parse(input).ToList();

        // Assert
        Assert.AreEqual(1, result.Count);
        Assert.AreEqual("https://example.com/metadata", result[0].Url);
        Assert.AreEqual("indieauth-metadata", result[0].Rel);
    }

    [TestMethod]
    public void Parse_MultipleLinkHeaders_ReturnsAllEntries()
    {
        // Arrange
        var input = new[]
        {
            "<https://example.com/auth>; rel=\"authorization_endpoint\"",
            "<https://example.com/token>; rel=\"token_endpoint\""
        };

        // Act
        var result = LinkHeaderParser.Parse(input).ToList();

        // Assert
        Assert.AreEqual(2, result.Count);
        Assert.AreEqual("https://example.com/auth", result[0].Url);
        Assert.AreEqual("authorization_endpoint", result[0].Rel);
        Assert.AreEqual("https://example.com/token", result[1].Url);
        Assert.AreEqual("token_endpoint", result[1].Rel);
    }

    [TestMethod]
    public void Parse_CommaSeparatedLinks_ReturnsAllEntries()
    {
        // Arrange - Multiple links in a single header value
        var input = new[] { "<https://example.com/auth>; rel=\"authorization_endpoint\", <https://example.com/token>; rel=\"token_endpoint\"" };

        // Act
        var result = LinkHeaderParser.Parse(input).ToList();

        // Assert
        Assert.AreEqual(2, result.Count);
        Assert.AreEqual("https://example.com/auth", result[0].Url);
        Assert.AreEqual("https://example.com/token", result[1].Url);
    }

    [TestMethod]
    public void Parse_UnquotedRelValue_ParsesCorrectly()
    {
        // Arrange
        var input = new[] { "<https://example.com/metadata>; rel=indieauth-metadata" };

        // Act
        var result = LinkHeaderParser.Parse(input).ToList();

        // Assert
        Assert.AreEqual(1, result.Count);
        Assert.AreEqual("indieauth-metadata", result[0].Rel);
    }

    [TestMethod]
    public void Parse_RelWithSpaces_ParsesCorrectly()
    {
        // Arrange
        var input = new[] { "<https://example.com/metadata>; rel = \"indieauth-metadata\"" };

        // Act
        var result = LinkHeaderParser.Parse(input).ToList();

        // Assert
        Assert.AreEqual(1, result.Count);
        Assert.AreEqual("indieauth-metadata", result[0].Rel);
    }

    [TestMethod]
    public void Parse_WithOtherParameters_ExtractsRelCorrectly()
    {
        // Arrange
        var input = new[] { "<https://example.com/metadata>; rel=\"indieauth-metadata\"; type=\"application/json\"" };

        // Act
        var result = LinkHeaderParser.Parse(input).ToList();

        // Assert
        Assert.AreEqual(1, result.Count);
        Assert.AreEqual("indieauth-metadata", result[0].Rel);
    }

    [TestMethod]
    public void Parse_RelativeUrl_PreservesUrl()
    {
        // Arrange
        var input = new[] { "</metadata>; rel=\"indieauth-metadata\"" };

        // Act
        var result = LinkHeaderParser.Parse(input).ToList();

        // Assert
        Assert.AreEqual(1, result.Count);
        Assert.AreEqual("/metadata", result[0].Url);
    }

    [TestMethod]
    public void Parse_NoRelParameter_SkipsEntry()
    {
        // Arrange
        var input = new[] { "<https://example.com/metadata>; type=\"application/json\"" };

        // Act
        var result = LinkHeaderParser.Parse(input).ToList();

        // Assert
        Assert.AreEqual(0, result.Count);
    }

    [TestMethod]
    public void Parse_EmptyString_ReturnsEmpty()
    {
        // Arrange
        var input = new[] { "" };

        // Act
        var result = LinkHeaderParser.Parse(input).ToList();

        // Assert
        Assert.AreEqual(0, result.Count);
    }

    [TestMethod]
    public void Parse_WhitespaceOnly_ReturnsEmpty()
    {
        // Arrange
        var input = new[] { "   " };

        // Act
        var result = LinkHeaderParser.Parse(input).ToList();

        // Assert
        Assert.AreEqual(0, result.Count);
    }

    #endregion

    #region FindFirstByRel Tests

    [TestMethod]
    public void FindFirstByRel_NullHeaders_ReturnsNull()
    {
        // Act
        var result = LinkHeaderParser.FindFirstByRel(null, "indieauth-metadata");

        // Assert
        Assert.IsNull(result);
    }

    [TestMethod]
    public void FindFirstByRel_NullRel_ReturnsNull()
    {
        // Arrange
        var input = new[] { "<https://example.com/metadata>; rel=\"indieauth-metadata\"" };

        // Act
        var result = LinkHeaderParser.FindFirstByRel(input, null!);

        // Assert
        Assert.IsNull(result);
    }

    [TestMethod]
    public void FindFirstByRel_EmptyRel_ReturnsNull()
    {
        // Arrange
        var input = new[] { "<https://example.com/metadata>; rel=\"indieauth-metadata\"" };

        // Act
        var result = LinkHeaderParser.FindFirstByRel(input, "");

        // Assert
        Assert.IsNull(result);
    }

    [TestMethod]
    public void FindFirstByRel_MatchingRel_ReturnsUrl()
    {
        // Arrange
        var input = new[] { "<https://example.com/metadata>; rel=\"indieauth-metadata\"" };

        // Act
        var result = LinkHeaderParser.FindFirstByRel(input, "indieauth-metadata");

        // Assert
        Assert.AreEqual("https://example.com/metadata", result);
    }

    [TestMethod]
    public void FindFirstByRel_CaseInsensitiveMatch_ReturnsUrl()
    {
        // Arrange
        var input = new[] { "<https://example.com/metadata>; rel=\"IndieAuth-Metadata\"" };

        // Act
        var result = LinkHeaderParser.FindFirstByRel(input, "indieauth-metadata");

        // Assert
        Assert.AreEqual("https://example.com/metadata", result);
    }

    [TestMethod]
    public void FindFirstByRel_MultipleMatches_ReturnsFirst()
    {
        // Arrange - First matching takes precedence per spec
        var input = new[]
        {
            "<https://example.com/first>; rel=\"indieauth-metadata\"",
            "<https://example.com/second>; rel=\"indieauth-metadata\""
        };

        // Act
        var result = LinkHeaderParser.FindFirstByRel(input, "indieauth-metadata");

        // Assert
        Assert.AreEqual("https://example.com/first", result);
    }

    [TestMethod]
    public void FindFirstByRel_NoMatch_ReturnsNull()
    {
        // Arrange
        var input = new[] { "<https://example.com/auth>; rel=\"authorization_endpoint\"" };

        // Act
        var result = LinkHeaderParser.FindFirstByRel(input, "indieauth-metadata");

        // Assert
        Assert.IsNull(result);
    }

    #endregion

    #region ResolveUrl Tests

    [TestMethod]
    public void ResolveUrl_AbsoluteUrl_ReturnsAsIs()
    {
        // Arrange
        var url = "https://example.com/metadata";
        var baseUri = new Uri("https://other.com/");

        // Act
        var result = LinkHeaderParser.ResolveUrl(url, baseUri);

        // Assert
        Assert.AreEqual("https://example.com/metadata", result);
    }

    [TestMethod]
    public void ResolveUrl_RelativeUrlWithBase_ResolvesCorrectly()
    {
        // Arrange
        var url = "/metadata";
        var baseUri = new Uri("https://example.com/page");

        // Act
        var result = LinkHeaderParser.ResolveUrl(url, baseUri);

        // Assert
        Assert.AreEqual("https://example.com/metadata", result);
    }

    [TestMethod]
    public void ResolveUrl_RelativeUrlNoSlash_ResolvesCorrectly()
    {
        // Arrange
        var url = "metadata";
        var baseUri = new Uri("https://example.com/path/");

        // Act
        var result = LinkHeaderParser.ResolveUrl(url, baseUri);

        // Assert
        Assert.AreEqual("https://example.com/path/metadata", result);
    }

    [TestMethod]
    public void ResolveUrl_RelativeUrlNoBase_ReturnsOriginal()
    {
        // Arrange
        var url = "/metadata";

        // Act
        var result = LinkHeaderParser.ResolveUrl(url, null);

        // Assert
        Assert.AreEqual("/metadata", result);
    }

    [TestMethod]
    public void ResolveUrl_EmptyUrl_ReturnsEmpty()
    {
        // Arrange
        var baseUri = new Uri("https://example.com/");

        // Act
        var result = LinkHeaderParser.ResolveUrl("", baseUri);

        // Assert
        Assert.AreEqual("", result);
    }

    [TestMethod]
    public void ResolveUrl_NullUrl_ReturnsNull()
    {
        // Arrange
        var baseUri = new Uri("https://example.com/");

        // Act
        var result = LinkHeaderParser.ResolveUrl(null!, baseUri);

        // Assert
        Assert.IsNull(result);
    }

    #endregion

    #region FindFirstByRelResolved Tests

    [TestMethod]
    public void FindFirstByRelResolved_AbsoluteUrl_ReturnsAsIs()
    {
        // Arrange
        var input = new[] { "<https://example.com/metadata>; rel=\"indieauth-metadata\"" };
        var baseUri = new Uri("https://other.com/");

        // Act
        var result = LinkHeaderParser.FindFirstByRelResolved(input, "indieauth-metadata", baseUri);

        // Assert
        Assert.AreEqual("https://example.com/metadata", result);
    }

    [TestMethod]
    public void FindFirstByRelResolved_RelativeUrl_ResolvesAgainstBase()
    {
        // Arrange
        var input = new[] { "</metadata>; rel=\"indieauth-metadata\"" };
        var baseUri = new Uri("https://example.com/page");

        // Act
        var result = LinkHeaderParser.FindFirstByRelResolved(input, "indieauth-metadata", baseUri);

        // Assert
        Assert.AreEqual("https://example.com/metadata", result);
    }

    [TestMethod]
    public void FindFirstByRelResolved_NoMatch_ReturnsNull()
    {
        // Arrange
        var input = new[] { "<https://example.com/auth>; rel=\"authorization_endpoint\"" };
        var baseUri = new Uri("https://example.com/");

        // Act
        var result = LinkHeaderParser.FindFirstByRelResolved(input, "indieauth-metadata", baseUri);

        // Assert
        Assert.IsNull(result);
    }

    #endregion

    #region Edge Cases and Real-World Examples

    [TestMethod]
    public void Parse_RealWorldIndieAuthHeader_ParsesCorrectly()
    {
        // Arrange - Example from IndieAuth spec
        var input = new[] { "<https://indieauth.example.com/.well-known/oauth-authorization-server>; rel=\"indieauth-metadata\"" };

        // Act
        var result = LinkHeaderParser.Parse(input).ToList();

        // Assert
        Assert.AreEqual(1, result.Count);
        Assert.AreEqual("https://indieauth.example.com/.well-known/oauth-authorization-server", result[0].Url);
        Assert.AreEqual("indieauth-metadata", result[0].Rel);
    }

    [TestMethod]
    public void Parse_MixedValidAndInvalidEntries_ParsesValidOnly()
    {
        // Arrange
        var input = new[]
        {
            "<https://example.com/valid>; rel=\"indieauth-metadata\"",
            "invalid-entry-no-angle-brackets",
            "<https://example.com/also-valid>; rel=\"token_endpoint\""
        };

        // Act
        var result = LinkHeaderParser.Parse(input).ToList();

        // Assert
        Assert.AreEqual(2, result.Count);
    }

    [TestMethod]
    public void FindFirstByRel_PrecedenceTest_HttpLinkHeaderFirst()
    {
        // Arrange - Simulating HTTP Link header (first) vs HTML link (second)
        var httpLinkHeaders = new[] { "<https://http-header.example.com/metadata>; rel=\"indieauth-metadata\"" };

        // Act
        var result = LinkHeaderParser.FindFirstByRel(httpLinkHeaders, "indieauth-metadata");

        // Assert - HTTP Link header should be found first
        Assert.AreEqual("https://http-header.example.com/metadata", result);
    }

    #endregion
}
