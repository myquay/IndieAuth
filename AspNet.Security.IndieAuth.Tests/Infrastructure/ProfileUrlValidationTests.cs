using AspNet.Security.IndieAuth;

namespace AspNet.Security.IndieAuth.Tests.Infrastructure;

/// <summary>
/// Unit tests for profile URL validation per IndieAuth specification section 3.2.
/// See: https://indieauth.spec.indieweb.org/#user-profile-url
/// </summary>
[TestClass]
public class ProfileUrlValidationTests
{
    #region Valid Profile URLs (from spec)

    [TestMethod]
    [Description("Spec example: https://example.com/ is a valid profile URL")]
    public void IsValidProfileUrl_SpecExample_RootPath_ReturnsValid()
    {
        // Arrange
        var url = "https://example.com/";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsTrue(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.None, result.ErrorCode);
        Assert.IsNull(result.ErrorMessage);
    }

    [TestMethod]
    [Description("Spec example: https://example.com/username is a valid profile URL")]
    public void IsValidProfileUrl_SpecExample_WithPath_ReturnsValid()
    {
        // Arrange
        var url = "https://example.com/username";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsTrue(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.None, result.ErrorCode);
    }

    [TestMethod]
    [Description("Spec example: https://example.com/users?id=100 is a valid profile URL (query strings allowed)")]
    public void IsValidProfileUrl_SpecExample_WithQueryString_ReturnsValid()
    {
        // Arrange
        var url = "https://example.com/users?id=100";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsTrue(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.None, result.ErrorCode);
    }

    [TestMethod]
    public void IsValidProfileUrl_HttpScheme_ReturnsValid()
    {
        // Arrange - http is also valid per spec
        var url = "http://example.com/";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsTrue(result.IsValid);
    }

    [TestMethod]
    public void IsValidProfileUrl_DeepPath_ReturnsValid()
    {
        // Arrange
        var url = "https://example.com/users/john/profile";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsTrue(result.IsValid);
    }

    [TestMethod]
    public void IsValidProfileUrl_SubdomainWithPath_ReturnsValid()
    {
        // Arrange
        var url = "https://blog.example.com/author/jane";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsTrue(result.IsValid);
    }

    [TestMethod]
    public void IsValidProfileUrl_TildeInPath_ReturnsValid()
    {
        // Arrange - common pattern: https://example.com/~user
        var url = "https://example.com/~user";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsTrue(result.IsValid);
    }

    [TestMethod]
    public void IsValidProfileUrl_ComplexQueryString_ReturnsValid()
    {
        // Arrange
        var url = "https://example.com/profile?user=john&type=public";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsTrue(result.IsValid);
    }

    #endregion

    #region Invalid Profile URLs (from spec)

    [TestMethod]
    [Description("Spec example: example.com - missing scheme")]
    public void IsValidProfileUrl_SpecExample_MissingScheme_ReturnsInvalid()
    {
        // Arrange
        var url = "example.com";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.MalformedUrl, result.ErrorCode);
        Assert.IsNotNull(result.ErrorMessage);
    }

    [TestMethod]
    [Description("Spec example: mailto:user@example.com - invalid scheme")]
    public void IsValidProfileUrl_SpecExample_MailtoScheme_ReturnsInvalid()
    {
        // Arrange
        var url = "mailto:user@example.com";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.InvalidScheme, result.ErrorCode);
        Assert.IsTrue(result.ErrorMessage!.Contains("mailto"));
    }

    [TestMethod]
    [Description("Spec example: https://example.com/foo/../bar - contains double-dot path segment")]
    public void IsValidProfileUrl_SpecExample_DoubleDotPath_ReturnsInvalid()
    {
        // Arrange
        var url = "https://example.com/foo/../bar";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.DotPathSegment, result.ErrorCode);
        Assert.IsTrue(result.ErrorMessage!.Contains(".."));
    }

    [TestMethod]
    [Description("Spec example: https://example.com/#me - contains a fragment")]
    public void IsValidProfileUrl_SpecExample_Fragment_ReturnsInvalid()
    {
        // Arrange
        var url = "https://example.com/#me";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.ContainsFragment, result.ErrorCode);
        Assert.IsTrue(result.ErrorMessage!.Contains("fragment"));
    }

    [TestMethod]
    [Description("Spec example: https://user:pass@example.com/ - contains username and password")]
    public void IsValidProfileUrl_SpecExample_UsernamePassword_ReturnsInvalid()
    {
        // Arrange
        var url = "https://user:pass@example.com/";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        // Could be either username or password error depending on implementation
        Assert.IsTrue(
            result.ErrorCode == ProfileUrlValidationError.ContainsUsername ||
            result.ErrorCode == ProfileUrlValidationError.ContainsPassword);
    }

    [TestMethod]
    [Description("Spec example: https://example.com:8443/ - contains a port")]
    public void IsValidProfileUrl_SpecExample_Port_ReturnsInvalid()
    {
        // Arrange
        var url = "https://example.com:8443/";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.ContainsPort, result.ErrorCode);
        Assert.IsTrue(result.ErrorMessage!.Contains("8443") || result.ErrorMessage!.Contains("port"));
    }

    [TestMethod]
    [Description("Spec example: https://172.28.92.51/ - host is an IP address")]
    public void IsValidProfileUrl_SpecExample_IPv4Address_ReturnsInvalid()
    {
        // Arrange
        var url = "https://172.28.92.51/";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.HostIsIPv4Address, result.ErrorCode);
        Assert.IsTrue(result.ErrorMessage!.Contains("172.28.92.51") || result.ErrorMessage!.Contains("IPv4"));
    }

    #endregion

    #region Null and Empty Input

    [TestMethod]
    public void IsValidProfileUrl_Null_ReturnsInvalid()
    {
        // Arrange
        string? url = null;

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.NullOrEmpty, result.ErrorCode);
    }

    [TestMethod]
    public void IsValidProfileUrl_EmptyString_ReturnsInvalid()
    {
        // Arrange
        var url = string.Empty;

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.NullOrEmpty, result.ErrorCode);
    }

    [TestMethod]
    public void IsValidProfileUrl_Whitespace_ReturnsInvalid()
    {
        // Arrange
        var url = "   ";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        // Whitespace-only URLs are treated as malformed
        Assert.IsTrue(result.ErrorCode == ProfileUrlValidationError.NullOrEmpty ||
                      result.ErrorCode == ProfileUrlValidationError.MalformedUrl);
    }

    #endregion

    #region Scheme Validation

    [TestMethod]
    public void IsValidProfileUrl_FtpScheme_ReturnsInvalid()
    {
        // Arrange
        var url = "ftp://example.com/";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.InvalidScheme, result.ErrorCode);
    }

    [TestMethod]
    public void IsValidProfileUrl_FileScheme_ReturnsInvalid()
    {
        // Arrange
        var url = "file:///home/user/profile";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.InvalidScheme, result.ErrorCode);
    }

    [TestMethod]
    public void IsValidProfileUrl_JavaScriptScheme_ReturnsInvalid()
    {
        // Arrange
        var url = "javascript:alert(1)";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.InvalidScheme, result.ErrorCode);
    }

    [TestMethod]
    public void IsValidProfileUrl_DataScheme_ReturnsInvalid()
    {
        // Arrange
        var url = "data:text/html,<h1>Hello</h1>";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.InvalidScheme, result.ErrorCode);
    }

    #endregion

    #region Dot Path Segment Validation

    [TestMethod]
    public void IsValidProfileUrl_SingleDotPath_ReturnsInvalid()
    {
        // Arrange
        var url = "https://example.com/./path";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.DotPathSegment, result.ErrorCode);
    }

    [TestMethod]
    public void IsValidProfileUrl_DoubleDotAtEnd_ReturnsInvalid()
    {
        // Arrange
        var url = "https://example.com/path/..";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.DotPathSegment, result.ErrorCode);
    }

    [TestMethod]
    public void IsValidProfileUrl_SingleDotAtEnd_ReturnsInvalid()
    {
        // Arrange
        var url = "https://example.com/path/.";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.DotPathSegment, result.ErrorCode);
    }

    [TestMethod]
    public void IsValidProfileUrl_DotInFilename_ReturnsValid()
    {
        // Arrange - dots in filenames are fine, just not as path segments
        var url = "https://example.com/file.html";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsTrue(result.IsValid);
    }

    [TestMethod]
    public void IsValidProfileUrl_MultipleDots_ReturnsValid()
    {
        // Arrange - multiple dots in segment are fine
        var url = "https://example.com/file..name";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsTrue(result.IsValid);
    }

    [TestMethod]
    public void IsValidProfileUrl_HiddenFile_ReturnsValid()
    {
        // Arrange - hidden files starting with dot are okay (not a bare . segment)
        var url = "https://example.com/.hidden";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsTrue(result.IsValid);
    }

    #endregion

    #region Fragment Validation

    [TestMethod]
    public void IsValidProfileUrl_FragmentWithPath_ReturnsInvalid()
    {
        // Arrange
        var url = "https://example.com/profile#section";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.ContainsFragment, result.ErrorCode);
    }

    [TestMethod]
    public void IsValidProfileUrl_FragmentWithQuery_ReturnsInvalid()
    {
        // Arrange
        var url = "https://example.com/?id=1#section";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.ContainsFragment, result.ErrorCode);
    }

    #endregion

    #region Username/Password Validation

    [TestMethod]
    public void IsValidProfileUrl_UsernameOnly_ReturnsInvalid()
    {
        // Arrange
        var url = "https://user@example.com/";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.ContainsUsername, result.ErrorCode);
    }

    [TestMethod]
    public void IsValidProfileUrl_EmptyUsernameWithPassword_ReturnsInvalid()
    {
        // Arrange - unusual but possible: https://:password@example.com/
        var url = "https://:password@example.com/";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.ContainsPassword, result.ErrorCode);
    }

    #endregion

    #region Port Validation

    [TestMethod]
    public void IsValidProfileUrl_DefaultHttpPort_ReturnsInvalid()
    {
        // Arrange - even default ports should be rejected per spec
        var url = "http://example.com:80/";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.ContainsPort, result.ErrorCode);
    }

    [TestMethod]
    public void IsValidProfileUrl_DefaultHttpsPort_ReturnsInvalid()
    {
        // Arrange
        var url = "https://example.com:443/";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.ContainsPort, result.ErrorCode);
    }

    [TestMethod]
    public void IsValidProfileUrl_CustomPort_ReturnsInvalid()
    {
        // Arrange
        var url = "https://example.com:3000/";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.ContainsPort, result.ErrorCode);
    }

    #endregion

    #region IP Address Validation

    [TestMethod]
    public void IsValidProfileUrl_LocalhostIPv4_ReturnsInvalid()
    {
        // Arrange
        var url = "https://127.0.0.1/";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.HostIsIPv4Address, result.ErrorCode);
    }

    [TestMethod]
    public void IsValidProfileUrl_PrivateIPv4_ReturnsInvalid()
    {
        // Arrange
        var url = "https://192.168.1.1/";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.HostIsIPv4Address, result.ErrorCode);
    }

    [TestMethod]
    public void IsValidProfileUrl_IPv6Loopback_ReturnsInvalid()
    {
        // Arrange
        var url = "https://[::1]/";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.HostIsIPv6Address, result.ErrorCode);
    }

    [TestMethod]
    public void IsValidProfileUrl_IPv6Address_ReturnsInvalid()
    {
        // Arrange
        var url = "https://[2001:db8::1]/";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.HostIsIPv6Address, result.ErrorCode);
    }

    [TestMethod]
    public void IsValidProfileUrl_LocalhostDomain_ReturnsValid()
    {
        // Arrange - "localhost" is a domain name, not an IP address
        var url = "https://localhost/";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsTrue(result.IsValid);
    }

    #endregion

    #region Edge Cases

    [TestMethod]
    public void IsValidProfileUrl_VeryLongPath_ReturnsValid()
    {
        // Arrange
        var url = "https://example.com/" + string.Join("/", Enumerable.Repeat("segment", 50));

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsTrue(result.IsValid);
    }

    [TestMethod]
    public void IsValidProfileUrl_UnicodeInPath_ReturnsValid()
    {
        // Arrange - unicode characters in path should be okay
        var url = "https://example.com/用户/profile";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsTrue(result.IsValid);
    }

    [TestMethod]
    public void IsValidProfileUrl_EncodedCharacters_ReturnsValid()
    {
        // Arrange
        var url = "https://example.com/path%20with%20spaces";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsTrue(result.IsValid);
    }

    [TestMethod]
    public void IsValidProfileUrl_InternationalDomain_ReturnsValid()
    {
        // Arrange - IDN domains are valid
        var url = "https://例え.jp/";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsTrue(result.IsValid);
    }

    [TestMethod]
    public void IsValidProfileUrl_PunycodeDomaln_ReturnsValid()
    {
        // Arrange - Punycode encoded domains are valid
        var url = "https://xn--n3h.com/";

        // Act
        var result = url.IsValidProfileUrl();

        // Assert
        Assert.IsTrue(result.IsValid);
    }

    #endregion

    #region Error Code Verification

    [TestMethod]
    public void ProfileUrlValidationError_AllErrorCodesHaveDistinctValues()
    {
        // Arrange
        var values = Enum.GetValues<ProfileUrlValidationError>();

        // Act
        var distinctCount = values.Distinct().Count();

        // Assert
        Assert.AreEqual(values.Length, distinctCount, "All error codes should have distinct values");
    }

    [TestMethod]
    public void ProfileUrlValidationResult_Success_HasCorrectProperties()
    {
        // Arrange & Act
        var result = ProfileUrlValidationResult.Success();

        // Assert
        Assert.IsTrue(result.IsValid);
        Assert.AreEqual(ProfileUrlValidationError.None, result.ErrorCode);
        Assert.IsNull(result.ErrorMessage);
    }

    [TestMethod]
    public void ProfileUrlValidationResult_FactoryMethods_ReturnInvalidResults()
    {
        // Arrange & Act
        var results = new[]
        {
            ProfileUrlValidationResult.NullOrEmpty(),
            ProfileUrlValidationResult.MalformedUrl("test"),
            ProfileUrlValidationResult.InvalidScheme("ftp"),
            ProfileUrlValidationResult.MissingPath(),
            ProfileUrlValidationResult.DotPathSegment(".."),
            ProfileUrlValidationResult.ContainsFragment(),
            ProfileUrlValidationResult.ContainsUsername(),
            ProfileUrlValidationResult.ContainsPassword(),
            ProfileUrlValidationResult.ContainsPort(8080),
            ProfileUrlValidationResult.HostIsIPv4Address("127.0.0.1"),
            ProfileUrlValidationResult.HostIsIPv6Address("::1")
        };

        // Assert
        foreach (var result in results)
        {
            Assert.IsFalse(result.IsValid, $"Factory method for {result.ErrorCode} should return invalid result");
            Assert.AreNotEqual(ProfileUrlValidationError.None, result.ErrorCode);
            Assert.IsNotNull(result.ErrorMessage);
        }
    }

    #endregion
}
