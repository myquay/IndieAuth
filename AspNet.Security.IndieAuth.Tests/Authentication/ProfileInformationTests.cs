using AspNet.Security.IndieAuth;
using System.Text.Json;

namespace AspNet.Security.IndieAuth.Tests.Authentication;

/// <summary>
/// Unit tests for Profile Information parsing per IndieAuth spec Section 5.3.4.
/// </summary>
[TestClass]
public class ProfileInformationTests
{
    #region Profile Parsing Tests

    [TestMethod]
    public void TokenResponse_WithFullProfile_ParsesAllFields()
    {
        // Arrange
        var json = @"{
            ""me"": ""https://example.com/"",
            ""access_token"": ""token123"",
            ""token_type"": ""Bearer"",
            ""profile"": {
                ""name"": ""Example User"",
                ""url"": ""https://example.com/"",
                ""photo"": ""https://example.com/photo.jpg"",
                ""email"": ""user@example.com""
            }
        }";

        // Act
        using var response = IndieAuthTokenResponse.Success(JsonDocument.Parse(json));

        // Assert
        Assert.IsNotNull(response.Profile);
        Assert.IsTrue(response.Profile.HasData);
        Assert.AreEqual("Example User", response.Profile.Name);
        Assert.AreEqual("https://example.com/", response.Profile.Url);
        Assert.AreEqual("https://example.com/photo.jpg", response.Profile.Photo);
        Assert.AreEqual("user@example.com", response.Profile.Email);
    }

    [TestMethod]
    public void TokenResponse_WithPartialProfile_ParsesAvailableFields()
    {
        // Arrange - only name and photo, no url or email
        var json = @"{
            ""me"": ""https://example.com/"",
            ""profile"": {
                ""name"": ""John Doe"",
                ""photo"": ""https://example.com/avatar.png""
            }
        }";

        // Act
        using var response = IndieAuthTokenResponse.Success(JsonDocument.Parse(json));

        // Assert
        Assert.IsNotNull(response.Profile);
        Assert.IsTrue(response.Profile.HasData);
        Assert.AreEqual("John Doe", response.Profile.Name);
        Assert.AreEqual("https://example.com/avatar.png", response.Profile.Photo);
        Assert.IsNull(response.Profile.Url);
        Assert.IsNull(response.Profile.Email);
    }

    [TestMethod]
    public void TokenResponse_WithNoProfile_ProfileIsNull()
    {
        // Arrange
        var json = @"{
            ""me"": ""https://example.com/"",
            ""access_token"": ""token123""
        }";

        // Act
        using var response = IndieAuthTokenResponse.Success(JsonDocument.Parse(json));

        // Assert
        Assert.IsNull(response.Profile);
    }

    [TestMethod]
    public void TokenResponse_WithEmptyProfile_ProfileHasNoData()
    {
        // Arrange
        var json = @"{
            ""me"": ""https://example.com/"",
            ""profile"": {}
        }";

        // Act
        using var response = IndieAuthTokenResponse.Success(JsonDocument.Parse(json));

        // Assert
        Assert.IsNotNull(response.Profile);
        Assert.IsFalse(response.Profile.HasData);
        Assert.IsNull(response.Profile.Name);
        Assert.IsNull(response.Profile.Url);
        Assert.IsNull(response.Profile.Photo);
        Assert.IsNull(response.Profile.Email);
    }

    [TestMethod]
    public void TokenResponse_WithOnlyEmail_ParsesEmail()
    {
        // Arrange - email scope requested
        var json = @"{
            ""me"": ""https://example.com/"",
            ""profile"": {
                ""email"": ""user@example.com""
            }
        }";

        // Act
        using var response = IndieAuthTokenResponse.Success(JsonDocument.Parse(json));

        // Assert
        Assert.IsNotNull(response.Profile);
        Assert.IsTrue(response.Profile.HasData);
        Assert.AreEqual("user@example.com", response.Profile.Email);
    }

    #endregion

    #region IndieAuthProfile Record Tests

    [TestMethod]
    public void IndieAuthProfile_HasData_ReturnsTrueWhenAnyFieldSet()
    {
        // Arrange & Act & Assert
        Assert.IsTrue(new IndieAuthProfile(Name: "Test").HasData);
        Assert.IsTrue(new IndieAuthProfile(Url: "https://example.com").HasData);
        Assert.IsTrue(new IndieAuthProfile(Photo: "https://example.com/photo.jpg").HasData);
        Assert.IsTrue(new IndieAuthProfile(Email: "test@example.com").HasData);
    }

    [TestMethod]
    public void IndieAuthProfile_HasData_ReturnsFalseWhenAllNull()
    {
        // Arrange & Act
        var profile = new IndieAuthProfile();

        // Assert
        Assert.IsFalse(profile.HasData);
    }

    [TestMethod]
    public void IndieAuthProfile_RecordEquality_Works()
    {
        // Arrange
        var profile1 = new IndieAuthProfile("Test", "https://example.com", "photo.jpg", "test@example.com");
        var profile2 = new IndieAuthProfile("Test", "https://example.com", "photo.jpg", "test@example.com");

        // Act & Assert
        Assert.AreEqual(profile1, profile2);
    }

    #endregion

    #region Claim Type Tests

    [TestMethod]
    public void IndieAuthClaimTypes_HasCorrectValues()
    {
        // Assert
        Assert.AreEqual("me", IndieAuthClaimTypes.Me);
        Assert.AreEqual("name", IndieAuthClaimTypes.Name);
        Assert.AreEqual("picture", IndieAuthClaimTypes.Picture);
        Assert.AreEqual("website", IndieAuthClaimTypes.Website);
        Assert.AreEqual("email_verified", IndieAuthClaimTypes.EmailVerified);
        // Email uses standard claim type
        Assert.AreEqual(System.Security.Claims.ClaimTypes.Email, IndieAuthClaimTypes.Email);
    }

    #endregion

    #region Spec Response Examples

    [TestMethod]
    public void TokenResponse_SpecExample_ParsesCorrectly()
    {
        // Arrange - Example from spec Section 5.3.4
        var json = @"{
            ""access_token"": ""XXXXXX"",
            ""token_type"": ""Bearer"",
            ""scope"": ""profile email create"",
            ""me"": ""https://user.example.net/"",
            ""profile"": {
                ""name"": ""Example User"",
                ""url"": ""https://user.example.net/"",
                ""photo"": ""https://user.example.net/photo.jpg"",
                ""email"": ""user@example.net""
            }
        }";

        // Act
        using var response = IndieAuthTokenResponse.Success(JsonDocument.Parse(json));

        // Assert
        Assert.AreEqual("https://user.example.net/", response.Me);
        Assert.AreEqual("XXXXXX", response.AccessToken);
        Assert.AreEqual("Bearer", response.TokenType);
        Assert.IsNotNull(response.Profile);
        Assert.AreEqual("Example User", response.Profile.Name);
        Assert.AreEqual("https://user.example.net/", response.Profile.Url);
        Assert.AreEqual("https://user.example.net/photo.jpg", response.Profile.Photo);
        Assert.AreEqual("user@example.net", response.Profile.Email);
    }

    #endregion
}
