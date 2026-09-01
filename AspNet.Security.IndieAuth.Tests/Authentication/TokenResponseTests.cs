using System.Text.Json;
using AspNet.Security.IndieAuth;

namespace AspNet.Security.IndieAuth.Tests.Authentication;

[TestClass]
public class TokenResponseTests
{
    [TestMethod]
    public void NumericExpiresIn_IsParsedAsSeconds()
    {
        using var response = IndieAuthTokenResponse.Success(JsonDocument.Parse("""
            {
              "access_token": "access-token",
              "token_type": "Bearer",
              "expires_in": 900,
              "me": "https://example.com/"
            }
            """));

        Assert.AreEqual("900", response.ExpiresIn);
    }

    [TestMethod]
    public void StringExpiresIn_RemainsSupported()
    {
        using var response = IndieAuthTokenResponse.Success(JsonDocument.Parse("""
            {
              "access_token": "access-token",
              "token_type": "Bearer",
              "expires_in": "900",
              "me": "https://example.com/"
            }
            """));

        Assert.AreEqual("900", response.ExpiresIn);
    }
}
