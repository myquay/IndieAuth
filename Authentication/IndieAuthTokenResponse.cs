using AspNet.Security.IndieAuth.Infrastructure;
using System.Text;
using System.Text.Json;

namespace AspNet.Security.IndieAuth;

public class IndieAuthTokenResponse : IDisposable
{
    /// <summary>
    /// Initializes a new instance <see cref="IndieAuthTokenResponse"/>.
    /// </summary>
    /// <param name="response">The received JSON payload.</param>
    private IndieAuthTokenResponse(JsonDocument response)
    {
        Response = response;
        var root = response.RootElement;

        if (root.TryGetProperty("access_token", out var accessToken))
            AccessToken = accessToken.GetString();
        if (root.TryGetProperty("token_type", out var tokenType))
            TokenType = tokenType.GetString();
        if (root.TryGetProperty("refresh_token", out var refreshToken))
            RefreshToken = refreshToken.GetString();
        if (root.TryGetProperty("expires_in", out var expiresIn))
            ExpiresIn = expiresIn.GetString();

        Me = root.GetProperty("me").GetString();
        Error = GetStandardErrorException(response);
    }

    private IndieAuthTokenResponse(Exception error)
    {
        Error = error;
    }

    /// <summary>
    /// Creates a successful <see cref="IndieAuthTokenResponse"/>.
    /// </summary>
    /// <param name="response">The received JSON payload.</param>
    /// <returns>A <see cref="IndieAuthTokenResponse"/> instance.</returns>
    public static IndieAuthTokenResponse Success(JsonDocument response)
    {
        return new IndieAuthTokenResponse(response);
    }

    /// <summary>
    /// Creates a failed <see cref="IndieAuthTokenResponse"/>.
    /// </summary>
    /// <param name="error">The error associated with the failure.</param>
    /// <returns>A <see cref="IndieAuthTokenResponse"/> instance.</returns>
    public static IndieAuthTokenResponse Failed(Exception error)
    {
        return new IndieAuthTokenResponse(error);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        Response?.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Gets or sets the received JSON payload.
    /// </summary>
    public JsonDocument? Response { get; set; }

    /// <summary>
    /// Gets or sets the access token issued by the IndieAuth provider.
    /// </summary>
    public string? AccessToken { get; set; }

    /// <summary>
    /// Gets or sets the token type.
    /// </summary>
    /// <remarks>
    /// Typically the string “bearer”.
    /// </remarks>
    public string? TokenType { get; set; }

    /// <summary>
    /// Gets or sets the user domain
    /// </summary>
    public string? Me { get; set; }

    /// <summary>
    /// Gets or sets a refresh token that applications can use to obtain another access token if tokens can expire.
    /// </summary>
    public string? RefreshToken { get; set; }

    /// <summary>
    /// Gets or sets the validatity lifetime of the token in seconds.
    /// </summary>
    public string? ExpiresIn { get; set; }

    /// <summary>
    /// The exception in the event the response was a failure.
    /// </summary>
    public Exception? Error { get; set; }

    internal static Exception? GetStandardErrorException(JsonDocument response)
    {
        var root = response.RootElement;

        if (root.TryGetProperty("error", out var error))
        {
            var result = new StringBuilder("IndieAuth token endpoint failure: ");
            result.Append(error);

            if (root.TryGetProperty("error_description", out var errorDescription))
            {
                result.Append(";Description=");
                result.Append(errorDescription);
            }

            if (root.TryGetProperty("error_uri", out var errorUri))
            {
                result.Append(";Uri=");
                result.Append(errorUri);
            }

            var exception = new AuthenticationFailureException(result.ToString());
            exception.Data["error"] = error.ToString();
            exception.Data["error_description"] = errorDescription.ToString();
            exception.Data["error_uri"] = errorUri.ToString();

            return exception;
        }

        return null;

    }
}