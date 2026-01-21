using System.Net;

namespace AspNet.Security.IndieAuth.Tests.Helpers;

/// <summary>
/// Fluent builder for constructing HTTP responses for testing.
/// </summary>
public class HttpResponseBuilder
{
    private HttpStatusCode _statusCode = HttpStatusCode.OK;
    private string _content = string.Empty;
    private string _contentType = "text/html";
    private readonly List<string> _linkHeaders = new();
    private Uri? _requestUri;

    public static HttpResponseBuilder Create() => new();

    public HttpResponseBuilder WithStatusCode(HttpStatusCode statusCode)
    {
        _statusCode = statusCode;
        return this;
    }

    public HttpResponseBuilder WithOk() => WithStatusCode(HttpStatusCode.OK);
    public HttpResponseBuilder WithNotFound() => WithStatusCode(HttpStatusCode.NotFound);

    public HttpResponseBuilder WithContent(string content, string contentType = "text/html")
    {
        _content = content;
        _contentType = contentType;
        return this;
    }

    public HttpResponseBuilder WithHtmlContent(string html) => WithContent(html, "text/html");
    public HttpResponseBuilder WithJsonContent(string json) => WithContent(json, "application/json");

    public HttpResponseBuilder WithLinkHeader(string url, string rel)
    {
        _linkHeaders.Add($"<{url}>; rel=\"{rel}\"");
        return this;
    }

    public HttpResponseBuilder WithIndieAuthMetadataLink(string metadataUrl)
        => WithLinkHeader(metadataUrl, "indieauth-metadata");

    public HttpResponseBuilder WithAuthorizationEndpointLink(string authUrl)
        => WithLinkHeader(authUrl, "authorization_endpoint");

    public HttpResponseBuilder WithTokenEndpointLink(string tokenUrl)
        => WithLinkHeader(tokenUrl, "token_endpoint");

    public HttpResponseBuilder WithRequestUri(string uri)
    {
        _requestUri = new Uri(uri);
        return this;
    }

    public HttpResponseMessage Build()
    {
        var response = new HttpResponseMessage(_statusCode)
        {
            Content = new StringContent(_content, System.Text.Encoding.UTF8, _contentType)
        };

        foreach (var linkHeader in _linkHeaders)
        {
            response.Headers.TryAddWithoutValidation("Link", linkHeader);
        }

        if (_requestUri != null)
        {
            response.RequestMessage = new HttpRequestMessage(HttpMethod.Get, _requestUri);
        }

        return response;
    }

    /// <summary>
    /// Builds an HTML page with indieauth-metadata link element.
    /// </summary>
    public static string HtmlWithMetadataLink(string metadataUrl)
        => $"<!DOCTYPE html><html><head><link rel=\"indieauth-metadata\" href=\"{metadataUrl}\"></head><body></body></html>";

    /// <summary>
    /// Builds an HTML page with legacy authorization and token endpoint links.
    /// </summary>
    public static string HtmlWithLegacyEndpoints(string authUrl, string tokenUrl)
        => $"<!DOCTYPE html><html><head><link rel=\"authorization_endpoint\" href=\"{authUrl}\"><link rel=\"token_endpoint\" href=\"{tokenUrl}\"></head><body></body></html>";

    /// <summary>
    /// Builds minimal HTML without any IndieAuth links.
    /// </summary>
    public static string MinimalHtml()
        => "<!DOCTYPE html><html><head></head><body></body></html>";

    /// <summary>
    /// Builds IndieAuth server metadata JSON.
    /// </summary>
    public static string MetadataJson(string issuer, string authEndpoint, string tokenEndpoint)
        => $@"{{
            ""issuer"": ""{issuer}"",
            ""authorization_endpoint"": ""{authEndpoint}"",
            ""token_endpoint"": ""{tokenEndpoint}"",
            ""code_challenge_methods_supported"": [""S256""]
        }}";
}
