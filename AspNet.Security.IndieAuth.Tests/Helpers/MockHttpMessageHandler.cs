namespace AspNet.Security.IndieAuth.Tests.Helpers;

/// <summary>
/// A mock HttpMessageHandler for testing HTTP interactions.
/// </summary>
public class MockHttpMessageHandler : HttpMessageHandler
{
    private readonly Queue<HttpResponseMessage> _responses = new();
    private readonly List<HttpRequestMessage> _requests = new();

    /// <summary>
    /// Gets the list of requests that were made.
    /// </summary>
    public IReadOnlyList<HttpRequestMessage> Requests => _requests;

    /// <summary>
    /// Queues a response to be returned for the next request.
    /// </summary>
    public void QueueResponse(HttpResponseMessage response)
    {
        _responses.Enqueue(response);
    }

    /// <summary>
    /// Queues a response with the specified status code and content.
    /// </summary>
    public void QueueResponse(System.Net.HttpStatusCode statusCode, string content, string contentType = "text/html")
    {
        var response = new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(content, System.Text.Encoding.UTF8, contentType)
        };
        _responses.Enqueue(response);
    }

    /// <summary>
    /// Queues a response with Link headers.
    /// </summary>
    public void QueueResponseWithLinkHeader(
        System.Net.HttpStatusCode statusCode, 
        string content, 
        params string[] linkHeaders)
    {
        var response = new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(content, System.Text.Encoding.UTF8, "text/html")
        };

        foreach (var linkHeader in linkHeaders)
        {
            response.Headers.TryAddWithoutValidation("Link", linkHeader);
        }

        _responses.Enqueue(response);
    }

    /// <summary>
    /// Queues a response with Link headers, optionally for a HEAD request (empty body).
    /// </summary>
    public void QueueResponseWithLinkHeader(
        System.Net.HttpStatusCode statusCode,
        string content,
        string linkHeader,
        bool isHeadRequest)
    {
        var response = new HttpResponseMessage(statusCode)
        {
            Content = isHeadRequest 
                ? new StringContent(string.Empty) 
                : new StringContent(content, System.Text.Encoding.UTF8, "text/html")
        };

        response.Headers.TryAddWithoutValidation("Link", linkHeader);
        _responses.Enqueue(response);
    }

    /// <summary>
    /// Queues a JSON response.
    /// </summary>
    public void QueueJsonResponse(System.Net.HttpStatusCode statusCode, string json)
    {
        var response = new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
        };
        _responses.Enqueue(response);
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        _requests.Add(request);

        if (_responses.Count == 0)
        {
            throw new InvalidOperationException($"No response queued for request to {request.RequestUri}");
        }

        var response = _responses.Dequeue();
        
        // Set the RequestUri on the response to simulate the final URL after redirects
        response.RequestMessage = request;

        return Task.FromResult(response);
    }
}
