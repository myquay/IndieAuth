﻿using AspNet.Security.IndieAuth.Events;
using AspNet.Security.IndieAuth.Infrastructure;
using Microformats;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace AspNet.Security.IndieAuth;

/// <summary>
/// An authentication handler that supports IndieAuth.
/// </summary>
/// <typeparam name="TOptions">The type of options.</typeparam>
public class IndieAuthHandler<TOptions> : RemoteAuthenticationHandler<TOptions> where TOptions : IndieAuthOptions, new()
{
    /// <summary>
    /// Gets the <see cref="HttpClient"/> instance used to communicate with the remote authentication provider.
    /// </summary>
    protected HttpClient Backchannel => Options.Backchannel;

    /// <summary>
    /// Allows for handling different events during the authentication process.
    /// </summary>
    protected new IndieAuthEvents Events
    {
        get { return (IndieAuthEvents)base.Events; }
        set { base.Events = value; }
    }

    public IndieAuthHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
    {
    }

    /// <summary>
    /// Creates a new instance of the events instance.
    /// </summary>
    /// <returns>A new instance of the events instance.</returns>
    protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new IndieAuthEvents());

    /// <inheritdoc />
    protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
    {
        var query = Request.Query;

        var state = query["state"];
        var properties = Options.StateDataFormat.Unprotect(state);

        //Rehydrate the Me property from the state
        properties.SetParameter(IndieAuthChallengeProperties.MeKey, properties.Items[IndieAuthChallengeProperties.MeKey]);

        if (properties == null)
        {
            return HandleRequestResults.InvalidState;
        }

        // OAuth2 10.12 CSRF
        if (!ValidateCorrelationId(properties))
        {
            return HandleRequestResult.Fail("Correlation failed.", properties);
        }

        var error = query["error"];
        if (!StringValues.IsNullOrEmpty(error))
        {
            var errorDescription = query["error_description"];
            var errorUri = query["error_uri"];

            var failureMessage = new StringBuilder();
            failureMessage.Append(error);
            if (!StringValues.IsNullOrEmpty(errorDescription))
            {
                failureMessage.Append(";Description=").Append(errorDescription);
            }
            if (!StringValues.IsNullOrEmpty(errorUri))
            {
                failureMessage.Append(";Uri=").Append(errorUri);
            }

            var ex = new AuthenticationFailureException(failureMessage.ToString());
            ex.Data["error"] = error.ToString();
            ex.Data["error_description"] = errorDescription.ToString();
            ex.Data["error_uri"] = errorUri.ToString();

            return HandleRequestResult.Fail(ex, properties);
        }

        var code = query["code"];

        if (StringValues.IsNullOrEmpty(code))
        {
            return HandleRequestResult.Fail("Code was not found.", properties);
        }

        var tokenEndpoint = await DiscoverIndieAuthEndpoints(properties);

        if (!tokenEndpoint.success)
        {
            var failure = new AuthenticationFailureException($"Unable to load IndieAuth token endpoint for domain '{properties.GetParameter<string>(IndieAuthChallengeProperties.MeKey)}'");

            failure.Data["error"] = "invalid_request";
            failure.Data["error_description"] = "Unable to load IndieAuth token endpoint";

            await Events.RemoteFailure(new RemoteFailureContext(Context, Scheme, Options, failure)
            {
                Failure = failure,
            });
            return HandleRequestResult.Fail(failure, properties);
        }

        var codeExchangeContext = new IndieAuthCodeExchangeContext(properties, code.ToString(), BuildRedirectUri(Options.CallbackPath));
        using var tokens = await ExchangeCodeAsync(tokenEndpoint.tokenEndpoint, codeExchangeContext);

        if (tokens.Error != null)
        {
            return HandleRequestResult.Fail(tokens.Error, properties);
        }

        var returnedMe = tokens.Me;
        var me = properties.GetParameter<string>(IndieAuthChallengeProperties.MeKey);

        if (!string.Equals(returnedMe?.Canonicalize(), me?.Canonicalize(), StringComparison.OrdinalIgnoreCase))
        {
            //TODO: HANDLE OTHER CASES AS DETAILED HERE: https://indieauth.spec.indieweb.org/#example-6
            return HandleRequestResult.Fail("Returned me value does not match the me value from the challenge.", properties);
        }

        var identity = new ClaimsIdentity(new[]
        {
            new Claim(IndieAuthClaims.ME, me!)
        }, ClaimsIssuer);

        if (Options.SaveTokens)
        {
            var authTokens = new List<AuthenticationToken>();

            if (!string.IsNullOrEmpty(tokens.AccessToken))
                authTokens.Add(new AuthenticationToken { Name = "access_token", Value = tokens.AccessToken });
            if (!string.IsNullOrEmpty(tokens.RefreshToken))
                authTokens.Add(new AuthenticationToken { Name = "refresh_token", Value = tokens.RefreshToken });
            if (!string.IsNullOrEmpty(tokens.TokenType))
                authTokens.Add(new AuthenticationToken { Name = "token_type", Value = tokens.TokenType });

            if (!string.IsNullOrEmpty(tokens.ExpiresIn))
            {
                if (int.TryParse(tokens.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out int value))
                {
                    // https://www.w3.org/TR/xmlschema-2/#dateTime
                    // https://msdn.microsoft.com/en-us/library/az4se3k1(v=vs.110).aspx
                    var expiresAt = DateTime.UtcNow + TimeSpan.FromSeconds(value);
                    authTokens.Add(new AuthenticationToken
                    {
                        Name = "expires_at",
                        Value = expiresAt.ToString("o", CultureInfo.InvariantCulture)
                    });
                }
            }

            properties.StoreTokens(authTokens);
        }

        var ticket = await CreateTicketAsync(identity, properties, tokens);
        if (ticket != null)
        {
            return HandleRequestResult.Success(ticket);
        }
        else
        {
            return HandleRequestResult.Fail("Failed to retrieve user information from remote server.", properties);
        }
    }

    /// <summary>
    /// Exchanges the authorization code for a authorization token from the remote provider.
    /// </summary>
    /// <param name="context">The <see cref="OAuthCodeExchangeContext"/>.</param>
    /// <returns>The response <see cref="OAuthTokenResponse"/>.</returns>
    protected virtual async Task<IndieAuthTokenResponse> ExchangeCodeAsync(string tokenEndpoint, IndieAuthCodeExchangeContext context)
    {
        var tokenRequestParameters = new Dictionary<string, string>()
            {
                { "client_id", Options.ClientId },
                { "redirect_uri", context.RedirectUri },
                { "code", context.Code },
                { "grant_type", "authorization_code" },
            };

        // PKCE https://tools.ietf.org/html/rfc7636#section-4.5, see BuildChallengeUrl
        if (context.Properties.Items.TryGetValue(IndieAuthConstants.CodeVerifierKey, out var codeVerifier))
        {
            tokenRequestParameters.Add(IndieAuthConstants.CodeVerifierKey, codeVerifier!);
            context.Properties.Items.Remove(IndieAuthConstants.CodeVerifierKey);
        }

        var requestContent = new FormUrlEncodedContent(tokenRequestParameters!);

        var requestMessage = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
        requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        requestMessage.Content = requestContent;
        requestMessage.Version = Backchannel.DefaultRequestVersion;
        var response = await Backchannel.SendAsync(requestMessage, Context.RequestAborted);
        var body = await response.Content.ReadAsStringAsync(Context.RequestAborted);

        return response.IsSuccessStatusCode switch
        {
            true => IndieAuthTokenResponse.Success(JsonDocument.Parse(body)),
            false => PrepareFailedIndieAuthTokenReponse(response, body)
        };
    }

    private static IndieAuthTokenResponse PrepareFailedIndieAuthTokenReponse(HttpResponseMessage response, string body)
    {
        var exception = IndieAuthTokenResponse.GetStandardErrorException(JsonDocument.Parse(body));

        if (exception is null)
        {
            var errorMessage = $"IndieAuth token endpoint failure: Status: {response.StatusCode};Headers: {response.Headers};Body: {body};";
            return IndieAuthTokenResponse.Failed(new AuthenticationFailureException(errorMessage));
        }

        return IndieAuthTokenResponse.Failed(exception);
    }

    /// <summary>
    /// Creates an <see cref="AuthenticationTicket"/> from the specified <paramref name="tokens"/>.
    /// </summary>
    /// <param name="identity">The <see cref="ClaimsIdentity"/>.</param>
    /// <param name="properties">The <see cref="AuthenticationProperties"/>.</param>
    /// <param name="tokens">The <see cref="OAuthTokenResponse"/>.</param>
    /// <returns>The <see cref="AuthenticationTicket"/>.</returns>
    protected virtual async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, IndieAuthTokenResponse tokens)
    {
        using var user = JsonDocument.Parse("{}");

        var context = new IndieAuthCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options, Backchannel, tokens, user.RootElement);
        await Events.CreatingTicket(context);
        return new AuthenticationTicket(context.Principal!, context.Properties, Scheme.Name);
    }

    /// <inheritdoc />
    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var domain = properties.GetParameter<string>(IndieAuthChallengeProperties.MeKey);

        if (string.IsNullOrEmpty(domain) || !Uri.IsWellFormedUriString(domain, UriKind.Absolute))
        {
            var failure = new AuthenticationFailureException("Domain is not specified or otherwise invalid");
            await Events.RemoteFailure(new RemoteFailureContext(Context, Scheme, Options, failure)
            {
                Failure = failure,
            });
            return;
        }

        if (string.IsNullOrEmpty(properties.RedirectUri))
        {
            properties.RedirectUri = OriginalPathBase + OriginalPath + Request.QueryString;
        }

        // OAuth2 10.12 CSRF
        GenerateCorrelationId(properties);
        var (success, authEndpoint, _) = await DiscoverIndieAuthEndpoints(properties);

        if (!success)
        {
            var failure = new AuthenticationFailureException($"Unable to load IndieAuth authorization endpoint for domain '{properties.GetParameter<string>(IndieAuthChallengeProperties.MeKey)}'");
            await Events.RemoteFailure(new RemoteFailureContext(Context, Scheme, Options, failure)
            {
                Failure = failure,
            });
            return;
        }

        var authorizationEndpoint = BuildChallengeUrl(authEndpoint, properties, BuildRedirectUri(Options.CallbackPath));

        var redirectContext = new RedirectContext<IndieAuthOptions>(
            Context, Scheme, Options,
            properties, authorizationEndpoint);
        await Events.RedirectToAuthorizationEndpoint(redirectContext);

    }

    public virtual async Task<(bool success, string authEndpoint, string tokenEndpoint)> DiscoverIndieAuthEndpoints(AuthenticationProperties properties)
    {

        //Discover IndieAuth endpoint
        var response = await Options.Backchannel.GetAsync(properties.GetParameter<string>(IndieAuthChallengeProperties.MeKey));

        if (!response.IsSuccessStatusCode)
        {
            var failure = new AuthenticationFailureException($"Cannot load webpage at domain '{properties.GetParameter<string>(IndieAuthChallengeProperties.MeKey)}'");
            await Events.RemoteFailure(new RemoteFailureContext(Context, Scheme, Options, failure)
            {
                Failure = failure,
            });
            return (false, String.Empty, String.Empty);
        }

        //Parse for the IndieAuth endpoint
        var result = new Mf2().Parse(await response.Content.ReadAsStringAsync());

        if (result.Rels.ContainsKey("indieauth-metadata"))
        {
            var metadataResponse = await Options.Backchannel.GetAsync(result.Rels["indieauth-metadata"].First());
            if (!metadataResponse.IsSuccessStatusCode)
            {
                var failure = new AuthenticationFailureException($"Cannot load IndieAuth metadata '{result.Rels["indieauth-metadata"].First()}'");
                await Events.RemoteFailure(new RemoteFailureContext(Context, Scheme, Options, failure)
                {
                    Failure = failure,
                });
                return (false, String.Empty, String.Empty);
            }

            var metadata = JsonSerializer.Deserialize<IndieAuthServerMetadataResponse>(await metadataResponse.Content.ReadAsStreamAsync(), new JsonSerializerOptions
            {
                PropertyNamingPolicy = new SnakeCaseNamingPolicy()
            });

            if (Uri.IsWellFormedUriString(metadata?.AuthorizationEndpoint, UriKind.Absolute))
                return (true, metadata.AuthorizationEndpoint, metadata.TokenEndpoint);
            return (false, String.Empty, String.Empty);
        }

        var authEndpoint = result.Rels.ContainsKey("authorization_endpoint") && Uri.IsWellFormedUriString(result.Rels["authorization_endpoint"].First(), UriKind.Absolute) ? result.Rels["authorization_endpoint"].First() : String.Empty;
        var tokenEndpoint = result.Rels.ContainsKey("token_endpoint") && Uri.IsWellFormedUriString(result.Rels["token_endpoint"].First(), UriKind.Absolute) ? result.Rels["token_endpoint"].First() : String.Empty;

        return (!string.IsNullOrEmpty(authEndpoint) && !string.IsNullOrEmpty(tokenEndpoint), authEndpoint, tokenEndpoint);
    }

    /// <summary>
    /// Constructs the IndieAuth challenge url.
    /// </summary>
    /// <param name="properties">The <see cref="AuthenticationProperties"/>.</param>
    /// <param name="redirectUri">The url to redirect to once the challenge is completed.</param>
    /// <returns>The challenge url.</returns>
    protected virtual string BuildChallengeUrl(string authorizeEndpoint, AuthenticationProperties properties, string redirectUri)
    {
        var scopeParameter = properties.GetParameter<ICollection<string>>(IndieAuthChallengeProperties.ScopeKey);
        var scope = scopeParameter != null ? FormatScope(scopeParameter) : FormatScope();

        var parameters = new Dictionary<string, string>
            {
                { "client_id", Options.ClientId },
                { "scope", scope },
                { "response_type", "code" },
                { "redirect_uri", redirectUri },
            };

        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        var codeVerifier = Microsoft.AspNetCore.Authentication.Base64UrlTextEncoder.Encode(bytes);

        // Store this for use during the code redemption.
        properties.Items.Add(IndieAuthConstants.CodeVerifierKey, codeVerifier);

        var challengeBytes = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
        var codeChallenge = WebEncoders.Base64UrlEncode(challengeBytes);

        parameters[IndieAuthConstants.CodeChallengeKey] = codeChallenge;
        parameters[IndieAuthConstants.CodeChallengeMethodKey] = IndieAuthConstants.CodeChallengeMethodS256;

        parameters["state"] = Options.StateDataFormat.Protect(properties);
        parameters["me"] = properties.GetParameter<string>(IndieAuthChallengeProperties.MeKey);

        return QueryHelpers.AddQueryString(authorizeEndpoint, parameters!);
    }

    /// <summary>
    /// Format a list of OAuth scopes.
    /// </summary>
    /// <param name="scopes">List of scopes.</param>
    /// <returns>Formatted scopes.</returns>
    protected virtual string FormatScope(IEnumerable<string> scopes)
        => string.Join(" ", scopes); // OAuth2 3.3 space separated

    /// <summary>
    /// Format the <see cref="OAuthOptions.Scope"/> property.
    /// </summary>
    /// <returns>Formatted scopes.</returns>
    /// <remarks>Subclasses should rather override <see cref="FormatScope(IEnumerable{string})"/>.</remarks>
    protected virtual string FormatScope()
        => FormatScope(Options.Scope);
}