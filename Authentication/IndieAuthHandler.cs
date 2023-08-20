using IndieAuth.Authentication.Responses;
using IndieAuth.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

namespace IndieAuth.Authentication
{
    public class IndieAuthHandler<TOptions> : AuthenticationHandler<TOptions>, IAuthenticationRequestHandler where TOptions : IndieAuthOptions, new()
    {
        public IndieAuthHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }

        public async Task<bool> ShouldHandleRequestAsync()
        {
            if ((base.Options.EnableMetadataEndpoint && base.Options.MetadataEndpoint == base.Request.Path) ||
                (base.Options.AuthorizationEndpoint == base.Request.Path))
            {
                return true;
            }

            return false;
        }

        public async Task<bool> HandleRequestAsync()
        {
            if (!await ShouldHandleRequestAsync())
            {
                return false;
            }
            else if (base.Options.EnableMetadataEndpoint && base.Options.MetadataEndpoint == base.Request.Path)
            {
                return await WriteIndieAuthServerMetatdata();
            }
            else if (base.Options.AuthorizationEndpoint == base.Request.Path)
            {
                return await HandleIndieAuthServerAuthorization();
            }
            
            return true;
        }

        /// <summary>
        /// Handle the request to the authorize endpoint
        /// </summary>
        /// <returns>Return true to stop request processing</returns>
        private async Task<bool> HandleIndieAuthServerAuthorization()
        {
            var authResult = await base.Context.AuthenticateAsync(base.Options.ExternalSignInScheme);
            Response.StatusCode = (int)HttpStatusCode.OK;

            var queryParameters = base.Request.Query.ToDictionary(x => x.Key, x => x.Value.ToString());

            if (!await ValidateAuthorizationRequest(queryParameters))
                return true;

            if (authResult.Succeeded)
            {
                if (!authResult.VerifyWebsite(queryParameters["me"]))
                {
                    var message = $"The user is not signed in with the correct website. Expected: '{queryParameters["me"]?.Trim('/')}', Actual: '{authResult.GetSuppliedWebsiteParameter()}'";
                    //await Events.(new RemoteFailureContext(Context, Scheme, base.Options, new Exception(message)));

                    queryParameters["redirect_uri"] = QueryHelpers.AddQueryString(queryParameters["redirect_uri"], "error", "access_denied");
                    queryParameters["redirect_uri"] = QueryHelpers.AddQueryString(queryParameters["redirect_uri"], "error_description", message);
                    queryParameters["redirect_uri"] = QueryHelpers.AddQueryString(queryParameters["redirect_uri"], "state", queryParameters["state"]);

                    Response.Redirect(queryParameters["redirect_uri"]);
                    return true;
                }
                else
                {
                    //TODO: GENERATE AUTHORIZATION CODE AND RETURN
                    await Response.WriteAsync("LOGGED IN EXTERNALLY - PROCESSING AUTHORIZE ENDPOINT");
                    return true;
                }
            }
            else
            {
                await Context.ChallengeAsync(base.Options.ExternalSignInScheme, new AuthenticationProperties(new Dictionary<string, string>
                {
                    { "me", queryParameters["me"]}
                })
                {
                    RedirectUri = Context.Request.GetEncodedUrl(),
                });

                return true;
            }
        }

        /// <summary>
        /// Handle the request to the authorize endpoint
        /// </summary>
        /// <returns></returns>
        private async Task<bool> ValidateAuthorizationRequest(Dictionary<string, string> queryParameters)
        {
            if (!queryParameters.ContainsKey("redirect_uri") || !Uri.TryCreate(queryParameters["redirect_uri"], UriKind.Absolute, out Uri? redirectUriOutput))
            {
                await Response.WriteAsync(JsonSerializer.Serialize(new IndieAuthErrorResponse
                {
                    Error = IndieAuthError.INVALID_REQUEST,
                    ErrorDescription = "The redirect_uri parameter is required. See: https://indieauth.spec.indieweb.org/#authorization-request"
                }, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = new SnakeCaseNamingPolicy()
                }));
                return false;
            }

            var redirect = new UriBuilder(queryParameters["redirect_uri"]);
            var query = HttpUtility.ParseQueryString(redirect.Query);

            var metadata = GetIndieAuthMetadata();

            #region Validate response_type

            if (!queryParameters.ContainsKey("response_type"))
            {
                query.Add("error", IndieAuthError.INVALID_REQUEST);
                query.Add("description", Uri.EscapeDataString("The response_type parameter is required. See: https://indieauth.spec.indieweb.org/#authorization-request"));

                redirect.Query = query.ToString();
                Response.Redirect(redirect.ToString());
                return false;
            }
            else if (!metadata.ResponseTypesSupported.Contains(queryParameters["response_type"]))
            {
                query.Add("error", IndieAuthError.UNSUPPORTED_RESPONSE_TYPE);
                query.Add("description", Uri.EscapeDataString($"The response_type supplied is not supported, currently supported types: {String.Join(", ", metadata.ResponseTypesSupported)}"));

                redirect.Query = query.ToString();
                Response.Redirect(redirect.ToString());
                return false;
            }

            #endregion

            #region Validate client_id

            if (!queryParameters.ContainsKey("client_id"))
            {
                query.Add("error", IndieAuthError.INVALID_REQUEST);
                query.Add("description", Uri.EscapeDataString("The client_id parameter is required. See: https://indieauth.spec.indieweb.org/#authorization-request"));

                redirect.Query = query.ToString();
                Response.Redirect(redirect.ToString());
                return false;
            }
            else if (!Uri.TryCreate(queryParameters["client_id"], UriKind.Absolute, out Uri? clientId))
            {
                query.Add("error", IndieAuthError.INVALID_REQUEST);
                query.Add("description", Uri.EscapeDataString("The client_id parameter must be a wellformed URI string. See: https://indieauth.spec.indieweb.org/#client-identifier"));

                redirect.Query = query.ToString();
                Response.Redirect(redirect.ToString());
                return false;
            }
            else if (!new[] { "http", "https" }.Contains(clientId.Scheme))
            {
                query.Add("error", IndieAuthError.INVALID_REQUEST);
                query.Add("description", Uri.EscapeDataString("The client_id scheme must be http or https. See: https://indieauth.spec.indieweb.org/#client-identifier"));

                redirect.Query = query.ToString();
                Response.Redirect(redirect.ToString());
                return false;
            }
            else if (string.IsNullOrWhiteSpace(clientId.GetLeftPart(UriPartial.Path)))
            {
                query.Add("error", IndieAuthError.INVALID_REQUEST);
                query.Add("description", Uri.EscapeDataString("The client_id path must not be empty, specify the path '/' at a minimum. See: https://indieauth.spec.indieweb.org/#client-identifier"));

                redirect.Query = query.ToString();
                Response.Redirect(redirect.ToString());
                return false;
            }
            else if (clientId.GetLeftPart(UriPartial.Path).Contains("../") || clientId.GetLeftPart(UriPartial.Path).Contains("./"))
            {
                query.Add("error", IndieAuthError.INVALID_REQUEST);
                query.Add("description", Uri.EscapeDataString("The client_id path must not contain single-dot or double-dot path segments. See: https://indieauth.spec.indieweb.org/#client-identifier"));

                redirect.Query = query.ToString();
                Response.Redirect(redirect.ToString());
                return false;
            }
            else if (!string.IsNullOrEmpty(clientId.Fragment))
            {
                query.Add("error", IndieAuthError.INVALID_REQUEST);
                query.Add("description", Uri.EscapeDataString("The client_id path must not contain a fragment component. See: https://indieauth.spec.indieweb.org/#client-identifier"));

                redirect.Query = query.ToString();
                Response.Redirect(redirect.ToString());
                return false;
            }
            else if (IPAddress.TryParse(clientId.Host, out IPAddress? address) && address.ToString() != "27.0.0.1" && address.ToString() != "[::1]")
            {
                query.Add("error", IndieAuthError.INVALID_REQUEST);
                query.Add("description", Uri.EscapeDataString("The client_id path must contain a host name or loopback interface. See: https://indieauth.spec.indieweb.org/#client-identifier"));

                redirect.Query = query.ToString();
                Response.Redirect(redirect.ToString());
                return false;
            }
            else if (base.Options.RequireHttps && clientId.Scheme != "https")
            {
                query.Add("error", IndieAuthError.INVALID_REQUEST);
                query.Add("description", Uri.EscapeDataString("This service only supported the HTTPS scheme for client_id URIs for enhanced security."));

                redirect.Query = query.ToString();
                Response.Redirect(redirect.ToString());
                return false;
            }

            #endregion

            #region Validate redirect_uri

            if (!queryParameters.ContainsKey("redirect_uri"))
            {
                query.Add("error", IndieAuthError.INVALID_REQUEST);
                query.Add("description", Uri.EscapeDataString("The redirect_uri parameter is required. See: https://indieauth.spec.indieweb.org/#authorization-request"));

                redirect.Query = query.ToString();
                Response.Redirect(redirect.ToString());
                return false;
            }
            else if (!Uri.TryCreate(queryParameters["redirect_uri"], UriKind.Absolute, out Uri? redirectUri))
            {
                query.Add("error", IndieAuthError.INVALID_REQUEST);
                query.Add("description", Uri.EscapeDataString("The redirect_uri parameter must be a wellformed URI string."));

                redirect.Query = query.ToString();
                Response.Redirect(redirect.ToString());
                return false;
            }
            else if (base.Options.RequireHttps && redirectUri.Scheme != "https")
            {
                query.Add("error", IndieAuthError.INVALID_REQUEST);
                query.Add("description", Uri.EscapeDataString("This service only supported the HTTPS scheme for redirect URIs for enhanced security."));

                redirect.Query = query.ToString();
                Response.Redirect(redirect.ToString());
                return false;
            }
            else if (!Uri.TryCreate(queryParameters["client_id"], UriKind.Absolute, out Uri? clientId) ||
                redirectUri.Scheme != clientId.Scheme ||
                redirectUri.Host != clientId.Host ||
                redirectUri.Port != clientId.Port)
            {
                //TODO: FETCH CLIENTID AND PROCESS FOR REDIRECT URIS
            }

            #endregion

            #region Validate state parameter

            if (!queryParameters.ContainsKey("state"))
            {
                query.Add("error", IndieAuthError.INVALID_REQUEST);
                query.Add("description", Uri.EscapeDataString("The state parameter is required. See: https://indieauth.spec.indieweb.org/#authorization-request"));

                redirect.Query = query.ToString();
                Response.Redirect(redirect.ToString());
                return false;
            }

            #endregion

            #region Validate code challenge

            if (!queryParameters.ContainsKey("code_challenge"))
            {
                query.Add("error", IndieAuthError.INVALID_REQUEST);
                query.Add("description", Uri.EscapeDataString("The code_challenge parameter is required. See: https://indieauth.spec.indieweb.org/#authorization-request"));

                redirect.Query = query.ToString();
                Response.Redirect(redirect.ToString());
                return false;
            }

            if (!queryParameters.ContainsKey("code_challenge_method"))
            {
                query.Add("error", IndieAuthError.INVALID_REQUEST);
                query.Add("description", Uri.EscapeDataString("The code_challenge_method parameter is required. See: https://indieauth.spec.indieweb.org/#authorization-request"));

                redirect.Query = query.ToString();
                Response.Redirect(redirect.ToString());
                return false;
            }
            else if (!metadata.CodeChallengeMethodsSupported.Contains(queryParameters["code_challenge_method"]))
            {
                query.Add("error", IndieAuthError.INVALID_REQUEST);
                query.Add("description", Uri.EscapeDataString($"The code_challenge_method supplied is not supported, currently supported methods: {String.Join(", ", metadata.CodeChallengeMethodsSupported)}"));

                redirect.Query = query.ToString();
                Response.Redirect(redirect.ToString());
                return false;
            }

            #endregion

            #region Validate scope

            if (queryParameters.ContainsKey("scope") && !queryParameters["scope"].Split(' ').All(s => metadata.ScopesSupported.Contains(s)))
            {
                query.Add("error", IndieAuthError.INVALID_SCOPE);
                query.Add("description", Uri.EscapeDataString($"The scope supplied is not supported, currently supported scopes: {String.Join(", ", metadata.ScopesSupported)}"));

                redirect.Query = query.ToString();
                Response.Redirect(redirect.ToString());
                return false;
            }

            #endregion

            #region Validate me


            #region Validate redirect_uri

            if (queryParameters.ContainsKey("me"))
            {
                if (!Uri.TryCreate(queryParameters["redirect_uri"], UriKind.Absolute, out Uri? redirectUri))
                {
                    query.Add("error", IndieAuthError.INVALID_REQUEST);
                    query.Add("description", Uri.EscapeDataString("The me parameter must be a wellformed URI string."));

                    redirect.Query = query.ToString();
                    Response.Redirect(redirect.ToString());
                    return false;
                }
                else if (base.Options.RequireHttps && redirectUri.Scheme != "https")
                {
                    query.Add("error", IndieAuthError.INVALID_REQUEST);
                    query.Add("description", Uri.EscapeDataString("This service only supported the HTTPS scheme for me URIs for enhanced security."));

                    redirect.Query = query.ToString();
                    Response.Redirect(redirect.ToString());
                    return false;
                }
            }

            #endregion


            #endregion

            return await Task.FromResult(true);

        }

        /// <summary>
        /// Get the metadata for the auth handler
        /// </summary>
        /// <returns></returns>
        private IndieAuthServerMetadataResponse GetIndieAuthMetadata()
        {
            return new IndieAuthServerMetadataResponse
            {
                AuthorizationEndpoint = $"{base.Options.Issuer}{base.Options.AuthorizationEndpoint}",
                IntrospectionEndpoint = $"{base.Options.Issuer}{base.Options.IntrospectionEndpoint}",
                Issuer = base.Options.Issuer,
                ScopesSupported = base.Options.Scopes,
                RevocationEndpoint = base.Options.RevocationEndpoint != null ? $"{base.Options.Issuer}{base.Options.RevocationEndpoint}" : null,
                TokenEndpoint = $"{base.Options.Issuer}{base.Options.TokenEndpoint}",
                UserinfoEndpoint = base.Options.UserinfoEndpoint != null ? $"{base.Options.Issuer}{base.Options.UserinfoEndpoint}" : null
            };
        }

        /// <summary>
        /// Write out IndieAuth server metatdata to the response stream
        /// </summary>
        /// <returns></returns>
        private async Task<bool> WriteIndieAuthServerMetatdata()
        {
            Response.StatusCode = (int)HttpStatusCode.OK;
            await Response.WriteAsync(JsonSerializer.Serialize(GetIndieAuthMetadata(), new JsonSerializerOptions
            {
                PropertyNamingPolicy = new SnakeCaseNamingPolicy(),
                AllowTrailingCommas = false
            }));

            return true;
        }

        /// <summary>
        /// Handle a request secured with an IndieAuth token
        /// </summary>
        /// <returns></returns>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            //TODO: AUTHENTICATE BASED ON THE SUPPLIED BEARER TOKEN
            return AuthenticateResult.Fail("Not signed in");
        }
    }
}
