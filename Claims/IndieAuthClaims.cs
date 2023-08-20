using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Policy;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace IndieAuth.Claims
{
    public class IndieAuthClaims
    {
        /// <summary>
        /// The "me" claim for IndieAuth authentication.
        /// </summary>
        public const string ME = "urn:indieauth:me";

        /// <summary>
        /// Add the "me" claim to the claims principal
        /// </summary>
        public static Func<TicketReceivedContext, Task> OnGitHubTicketReceived = async (context) =>
        {
            var gitHubVerificationUri = context.Principal.Claims.FirstOrDefault(u => u.Type == "urn:github:url")?.Value;

            if(gitHubVerificationUri != null)
            {
                var client = context.HttpContext.RequestServices.GetService<HttpClient>() ?? new HttpClient();
                if(!client.DefaultRequestHeaders.Any(client => client.Key == "User-Agent"))
                    client.DefaultRequestHeaders.Add("User-Agent", "IndieAuth.NET/1.0");

                var gitHubUser = await client.GetFromJsonAsync<GitHubUser>(gitHubVerificationUri, new JsonSerializerOptions{
                     PropertyNameCaseInsensitive = true
                });

                if (!string.IsNullOrEmpty($"{gitHubUser?.blog}")) {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity(context.Principal.Claims.Union(new[] { new Claim(IndieAuthClaims.ME, gitHubUser?.blog) }), context.Principal.Identity?.AuthenticationType));
                }
            }
        };
    }

    class GitHubUser
    {
        public string blog { get; set; }
    }
}
