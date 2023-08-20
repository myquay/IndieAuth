using IndieAuth.Authentication;
using Microformats;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace IndieAuth.Discovery
{
    /// <summary>
    /// Discovery client for rel=me
    /// </summary>
    public class RelMeAuthDiscoveryClient
    {
        private readonly HttpClient _httpClient;

        public RelMeAuthDiscoveryClient(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        /// <summary>
        /// Discover supported authentication methods for a given URL
        /// </summary>
        /// <param name="me"></param>
        /// <returns></returns>
        public async Task<string[]> DiscoverSupportedAuthenticationMethods(string me) => await DiscoverSupportedAuthenticationMethods(me, CancellationToken.None);

        /// <summary>
        /// Discover supported authentication methods for a given URL
        /// </summary>
        /// <param name="me"></param>
        /// <returns></returns>
        public async Task<string[]> DiscoverSupportedAuthenticationMethods(string me, CancellationToken cancellationToken)
        {
            if (!Uri.IsWellFormedUriString(me, UriKind.Absolute))
                throw new ArgumentException("Invalid URL", nameof(me));

            if (!Uri.TryCreate(me, UriKind.Absolute, out var uri))
                throw new ArgumentException("Invalid URL", nameof(me));

            var html = await _httpClient.GetStringAsync(uri, cancellationToken);

            var result = new Mf2().Parse(html);

            if(!result.Rels.ContainsKey("me"))
                return Array.Empty<string>();

            var possibleMeUrls = result.Rels["me"].ToArray();

            if (result.Rels.ContainsKey("authn"))
                possibleMeUrls = possibleMeUrls.Intersect(result.Rels["authn"]).ToArray();

            return possibleMeUrls
                .Select(x => IndieAuthMethod.AllSupported.Where(a => Regex.IsMatch(x,IndieAuthProviderRegex.GetForProvider(a))).FirstOrDefault())
                .Where(x => x != null)
                .Select(x => x!.ToString())
                .ToArray();
        }

    }
}
