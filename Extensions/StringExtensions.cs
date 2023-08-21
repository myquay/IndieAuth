using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IndieAuth.Extensions
{
    public static class StringExtensions
    {
        public static string Canonicalize(this string uri)
        {
            if(string.IsNullOrEmpty(uri))
                return uri;

            var uriBuilder = new UriBuilder(uri.ToLower());

            if(string.IsNullOrEmpty(uriBuilder.Path))
                uriBuilder.Path = "/";

            if (string.IsNullOrEmpty(uriBuilder.Scheme) || (!uri.StartsWith("http://") && uriBuilder.Scheme == "http"))
            {
                uriBuilder.Scheme = "https";
                if (uriBuilder.Port == 80)
                    uriBuilder.Port = 443;
            }

            return uriBuilder.Uri.ToString();
        }
    }
}
