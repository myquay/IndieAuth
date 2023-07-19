using IndieAuth.Authentication.Responses;
using IndieAuth.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;

namespace IndieAuth.Authentication
{
    //TODO: COMPLETE
    public class IndieAuthHandler<TOptions> : RemoteAuthenticationHandler<TOptions> where TOptions : IndieAuthOptions, new()
    {
        public IndieAuthHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }

        public async override Task<bool> ShouldHandleRequestAsync()
        {
            if (base.Options.EnableMetadataEndpoint && base.Options.MetadataEndpoint == base.Request.Path)
            {
                return true;
            }
            else
            {
                return await base.ShouldHandleRequestAsync();
            }
        }

        public async override Task<bool> HandleRequestAsync()
        {
            if (!await ShouldHandleRequestAsync())
            {
                return false;
            }
            else if (base.Options.EnableMetadataEndpoint && base.Options.MetadataEndpoint == base.Request.Path)
            {
                return await WriteIndieAuthServerMetatdata();
            }
            else
            {
                return await base.HandleRequestAsync();
            }
        }

        /// <summary>
        /// Write out IndieAuth server metatdata to the response stream
        /// </summary>
        /// <returns></returns>
        private async Task<bool> WriteIndieAuthServerMetatdata()
        {
            Response.StatusCode = (int)HttpStatusCode.OK;
            await Response.WriteAsync(JsonSerializer.Serialize(new IndieAuthServerMetadataResponse
            {
                AuthorizationEndpoint = base.Options.AuthorizationEndpoint,
                IntrospectionEndpoint = base.Options.IntrospectionEndpoint,
                Issuer = base.Options.Issuer,
                ScopesSupported = base.Options.Scopes,
                RevocationEndpoint = base.Options.RevocationEndpoint,
                TokenEndpoint = base.Options.TokenEndpoint,
                UserinfoEndpoint = base.Options.UserinfoEndpoint
            }, new JsonSerializerOptions
            {
                PropertyNamingPolicy = new SnakeCaseNamingPolicy(),
                AllowTrailingCommas = false
            }));

            return true;
        }

        protected override Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            if (base.Options.MetadataEndpoint == base.Request.Path)
            {
                throw new NotImplementedException();
            }
            else
            {
                throw new NotImplementedException();
            }
        }
    }
}
