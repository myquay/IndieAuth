using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
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
            if (base.Options.MetadataEndpoint == base.Request.Path)
            {
                return true;
            }
            else
            {
                return await base.ShouldHandleRequestAsync();
            }
        }

        protected override Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            if (base.Options.MetadataEndpoint == base.Request.Path)
            {
                throw new NotImplementedException(); //Return metadata
            }
            else
            {
                throw new NotImplementedException();
            }
        }
    }
}
