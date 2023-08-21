using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace IndieAuth.Infrastructure
{
    public class IndieAuthClaims
    {
        /// <summary>
        /// The "me" claim for IndieAuth authentication.
        /// </summary>
        public const string ME = "urn:indieauth:me";
    }
}
