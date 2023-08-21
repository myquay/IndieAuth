using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IndieAuth.Authentication
{
    internal static class HandleRequestResults
    {
        internal static HandleRequestResult InvalidState = HandleRequestResult.Fail("The indieauth state was missing or invalid.");
    }
}
