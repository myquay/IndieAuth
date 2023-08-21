using Microsoft.AspNetCore.Authentication;

namespace AspNet.Security.IndieAuth;
internal static class HandleRequestResults
{
    internal static HandleRequestResult InvalidState = HandleRequestResult.Fail("The IndieAuth state was missing or invalid.");
}