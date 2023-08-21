namespace AspNet.Security.IndieAuth.Infrastructure;

public class AuthenticationFailureException : Exception
{
    public AuthenticationFailureException(string? message) : base(message) { }

    public AuthenticationFailureException(string? message, Exception? innerException) : base(message, innerException) { }
}