using Microsoft.AspNetCore.Authentication;

namespace AspNet.Security.IndieAuth.Events;

/// <summary>
/// Default implementation.
/// </summary>
public class IndieAuthEvents : RemoteAuthenticationEvents
{
    /// <summary>
    /// Gets or sets the function that is invoked when the CreatingTicket method is invoked.
    /// </summary>
    public Func<IndieAuthCreatingTicketContext, Task> OnCreatingTicket { get; set; } = context => Task.CompletedTask;

    /// <summary>
    /// Gets or sets the delegate that is invoked when the RedirectToAuthorizationEndpoint method is invoked.
    /// </summary>
    public Func<RedirectContext<IndieAuthOptions>, Task> OnRedirectToAuthorizationEndpoint { get; set; } = context =>
    {
        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
    };

    /// <summary>
    /// Invoked after the provider successfully authenticates a user.
    /// </summary>
    /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
    /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
    public virtual Task CreatingTicket(IndieAuthCreatingTicketContext context) => OnCreatingTicket(context);

    /// <summary>
    /// Called when a Challenge causes a redirect to authorize endpoint in the IndieAuth handler.
    /// </summary>
    /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge.</param>
    public virtual Task RedirectToAuthorizationEndpoint(RedirectContext<IndieAuthOptions> context) => OnRedirectToAuthorizationEndpoint(context);
}