using AspNet.Security.IndieAuth.Events;
using AspNet.Security.IndieAuth.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using System.Globalization;

namespace AspNet.Security.IndieAuth;


/// <summary>
/// Configuration options IndieAuth.
/// </summary>
public class IndieAuthOptions : RemoteAuthenticationOptions
{
    /// <summary>
    /// Initializes a new instance of <see cref="IndieAuthOptions"/>.
    /// </summary>
    public IndieAuthOptions()
    {
        Events = new IndieAuthEvents();
    }

    /// <summary>
    /// Check that the options are valid. Should throw an exception if things are not ok.
    /// </summary>
    public override void Validate()
    {
        base.Validate();

        if (string.IsNullOrEmpty(ClientId))
            throw new ArgumentException("Client Id must be a well formed URI string", nameof(ClientId));

        if (!Uri.IsWellFormedUriString(ClientId, UriKind.Absolute))
            throw new ArgumentException("Client Id must be a well formed URI string", nameof(ClientId));

        if (!CallbackPath.HasValue)
            throw new ArgumentException("A callback path must be provided", nameof(CallbackPath));
    }

    /// <summary>
    /// Gets or sets the client id
    /// </summary>
    public string ClientId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the <see cref="IndieAuthEvents"/> used to handle authentication events.
    /// </summary>
    public new IndieAuthEvents Events
    {
        get { return (IndieAuthEvents)base.Events; }
        set { base.Events = value; }
    }

    /// <summary>
    /// A collection of claim actions used to select values from the json user data and create Claims.
    /// </summary>
    public ClaimActionCollection ClaimActions { get; } = new ClaimActionCollection();

    /// <summary>
    /// Gets the list of permissions to request.
    /// </summary>
    public ICollection<string> Scope { get; } = new HashSet<string>();

    /// <summary>
    /// Gets or sets the type used to secure data handled by the middleware.
    /// </summary>
    public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; } = default!;

}