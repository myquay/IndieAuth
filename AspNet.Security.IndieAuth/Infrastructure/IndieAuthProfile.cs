namespace AspNet.Security.IndieAuth;

/// <summary>
/// Represents user profile information returned from IndieAuth token/authorization endpoint.
/// Per IndieAuth spec Section 5.3.4, this data is informational only and MUST NOT be used
/// for authentication or identification decisions.
/// </summary>
/// <param name="Name">Name the user wishes to provide. Not guaranteed to be their full name.</param>
/// <param name="Url">URL of the user's website. May differ from the 'me' URL.</param>
/// <param name="Photo">A photo or image URL for use as a profile image.</param>
/// <param name="Email">Email address (only present if 'email' scope was requested).</param>
public record IndieAuthProfile(
    string? Name = null,
    string? Url = null,
    string? Photo = null,
    string? Email = null)
{
    /// <summary>
    /// Returns true if any profile field has a value.
    /// </summary>
    public bool HasData => Name != null || Url != null || Photo != null || Email != null;
}
