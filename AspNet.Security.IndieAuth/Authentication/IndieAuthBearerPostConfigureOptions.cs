using Microsoft.Extensions.Options;

namespace AspNet.Security.IndieAuth;

/// <summary>
/// Post-configure options for <see cref="IndieAuthBearerOptions"/>.
/// </summary>
public class IndieAuthBearerPostConfigureOptions : IPostConfigureOptions<IndieAuthBearerOptions>
{
    /// <inheritdoc />
    public void PostConfigure(string? name, IndieAuthBearerOptions options)
    {
        if (options.Backchannel == null)
        {
            options.Backchannel = new HttpClient(options.BackchannelHttpHandler ?? new HttpClientHandler())
            {
                Timeout = options.BackchannelTimeout
            };
        }
    }
}
