using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Intrinsics.Arm;
using System.Text;
using System.Threading.Tasks;

namespace IndieAuth.Authentication
{
    /// <summary>
    /// Used to setup defaults for the IndieAuthOptions.
    /// </summary>
    public class IndieAuthPostConfigureOptions<TOptions, THandler> : IPostConfigureOptions<TOptions>
    where TOptions : IndieAuthOptions, new()
    where THandler : IndieAuthHandler<TOptions>
    {
        private readonly IDataProtectionProvider _dp;

        /// <summary>
        /// Initializes the <see cref="IndieAuthPostConfigureOptions{TOptions, THandler}"/>.
        /// </summary>
        /// <param name="dataProtection">The <see cref="IDataProtectionProvider"/>.</param>
        public IndieAuthPostConfigureOptions(IDataProtectionProvider dataProtection)
        {
            _dp = dataProtection;
        }

        /// <inheritdoc />
        public void PostConfigure(string name, TOptions options)
        {
            options.DataProtectionProvider = options.DataProtectionProvider ?? _dp;
            if (options.StateDataFormat == null)
            {
                var dataProtector = options.DataProtectionProvider.CreateProtector(
                    typeof(THandler).FullName!, name, "v1");
                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }
        }
    }
}
