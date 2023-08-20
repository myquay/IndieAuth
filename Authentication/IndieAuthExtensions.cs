using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IndieAuth.Authentication
{
    /// <summary>
    /// Extension methods to add IndieAuth authentication.
    /// </summary>
    public static class IndieAuthExtensions
    {
        /// <summary>
        /// Adds IndieAuth based authentication to <see cref="AuthenticationBuilder"/> using the specified authentication scheme.
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="configureOptions">A delegate to configure <see cref="IndieAuthOptions"/>.</param>
        /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
        public static AuthenticationBuilder AddIndieAuth(this AuthenticationBuilder builder, string authenticationScheme, Action<IndieAuthOptions> configureOptions)
            => builder.AddIndieAuth<IndieAuthOptions, IndieAuthHandler<IndieAuthOptions>>(authenticationScheme, configureOptions);

        /// <summary>
        /// Adds IndieAuth based authentication to <see cref="AuthenticationBuilder"/> using the specified authentication scheme.
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="displayName">A display name for the authentication handler.</param>
        /// <param name="configureOptions">A delegate to configure <see cref="IndieAuthOptions"/>.</param>
        /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
        public static AuthenticationBuilder AddIndieAuth(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<IndieAuthOptions> configureOptions)
            => builder.AddIndieAuth<IndieAuthOptions, IndieAuthHandler<IndieAuthOptions>>(authenticationScheme, displayName, configureOptions);

        /// <summary>
        /// Adds IndieAuth based authentication to <see cref="AuthenticationBuilder"/> using the specified authentication scheme.
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="configureOptions">A delegate to configure the handler specific options.</param>
        /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
        public static AuthenticationBuilder AddIndieAuth<TOptions, [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] THandler>(this AuthenticationBuilder builder, string authenticationScheme, Action<TOptions> configureOptions)
            where TOptions : IndieAuthOptions, new()
            where THandler : IndieAuthHandler<TOptions>
            => builder.AddIndieAuth<TOptions, THandler>(authenticationScheme, IndieAuthDefaults.DisplayName, configureOptions);

        /// <summary>
        /// Adds IndieAuth based authentication to <see cref="AuthenticationBuilder"/> using the specified authentication scheme.
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="displayName">A display name for the authentication handler.</param>
        /// <param name="configureOptions">A delegate to configure the handler specific options.</param>
        /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
        public static AuthenticationBuilder AddIndieAuth<TOptions, [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] THandler>(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<TOptions> configureOptions)
            where TOptions : IndieAuthOptions, new()
            where THandler : IndieAuthHandler<TOptions>
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<TOptions>, IndieAuthPostConfigureOptions<TOptions, THandler>>());
            return builder.AddScheme<TOptions, THandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
