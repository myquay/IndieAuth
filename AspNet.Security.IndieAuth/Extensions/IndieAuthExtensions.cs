﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System.Diagnostics.CodeAnalysis;

namespace AspNet.Security.IndieAuth;

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
        return builder.AddRemoteScheme<TOptions, THandler>(authenticationScheme, displayName, configureOptions);
    }

    #region IndieAuth Bearer Token Authentication

    /// <summary>
    /// Adds IndieAuth bearer token authentication using the default scheme.
    /// Use this to protect API endpoints with IndieAuth access tokens.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="IndieAuthBearerOptions"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddIndieAuthBearer(this AuthenticationBuilder builder, Action<IndieAuthBearerOptions> configureOptions)
        => builder.AddIndieAuthBearer(IndieAuthBearerDefaults.AuthenticationScheme, configureOptions);

    /// <summary>
    /// Adds IndieAuth bearer token authentication using the specified scheme.
    /// Use this to protect API endpoints with IndieAuth access tokens.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="IndieAuthBearerOptions"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddIndieAuthBearer(this AuthenticationBuilder builder, string authenticationScheme, Action<IndieAuthBearerOptions> configureOptions)
        => builder.AddIndieAuthBearer(authenticationScheme, IndieAuthBearerDefaults.DisplayName, configureOptions);

    /// <summary>
    /// Adds IndieAuth bearer token authentication using the specified scheme and display name.
    /// Use this to protect API endpoints with IndieAuth access tokens.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="displayName">A display name for the authentication handler.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="IndieAuthBearerOptions"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddIndieAuthBearer(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<IndieAuthBearerOptions> configureOptions)
    {
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<IndieAuthBearerOptions>, IndieAuthBearerPostConfigureOptions>());
        return builder.AddScheme<IndieAuthBearerOptions, IndieAuthBearerHandler>(authenticationScheme, displayName, configureOptions);
    }

    #endregion
}