# IndieAuth .NET
An ASP.NET Core 6 authentication handler adding support for authenticating visitors using the [IndieAuth protocol](https://indieauth.spec.indieweb.org/).

## Installation
This library is distributed as a NuGet package. To install with the .NET CLI run `dotnet add package AspNet.Security.IndieAuth --version {version number}`

## Usage
This is configured at startup just like any other authentication handler by calling `AddIndieAuth` on the result of `AddAuthentication`.

```csharp
var authBuilder = builder.Services.AddAuthentication()
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
                {
                    options.LoginPath = "/account/sign-in";
                })
                .AddIndieAuth(IndieAuthDefaults.AuthenticationScheme, options =>
                {
                    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.ClientId = config.IndieAuth.ClientId;
                    options.CallbackPath = "/authentication/indie-auth/callback";
                });
```

To trigger the authentication flow, issue an authentication challenge with the supplied domain the visitor is authenticating with.

```csharp
return Challenge(new IndieAuthChallengeProperties
{
    Me = domain,
    Scope = new[] { "profile", "create" },
    RedirectUri = ReturnUrl
}, IndieAuthDefaults.AuthenticationScheme);
```
That's it, if the authentication is successful the user will be signed in.

## Usage notes

Additional information on the configurable parameters

### Configuring Indie Auth

* `ClientId` should be a URI where the IndieAuth server can fetch details about the website _(using the hCard Microformat)_.
* `CallbackPath` is where the authentication middleware will intercept the response from the IndieAuth server
* `SignInScheme` is the scheme used to persist the visitor's session - normally a cookie authentication handler

### Configuring the challenge

* `Me` is the domain the visitor is authenticating with, the handler will fetch this domain to discover which IndieAuth server to authenticate with
* `Scope` is an array of scopes to use
* `RedirectUri` is where the visitor should be redirected to after the challenge is completed

## Roadmap

- [ ] Option to add additional claims from supplied domain hCard Microformat

## Contributing

Contributions are very welcome!

### Ways to contribute

* Fix an existing issue and submit a pull request
* Review open pull requests
* Report a new issue
* Make a suggestion/ contribute to a discussion

## Acknowledgments

The project is based on the [OAuth handler](https://github.com/dotnet/aspnetcore/tree/main/src/Security/Authentication/OAuth/src) in the [aspnetcore repository](https://github.com/dotnet/aspnetcore).

## License

MIT

