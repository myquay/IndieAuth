﻿namespace AspNet.Security.IndieAuth.Infrastructure;

/// <summary>
/// Constants used in the IndieAuth protocol
/// </summary>
public static class IndieAuthConstants
{
    /// <summary>
    /// code_verifier defined in <see href="https://tools.ietf.org/html/rfc7636"/>.
    /// </summary>
    public static readonly string CodeVerifierKey = "code_verifier";

    /// <summary>
    /// code_challenge defined in <see href="https://tools.ietf.org/html/rfc7636"/>.
    /// </summary>
    public static readonly string CodeChallengeKey = "code_challenge";

    /// <summary>
    /// code_challenge_method defined in <see href="https://tools.ietf.org/html/rfc7636"/>.
    /// </summary>
    public static readonly string CodeChallengeMethodKey = "code_challenge_method";

    /// <summary>
    /// S256 defined in <see href="https://tools.ietf.org/html/rfc7636"/>.
    /// </summary>
    public static readonly string CodeChallengeMethodS256 = "S256";

    /// <summary>
    /// Key for storing discovery result in authentication properties.
    /// Used for Authorization Server Confirmation (Section 5.4).
    /// </summary>
    public static readonly string DiscoveryResultKey = ".discovery_result";

    /// <summary>
    /// Key for storing the token endpoint URL in authentication properties.
    /// Used for Token Refresh (Section 5.5).
    /// </summary>
    public static readonly string TokenEndpointKey = ".token_endpoint";

    /// <summary>
    /// Key for storing the issuer in authentication properties.
    /// Used for Issuer Validation (RFC 9207).
    /// </summary>
    public static readonly string IssuerKey = ".issuer";

    /// <summary>
    /// Key for storing the granted scopes in authentication properties.
    /// Used for Token Refresh scope validation.
    /// </summary>
    public static readonly string ScopesKey = ".scopes";
}