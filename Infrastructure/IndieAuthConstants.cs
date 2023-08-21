using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IndieAuth.Infrastructure
{
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
    }
}
