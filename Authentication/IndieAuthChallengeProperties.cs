using IndieAuth.Extensions;
using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IndieAuth.Authentication
{
    public class IndieAuthChallengeProperties : AuthenticationProperties
    {
        /// <summary>
        /// The parameter key for the "scope" argument being used for a challenge request.
        /// </summary>
        public static readonly string ScopeKey = "scope";

        /// <summary>
        /// The parameter key for the "me" argument being used for a challenge request.
        /// </summary>
        public static readonly string MeKey = "me";

        /// <summary>
        /// Initializes a new instance of <see cref="IndieAuthChallengeProperties"/>.
        /// </summary>
        public IndieAuthChallengeProperties()
        { }

        /// <summary>
        /// Initializes a new instance of <see cref="IndieAuthChallengeProperties" />.
        /// </summary>
        /// <inheritdoc />
        public IndieAuthChallengeProperties(IDictionary<string, string?> items)
            : base(items)
        { }

        /// <summary>
        /// Initializes a new instance of <see cref="IndieAuthChallengeProperties" />.
        /// </summary>
        /// <inheritdoc />
        public IndieAuthChallengeProperties(IDictionary<string, string?>? items, IDictionary<string, object?>? parameters)
            : base(items, parameters)
        { }

        /// <summary>
        /// The "scope" parameter value being used for a challenge request.
        /// </summary>
        public ICollection<string> Scope
        {
            get => GetParameter<ICollection<string>>(ScopeKey)!;
            set => SetParameter(ScopeKey, value);
        }

        /// <summary>
        /// Set the "scope" parameter value.
        /// </summary>
        /// <param name="scopes">List of scopes.</param>
        public virtual void SetScope(params string[] scopes)
        {
            Scope = scopes;
        }

        /// <summary>
        /// The "me" parameter value being used for a challenge request.
        /// </summary>
        public string Me
        {
            get
            {
                return GetParameter<string>(MeKey) ?? Items[MeKey];
            }
            set
            {
                SetParameter(MeKey, value.Canonicalize());
                Items.Add(MeKey, value.Canonicalize());
            }
        }

        /// <summary>
        /// Set the "me" parameter value.
        /// </summary>
        /// <param name="me">The site authenticating</param>
        public virtual void SetMe(string me)
        {
            Me = me;
        }
    }
}
