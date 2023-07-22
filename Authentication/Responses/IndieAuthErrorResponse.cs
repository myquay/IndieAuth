using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IndieAuth.Authentication.Responses
{
    /// <summary>
    /// Error response
    /// </summary>
    public class IndieAuthErrorResponse
    {
        /// <summary>
        /// Error
        /// </summary>
        public string Error { get; set; } = default!;

        /// <summary>
        /// Description
        /// </summary>
        public string? ErrorDescription { get; set; }
    }

    /// <summary>
    /// Error type
    /// </summary>
    public static class IndieAuthError
    {
        public const string INVALID_REQUEST = "invalid_request";
        public const string UNAUTHORIZED_CLIENT = "unauthorized_client";
        public const string ACCESS_DENIED = "access_denied";
        public const string UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
        public const string INVALID_SCOPE = "invalid_scope";
        public const string SERVER_ERROR = "server_error";
        public const string TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";
    }
}
