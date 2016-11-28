using System;

namespace Volte.Data.Token
{
    public class TokenExpiredException : Exception
    {
        public TokenExpiredException(string message)
            : base(message)
        {
        }
    }
}
