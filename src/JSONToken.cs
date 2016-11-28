using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

using Volte.Data.Json;

namespace Volte.Data.Token
{
    public static class JSONToken
    {
        private static readonly IDictionary<JwtHashAlgorithm, Func<byte[], byte[], byte[]>> HashAlgorithms;
        private static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        static JSONToken()
        {
            HashAlgorithms = new Dictionary<JwtHashAlgorithm, Func<byte[], byte[], byte[]>>
            {
                { JwtHashAlgorithm.HS256, (key, value) => { using (var sha = new HMACSHA256(key)) { return sha.ComputeHash(value); } } },
                { JwtHashAlgorithm.HS384, (key, value) => { using (var sha = new HMACSHA384(key)) { return sha.ComputeHash(value); } } },
                { JwtHashAlgorithm.HS512, (key, value) => { using (var sha = new HMACSHA512(key)) { return sha.ComputeHash(value); } } }
            };
        }

        public static string Encode(JSONObject payload, string key, JwtHashAlgorithm algorithm)
        {
            return Encode(new JSONObject() , payload , Encoding.UTF8.GetBytes(key) , algorithm);
        }

        public static string Encode(JSONObject payload, byte[] key, JwtHashAlgorithm algorithm)
        {
            return Encode(new JSONObject(), payload, key, algorithm);
        }

        public static string Encode(JSONObject extraHeaders , JSONObject payload , string key , JwtHashAlgorithm algorithm)
        {
            return Encode(extraHeaders, payload, Encoding.UTF8.GetBytes(key), algorithm);
        }

        public static string Encode(JSONObject extraHeaders, object payload, byte[] key, JwtHashAlgorithm algorithm)
        {
            var segments = new List<string>();
            JSONObject header = extraHeaders;
            header.SetValue("typ" , "JWT");
            header.SetValue("alg" , algorithm.ToString());

            var headerBytes = Encoding.UTF8.GetBytes(header.ToString());
            var payloadBytes = Encoding.UTF8.GetBytes(payload.ToString());

            segments.Add(Base64UrlEncode(headerBytes));
            segments.Add(Base64UrlEncode(payloadBytes));

            var stringToSign = string.Join(".", segments.ToArray());
            var bytesToSign = Encoding.UTF8.GetBytes(stringToSign);

            var signature = HashAlgorithms[algorithm](key, bytesToSign);
            segments.Add(Base64UrlEncode(signature));

            return string.Join(".", segments.ToArray());
        }

        public static string Decode(string token, string key, bool verify = true)
        {
            return Decode(token, Encoding.UTF8.GetBytes(key), verify);
        }

        public static string Decode(string token, byte[] key, bool verify = true)
        {
            var parts = token.Split('.');
            if (parts.Length != 3)
            {
                throw new ArgumentException("Token must consist from 3 delimited by dot parts");
            }

            var payload = parts[1];
            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));

            if (verify)
            {
                Verify(payload, payloadJson, parts, key);
            }

            return payloadJson;
        }

        public static JSONObject DecodeToObject(string token , byte[] key , bool verify = true)
        {
            var payloadJson = Decode(token, key, verify);
            return new JSONObject(payloadJson);
        }

        public static string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }

        public static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: output += "=="; break; // Two pad chars
                case 3: output += "="; break;  // One pad char
                default: throw new FormatException("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }

        public static void Verify(string payloadJson, string decodedCrypto, string decodedSignature)
        {
            if (decodedCrypto != decodedSignature)
            {
                throw new SignatureVerificationException(string.Format("Invalid signature. Expected {0} got {1}", decodedCrypto, decodedSignature));
            }

            // verify exp claim https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.4
            JSONObject payloadData = new JSONObject(payloadJson);

            int expInt=payloadData.GetInteger("exp");

            var secondsSinceEpoch = Math.Round((DateTime.UtcNow - UnixEpoch).TotalSeconds);
            if (secondsSinceEpoch >= expInt) {
                throw new TokenExpiredException("Token has expired.");
            }
        }

        private static void Verify(string payload, string payloadJson, string[] parts, byte[] key)
        {
            var crypto = Base64UrlDecode(parts[2]);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var header = parts[0];
            var headerJson = Encoding.UTF8.GetString(Base64UrlDecode(header));
            JSONObject headerData = new JSONObject(headerJson);
            var algorithm = headerData.GetValue("alg");

            var bytesToSign = Encoding.UTF8.GetBytes(string.Concat(header, ".", payload));
            var signatureData = HashAlgorithms[GetHashAlgorithm(algorithm)](key, bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            Verify(payloadJson, decodedCrypto, decodedSignature);
        }

        private static JwtHashAlgorithm GetHashAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case "HS256": return JwtHashAlgorithm.HS256;
                case "HS384": return JwtHashAlgorithm.HS384;
                case "HS512": return JwtHashAlgorithm.HS512;
                default: throw new SignatureVerificationException("Algorithm not supported.");
            }
        }
    }
}
