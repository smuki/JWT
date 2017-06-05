using System;
using System.IO;
using System.IO.Compression;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

using Volte.Data.Json;

namespace Volte.Data.Token
{

    public class JSONToken
    {
        const string ZFILE_NAME = "JSONToken";
        private static IDictionary<JwtHashAlgorithm, Func<byte[], byte[], byte[]>> HashAlgorithms;
        private static DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        public string JWTVerify = "";
        public bool bCompress   = false;

        public JSONToken()
        {
            HashAlgorithms = new Dictionary<JwtHashAlgorithm, Func<byte[], byte[], byte[]>>
            {
                { JwtHashAlgorithm.HS256, (key, value) => { using (var sha = new HMACSHA256(key)) { return sha.ComputeHash(value); } } },
                { JwtHashAlgorithm.HS384, (key, value) => { using (var sha = new HMACSHA384(key)) { return sha.ComputeHash(value); } } },
                { JwtHashAlgorithm.HS512, (key, value) => { using (var sha = new HMACSHA512(key)) { return sha.ComputeHash(value); } } }
            };
        }

        public string Encode(JSONObject payload , string key , JwtHashAlgorithm algorithm)
        {
            return Encode(payload , Encoding.UTF8.GetBytes(key) , algorithm);
        }

        private byte[] Compress(byte[] bytes)
        {
            using(MemoryStream ms = new MemoryStream()) {
                DeflateStream Compress = new DeflateStream(ms, CompressionMode.Compress);
                Compress.Write(bytes, 0, bytes.Length);
                Compress.Close();
                return ms.ToArray();

            }
        }

        private byte[] Decompress(byte[] bytes)
        {
            using(MemoryStream tempMs = new MemoryStream()) {
                using(MemoryStream ms = new MemoryStream(bytes)) {
                    DeflateStream Decompress = new DeflateStream(ms, CompressionMode.Decompress);
                    Decompress.CopyTo(tempMs);
                    Decompress.Close();
                    return tempMs.ToArray();
                }
            }

        }

        public string Encode(JSONObject payload , byte[] key , JwtHashAlgorithm algorithm)
        {
            var segments = new List<string>();
            JSONObject header = new JSONObject();
            header.SetValue("typ" , "JWT");
            header.SetValue("alg" , algorithm.ToString());

            var payloadBytes = Encoding.UTF8.GetBytes(payload.ToString());
            if (bCompress){
                header.SetValue("zip" , "DEF");

                payloadBytes = Compress(Encoding.UTF8.GetBytes(payload.ToString()));

            }
            var headerBytes  = Encoding.UTF8.GetBytes(header.ToString());

            segments.Add(Base64UrlEncode(headerBytes));
            segments.Add(Base64UrlEncode(payloadBytes));

            var stringToSign = string.Join(".", segments.ToArray());
            var bytesToSign  = Encoding.UTF8.GetBytes(stringToSign);

            var signature = HashAlgorithms[algorithm](key, bytesToSign);
            segments.Add(Base64UrlEncode(signature));

            return string.Join(".", segments.ToArray());
        }

        public string Decode(string token , string key , bool verify = true)
        {
            return Decode(token, Encoding.UTF8.GetBytes(key), verify);
        }

        public string Decode(string token , byte[] key , bool verify = true)
        {
            var parts = token.Split('.');
            if (parts.Length != 3) {
                JWTVerify="INVALID_TOKENTOKEN";
                //payloadJson = "";
                ZZLogger.Debug(ZFILE_NAME,"Token must consist from 3 delimited by dot parts");
            }

            var headerJson    = Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
            JSONObject header = new JSONObject(headerJson);

            ZZLogger.Debug(ZFILE_NAME,header.ToString());

            var payloadJson ="";
            var payload = parts[1];

            if (header.GetValue("zip")=="DEF"){
                payloadJson = Encoding.UTF8.GetString(Decompress(Base64UrlDecode(payload)));
            }else{
                payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));
            }

            if (verify) {
                if (Verify(payload, payloadJson, parts, key)) {
                    JWTVerify="OK";
                }
            }else{
                JWTVerify="OK";
                ZZLogger.Debug(ZFILE_NAME , "Verify false");
            }

            return payloadJson;
        }

        public string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }

        public byte[] Base64UrlDecode(string input)
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

        public bool Verify(string payloadJson, string decodedCrypto, string decodedSignature)
        {
            if (decodedCrypto != decodedSignature) {
                ZZLogger.Debug(ZFILE_NAME , "Invalid signature. Expected {"+ decodedCrypto+"} got "+ decodedSignature);
                JWTVerify = "INVALID_SIGNATURE";
                return false;
                //throw new SignatureVerificationException(string.Format("Invalid signature. Expected {0} got {1}", decodedCrypto, decodedSignature));
            }

            // verify exp claim https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.4
            JSONObject payloadData = new JSONObject(payloadJson);

            int expInt = payloadData.GetInteger("exp");

            var secondsSinceEpoch = Math.Round((DateTime.UtcNow - UnixEpoch).TotalSeconds);
            if (secondsSinceEpoch >= expInt) {
                ZZLogger.Debug(ZFILE_NAME , "Token has. expired ");
                JWTVerify = "EXPIRED";
                return false;
                //throw new TokenExpiredException("Token has expired.");
            }
            return true;
        }

        private bool Verify(string payload, string payloadJson, string[] parts, byte[] key)
        {
            try {
                var crypto        = Base64UrlDecode(parts[2]);
                var decodedCrypto = Convert.ToBase64String(crypto);

                var header            = parts[0];
                var headerJson        = Encoding.UTF8.GetString(Base64UrlDecode(header));
                JSONObject headerData = new JSONObject(headerJson);
                var algorithm         = headerData.GetValue("alg");

                var bytesToSign      = Encoding.UTF8.GetBytes(string.Concat(header, ".", payload));
                var signatureData    = HashAlgorithms[GetHashAlgorithm(algorithm)](key, bytesToSign);
                var decodedSignature = Convert.ToBase64String(signatureData);

                return Verify(payloadJson, decodedCrypto, decodedSignature);
            } catch (Exception e) {

            }
            return false;
        }

        private JwtHashAlgorithm GetHashAlgorithm(string algorithm)
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
