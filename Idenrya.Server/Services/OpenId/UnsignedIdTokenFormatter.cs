using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace Idenrya.Server.Services.OpenId;

public static class UnsignedIdTokenFormatter
{
    public static string RewriteTokenWithNoneAlgorithm(string payloadSegment)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(payloadSegment);
        var unsignedHeader = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes("{\"alg\":\"none\",\"typ\":\"JWT\"}"));
        return $"{unsignedHeader}.{payloadSegment}.";
    }
}
