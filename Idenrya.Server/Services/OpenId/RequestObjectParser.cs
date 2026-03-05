using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

namespace Idenrya.Server.Services.OpenId;

public sealed class RequestObjectParser : IRequestObjectParser
{
    public bool TryParseUnsigned(string requestObject, out IReadOnlyDictionary<string, string?> parameters)
    {
        parameters = new Dictionary<string, string?>(StringComparer.Ordinal);

        var segments = requestObject.Split('.');
        if (segments.Length != 3 || !string.IsNullOrEmpty(segments[2]))
        {
            return false;
        }

        try
        {
            var headerJson = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(segments[0]));
            using var headerDocument = JsonDocument.Parse(headerJson);
            if (!headerDocument.RootElement.TryGetProperty("alg", out var algorithm) ||
                !string.Equals(algorithm.GetString(), "none", StringComparison.Ordinal))
            {
                return false;
            }

            var payloadJson = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(segments[1]));
            using var payloadDocument = JsonDocument.Parse(payloadJson);
            if (payloadDocument.RootElement.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            var values = new Dictionary<string, string?>(StringComparer.Ordinal);
            foreach (var property in payloadDocument.RootElement.EnumerateObject())
            {
                values[property.Name] = property.Value.ValueKind switch
                {
                    JsonValueKind.String => property.Value.GetString(),
                    JsonValueKind.Number => property.Value.GetRawText(),
                    JsonValueKind.True => "true",
                    JsonValueKind.False => "false",
                    JsonValueKind.Array => string.Join(
                        " ",
                        property.Value.EnumerateArray()
                            .Select(item => item.ValueKind == JsonValueKind.String ? item.GetString() : item.GetRawText())
                            .Where(static value => !string.IsNullOrWhiteSpace(value))),
                    JsonValueKind.Null => null,
                    _ => property.Value.GetRawText()
                };
            }

            parameters = values;
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
