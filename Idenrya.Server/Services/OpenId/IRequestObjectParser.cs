namespace Idenrya.Server.Services.OpenId;

public interface IRequestObjectParser
{
    bool TryParseUnsigned(string requestObject, out IReadOnlyDictionary<string, string?> parameters);
}
