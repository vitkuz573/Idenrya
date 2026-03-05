using OpenIddict.Abstractions;

namespace Idenrya.Server.Services.OpenId;

public sealed class AuthorizationRequestParameterMerger(
    IHttpRequestParameterReader parameterReader) : IAuthorizationRequestParameterMerger
{
    public async Task<List<KeyValuePair<string, string?>>> MergeAsync(
        HttpRequest request,
        IReadOnlyDictionary<string, string?> requestObjectParameters,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(requestObjectParameters);

        var excluded = new HashSet<string>(StringComparer.Ordinal)
        {
            OpenIddictConstants.Parameters.Request,
            OpenIddictConstants.Parameters.RequestUri
        };

        var merged = await parameterReader.GetParametersAsync(request, excluded, cancellationToken);

        foreach (var parameter in requestObjectParameters)
        {
            merged.RemoveAll(pair => pair.Key.Equals(parameter.Key, StringComparison.Ordinal));
            merged.Add(new KeyValuePair<string, string?>(parameter.Key, parameter.Value));
        }

        return merged;
    }
}
