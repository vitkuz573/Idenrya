using Microsoft.Extensions.Primitives;

namespace Idenrya.Server.Services.OpenId;

public sealed class HttpRequestParameterReader : IHttpRequestParameterReader
{
    public async Task<string?> GetParameterAsync(HttpRequest request, string name, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var queryValue = request.Query[name].ToString();
        if (!string.IsNullOrWhiteSpace(queryValue))
        {
            return queryValue;
        }

        if (!request.HasFormContentType)
        {
            return null;
        }

        var form = await request.ReadFormAsync(cancellationToken);
        var formValue = form[name].ToString();
        return string.IsNullOrWhiteSpace(formValue) ? null : formValue;
    }

    public async Task<List<KeyValuePair<string, string?>>> GetParametersAsync(
        HttpRequest request,
        ISet<string> excludedParameters,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(excludedParameters);

        var excluded = excludedParameters.Count > 0
            ? new HashSet<string>(excludedParameters, StringComparer.Ordinal)
            : null;

        var parameters = new List<KeyValuePair<string, string?>>();

        AddParameters(parameters, request.Query, excluded);

        if (request.HasFormContentType)
        {
            var form = await request.ReadFormAsync(cancellationToken);
            AddParameters(parameters, form, excluded);
        }

        return parameters;
    }

    private static void AddParameters(
        List<KeyValuePair<string, string?>> destination,
        IEnumerable<KeyValuePair<string, StringValues>> source,
        HashSet<string>? excluded)
    {
        foreach (var pair in source)
        {
            if (excluded?.Contains(pair.Key) == true)
            {
                continue;
            }

            foreach (var value in pair.Value)
            {
                destination.Add(new KeyValuePair<string, string?>(pair.Key, value));
            }
        }
    }
}
