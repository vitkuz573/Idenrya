using Idenrya.Server.Models;
using Idenrya.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Idenrya.Server.Controllers;

[ApiController]
[AllowAnonymous]
[ApiExplorerSettings(IgnoreApi = true)]
public sealed class DynamicClientRegistrationController(
    IOpenIdDynamicClientRegistrationService registrationService) : ControllerBase
{
    private const string RegistrationEndpointRouteName = "OpenIdDynamicRegistrationEndpoint";

    [HttpPost("~/connect/register", Name = RegistrationEndpointRouteName)]
    public async Task<IActionResult> Register(
        [FromBody] OpenIdDynamicClientRegistrationRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var created = await registrationService.RegisterAsync(
                request,
                BuildRegistrationEndpointUri(),
                ReadBearerToken(),
                cancellationToken);

            return StatusCode(StatusCodes.Status201Created, created);
        }
        catch (ArgumentException exception)
        {
            return InvalidClientMetadata(exception.Message);
        }
        catch (InvalidOperationException exception)
        {
            return InvalidClientMetadata(exception.Message);
        }
        catch (UnauthorizedAccessException exception)
        {
            return InvalidToken(exception.Message);
        }
    }

    [HttpGet("~/connect/register/{clientId}")]
    public async Task<IActionResult> Get(string clientId, CancellationToken cancellationToken)
    {
        try
        {
            var registered = await registrationService.GetAsync(
                clientId,
                BuildRegistrationEndpointUri(),
                ReadBearerToken(),
                cancellationToken);

            return registered is null ? NotFound() : Ok(registered);
        }
        catch (ArgumentException exception)
        {
            return InvalidRequest(exception.Message);
        }
        catch (UnauthorizedAccessException exception)
        {
            return InvalidToken(exception.Message);
        }
    }

    [HttpDelete("~/connect/register/{clientId}")]
    public async Task<IActionResult> Delete(string clientId, CancellationToken cancellationToken)
    {
        try
        {
            return await registrationService.DeleteAsync(clientId, ReadBearerToken(), cancellationToken)
                ? NoContent()
                : NotFound();
        }
        catch (ArgumentException exception)
        {
            return InvalidRequest(exception.Message);
        }
        catch (UnauthorizedAccessException exception)
        {
            return InvalidToken(exception.Message);
        }
    }

    private ObjectResult InvalidRequest(string description)
    {
        return StatusCode(StatusCodes.Status400BadRequest, new
        {
            error = "invalid_request",
            error_description = description
        });
    }

    private ObjectResult InvalidClientMetadata(string description)
    {
        return StatusCode(StatusCodes.Status400BadRequest, new
        {
            error = "invalid_client_metadata",
            error_description = description
        });
    }

    private ObjectResult InvalidToken(string description)
    {
        return StatusCode(StatusCodes.Status401Unauthorized, new
        {
            error = "invalid_token",
            error_description = description
        });
    }

    private Uri BuildRegistrationEndpointUri()
    {
        var endpoint = Url.RouteUrl(
            routeName: RegistrationEndpointRouteName,
            values: null,
            protocol: Request.Scheme,
            host: Request.Host.ToString());

        if (!string.IsNullOrWhiteSpace(endpoint) && Uri.TryCreate(endpoint, UriKind.Absolute, out var absolute))
        {
            return absolute;
        }

        return new Uri($"{Request.Scheme}://{Request.Host}{Request.PathBase}/connect/register", UriKind.Absolute);
    }

    private string? ReadBearerToken()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var authorizationHeader))
        {
            return null;
        }

        var value = authorizationHeader.ToString();
        const string bearerPrefix = "Bearer ";
        if (!value.StartsWith(bearerPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var token = value[bearerPrefix.Length..].Trim();
        return string.IsNullOrWhiteSpace(token) ? null : token;
    }
}
