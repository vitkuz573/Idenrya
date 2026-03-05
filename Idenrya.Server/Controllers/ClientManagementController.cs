using Idenrya.Server.Models;
using Idenrya.Server.Models.Admin;
using Idenrya.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Idenrya.Server.Controllers;

[ApiController]
[Route("api/admin/clients")]
[Authorize(Roles = IdentityRoles.Administrator)]
public sealed class ClientManagementController(
    IIdentityProviderClientService clientService) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<OpenIdClientResponse>>> List(CancellationToken cancellationToken)
    {
        return Ok(await clientService.ListAsync(cancellationToken));
    }

    [HttpGet("{clientId}")]
    public async Task<ActionResult<OpenIdClientResponse>> GetByClientId(
        string clientId,
        CancellationToken cancellationToken)
    {
        var client = await clientService.FindByClientIdAsync(clientId, cancellationToken);
        return client is null ? NotFound() : Ok(client);
    }

    [HttpPost]
    public async Task<ActionResult<OpenIdClientResponse>> Create(
        [FromBody] CreateOpenIdClientRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var created = await clientService.CreateAsync(request, cancellationToken);
            return CreatedAtAction(nameof(GetByClientId), new { clientId = created.ClientId }, created);
        }
        catch (ArgumentException exception)
        {
            ModelState.AddModelError(string.Empty, exception.Message);
            return ValidationProblem(ModelState);
        }
        catch (InvalidOperationException exception)
        {
            return Conflict(new ProblemDetails
            {
                Title = "Client already exists",
                Detail = exception.Message,
                Status = StatusCodes.Status409Conflict
            });
        }
    }

    [HttpPut("{clientId}")]
    public async Task<ActionResult<OpenIdClientResponse>> Update(
        string clientId,
        [FromBody] UpdateOpenIdClientRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var updated = await clientService.UpdateAsync(clientId, request, cancellationToken);
            return updated is null ? NotFound() : Ok(updated);
        }
        catch (ArgumentException exception)
        {
            ModelState.AddModelError(string.Empty, exception.Message);
            return ValidationProblem(ModelState);
        }
    }

    [HttpDelete("{clientId}")]
    public async Task<IActionResult> Delete(string clientId, CancellationToken cancellationToken)
    {
        try
        {
            return await clientService.DeleteAsync(clientId, cancellationToken) ? NoContent() : NotFound();
        }
        catch (ArgumentException exception)
        {
            ModelState.AddModelError(string.Empty, exception.Message);
            return ValidationProblem(ModelState);
        }
    }

    [HttpPost("{clientId}/rotate-secret")]
    public async Task<ActionResult<RotateOpenIdClientSecretResponse>> RotateSecret(
        string clientId,
        [FromBody] RotateOpenIdClientSecretRequest? request,
        CancellationToken cancellationToken)
    {
        try
        {
            var rotated = await clientService.RotateSecretAsync(
                clientId,
                request?.ClientSecret,
                cancellationToken);

            return rotated is null ? NotFound() : Ok(rotated);
        }
        catch (ArgumentException exception)
        {
            ModelState.AddModelError(string.Empty, exception.Message);
            return ValidationProblem(ModelState);
        }
        catch (InvalidOperationException exception)
        {
            return Conflict(new ProblemDetails
            {
                Title = "Client secret rotation failed",
                Detail = exception.Message,
                Status = StatusCodes.Status409Conflict
            });
        }
    }
}
