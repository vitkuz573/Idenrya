using Idenrya.Server.Models;
using Idenrya.Server.Models.Admin;
using Idenrya.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Idenrya.Server.Controllers;

[ApiController]
[Route("api/admin/scopes")]
[Authorize(Roles = IdentityRoles.Administrator)]
public sealed class ScopeManagementController(
    IIdentityProviderScopeService scopeService) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<OpenIdScopeResponse>>> List(CancellationToken cancellationToken)
    {
        return Ok(await scopeService.ListAsync(cancellationToken));
    }

    [HttpGet("{scopeName}")]
    public async Task<ActionResult<OpenIdScopeResponse>> GetByName(
        string scopeName,
        CancellationToken cancellationToken)
    {
        try
        {
            var scope = await scopeService.FindByNameAsync(scopeName, cancellationToken);
            return scope is null ? NotFound() : Ok(scope);
        }
        catch (ArgumentException exception)
        {
            ModelState.AddModelError(string.Empty, exception.Message);
            return ValidationProblem(ModelState);
        }
    }

    [HttpPost]
    public async Task<ActionResult<OpenIdScopeResponse>> Create(
        [FromBody] CreateOpenIdScopeRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var created = await scopeService.CreateAsync(request, cancellationToken);
            return CreatedAtAction(nameof(GetByName), new { scopeName = created.Name }, created);
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
                Title = "Scope operation failed",
                Detail = exception.Message,
                Status = StatusCodes.Status409Conflict
            });
        }
    }

    [HttpDelete("{scopeName}")]
    public async Task<IActionResult> Delete(string scopeName, CancellationToken cancellationToken)
    {
        try
        {
            return await scopeService.DeleteAsync(scopeName, cancellationToken) ? NoContent() : NotFound();
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
                Title = "Scope operation failed",
                Detail = exception.Message,
                Status = StatusCodes.Status409Conflict
            });
        }
    }
}
