using Microsoft.AspNetCore.Mvc;

namespace Idenrya.Server.Controllers;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        return View();
    }

}
