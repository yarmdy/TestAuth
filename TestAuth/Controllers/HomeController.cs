using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Text;
using System.Text.Encodings.Web;

namespace TestAuth.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return Content($"<p>欢迎</p><p><a href=\"/Account/Logout\">退出</a></p>","text/html",Encoding.UTF8);
        }
    }
}
