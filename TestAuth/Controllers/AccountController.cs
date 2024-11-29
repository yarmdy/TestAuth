using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text;
using System.Web;

namespace TestAuth.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult Login(string? returnUrl = null)
        {
            return Content($"<p>登录页</p><p><a href=\"/Account/DoLogin{(string.IsNullOrEmpty(returnUrl)?"": "?ReturnUrl= "+HttpUtility.UrlEncode(returnUrl))}\">登录</a></p>", "text/html", Encoding.UTF8);
        }
        public IActionResult DoLogin(string? returnUrl = null) {
            var claims = new List<Claim>
            {
                new Claim("name", "JohnDoe"),
                new Claim("role", "admin")
            };

            var claimsIdentity = new ClaimsIdentity(claims, "custom", "name", "role");
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
            return SignIn(claimsPrincipal);
        }
        public IActionResult Logout()
        {
            return SignOut();
        }
        public IActionResult UpRoot(string? returnUrl=null)
        {
            HttpContext.Response.Cookies.Append("face", "asdface", new CookieOptions { SameSite = SameSiteMode.Lax });
            return Redirect(returnUrl??"/");
        }
    }
}
