using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddMvc();
builder.Services.AddAuthentication("custom");
//builder.Services.AddAuthorization(a => {
//    a.DefaultPolicy = new AuthorizationPolicyBuilder().Requirements.Add().Build();
//});
builder.Services.Configure<AuthenticationOptions>(a => {
    a.AddScheme<CustomAuthenticationHandler>("custom","custom");
});
builder.Services.AddTransient<CustomAuthenticationHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, CustomAuthorizationHandler>();
builder.Services.AddHttpContextAccessor();
var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapDefaultControllerRoute   ();

app.Run();


public class CustomAuthenticationHandler : IAuthenticationRequestHandler,IAuthenticationSignInHandler
{
    private HttpContext _context = default!;
    private UrlEncoder _urlEncoder;
    public CustomAuthenticationHandler(UrlEncoder urlEncoder)
    {
        _urlEncoder = urlEncoder;
    }
    public Task<AuthenticateResult> AuthenticateAsync()
    {
        var cookie = _context.Request.Cookies["custom"];
        if (cookie == null)
        {
            return Task.FromResult(AuthenticateResult.Fail("你还没有登录"));
        }
        var claims = JsonSerializer.Deserialize<Dictionary<string,string>>(cookie)?.Select(a=>new Claim(a.Key,a.Value)).ToArray();
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(claims, "custom", "name", "role")), "custom")));
    }

    public Task ChallengeAsync(AuthenticationProperties? properties)
    {
        _context.Response.Redirect($"/Account/Login?ReturnUrl={_urlEncoder.Encode(_context.Request.Path+_context.Request.QueryString)}");
        return Task.CompletedTask;
    }

    public Task ForbidAsync(AuthenticationProperties? properties)
    {
        _context.Response.Headers.ContentType = ("text/html; charset=utf-8");
        return _context.Response.WriteAsync($"<p>你的权限不够，需要提升权限</p><p><a href=\"/Account/UpRoot?ReturnUrl={_urlEncoder.Encode(_context.Request.Path+_context.Request.QueryString)}\">权限提升</a></p>");
    }

    public Task<bool> HandleRequestAsync()
    {
        return Task.FromResult(false);
    }

    public Task InitializeAsync(AuthenticationScheme scheme, HttpContext context)
    {
        _context = context;
        return Task.CompletedTask;
    }

    public Task SignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
    {
        var str = JsonSerializer.Serialize(user.Claims.ToDictionary(a => a.Type, a => a.Value));
        _context.Response.Cookies.Append("custom",str,new CookieOptions{SameSite=SameSiteMode.Lax });
        _context.Response.Headers.Append("cookievalues",str);
        var ReturnUrl = _context.Request.Query["returnurl"].FirstOrDefault()??"/";
        _context.Response.Redirect(ReturnUrl);
        return Task.CompletedTask;
    }

    public Task SignOutAsync(AuthenticationProperties? properties)
    {
        _context.Response.Cookies.Delete("custom");
        _context.Response.Cookies.Delete("face");
        _context.Response.Redirect($"/Account/Login");
        return Task.CompletedTask;
    }
}
//public class CustomAuthorizationRequirement : IAuthorizationRequirement { }
public class CustomAuthorizationHandler : IAuthorizationHandler
{
    private IHttpContextAccessor _httpContextAccessor;
    public CustomAuthorizationHandler(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public Task HandleAsync(AuthorizationHandlerContext context)
    {
        var cookie = _httpContextAccessor.HttpContext!.Request.Cookies["face"];
        if (cookie!="asdface")
        {
            context.Fail();
            return Task.CompletedTask;
        }
        return Task.CompletedTask;
    }
}