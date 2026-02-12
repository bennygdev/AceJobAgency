using AceJobAgency.Model;
using AceJobAgency.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddDbContext<AuthDbContext>();

// Register custom services
builder.Services.AddScoped<IEncryptionService, EncryptionService>();
builder.Services.AddScoped<IAuditLogService, AuditLogService>();
builder.Services.AddHttpClient<IEmailService, EmailService>();
builder.Services.AddHttpClient<IReCaptchaService, ReCaptchaService>();

// Configure session
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(
        builder.Configuration.GetValue<int>("Session:IdleTimeoutMinutes", 15));
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.Name = ".AceJobAgency.Session";
});

// Configure antiforgery
builder.Services.AddAntiforgery(options =>
{
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.HttpOnly = true;
    options.HeaderName = "X-CSRF-TOKEN";
});

// Configure data protection
builder.Services.AddDataProtection();

// Add HttpContextAccessor
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
else
{
    app.UseDeveloperExceptionPage();
}

app.UseStatusCodePagesWithReExecute("/Error/{0}");

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseSession();

// Custom middleware for session validation
app.Use(async (context, next) =>
{
    // Check if user is logged in and session is valid
    var memberId = context.Session.GetInt32("MemberId");
    var sessionId = context.Session.GetString("SessionId");
    var path = context.Request.Path.Value?.ToLower() ?? "";
    
    if (memberId.HasValue && !string.IsNullOrEmpty(sessionId))
    {
        // Verify session is still valid in database
        using var scope = app.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        
        // Check against UserSession table instead of Member table
        var userSession = await dbContext.UserSessions
            .FirstOrDefaultAsync(s => s.SessionId == sessionId && s.MemberId == memberId.Value && s.IsActive);
        
        if (userSession == null)
        {
            // Session is invalid or inactive, clear it
            context.Session.Clear();
            context.Response.Redirect("/Login?message=session_expired");
            return;
        }

        // Update LastActive timestamp
        userSession.LastActive = DateTime.UtcNow;
        await dbContext.SaveChangesAsync();

        // Check password age (Moved from Login to Middleware for continuous enforcement)
        if (path != "/changepassword" && path != "/logout" && !path.StartsWith("/statuscode") && path != "/error")
        {
             var member = await dbContext.Members.FindAsync(memberId.Value);
             if (member != null && member.LastPasswordChange.HasValue)
             {
                 var maxPasswordAgeDays = builder.Configuration.GetValue<int>("Security:MaxPasswordAgeDays", 90);
                 if (member.LastPasswordChange.Value.AddDays(maxPasswordAgeDays) < DateTime.UtcNow)
                 {
                     context.Response.Redirect("/ChangePassword?expired=true");
                     return;
                 }
             }
        }
    }
    
    await next();
});

app.UseAuthorization();

app.MapRazorPages();

// Create database and apply migrations on startup
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    dbContext.Database.EnsureCreated();
}

app.Run();
