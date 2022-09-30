// Additional using declarations
using Project.Data;
using Project.Models;
using Project.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Identity;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Database Config
var config     = builder.Configuration;
var DBHost     = config["Host"];
var DBUserName = config["Username"];
var DBDatabase = config["Database"];
var DBPassword = config["Password"];

var connectionString = $"Host={DBHost};Database={DBDatabase};Username={DBUserName};Password={DBPassword};Include Error Detail=True";

builder.Services.AddDbContext<ProjectContext>(options =>
    options.UseNpgsql(connectionString)
           .UseSnakeCaseNamingConvention()
           .UseLoggerFactory(LoggerFactory.Create(builder => builder.AddConsole()))
           .EnableSensitiveDataLogging()
);

// Add identity model builder config
builder.Services.AddIdentity<User, IdentityRole>()
                .AddEntityFrameworkStores<ProjectContext>()
                .AddDefaultTokenProviders();

// Adding Authentication
builder.Services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                })
// Adding Jwt Bearer
                .AddJwtBearer(options =>
                {
                    options.SaveToken = true;
                    options.RequireHttpsMetadata = false;
                    options.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidAudience = config["JWT:ValidAudience"],
                        ValidIssuer = config["JWT:ValidIssuer"],
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JWT:Secret"]))
                    };
                });

// Add the PromotionsContext
builder.Services.AddScoped<PizzaService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Add the CreateDbIfNotExists method call
app.CreateDbIfNotExists();

app.UseHttpsRedirection();

// Authentication & Authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
