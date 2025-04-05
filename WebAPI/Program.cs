var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

// Cấu hình DB, Identity, JWT, CORS (được định nghĩa trong Infrastructure)
builder.Services.AddInfrastructureServices(builder.Configuration);
// Cấu hình Identity
builder.Services.AddIdentityServices(builder.Configuration);
builder.Services.AddRepositoryServices();


builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
