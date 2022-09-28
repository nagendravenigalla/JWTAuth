namespace JWTAuth.WebApi.Database
{
    public class DatabaseSettings:IDatabaseSettings
    {
        string? CollectionName { get; set; }
        string? ConnectionString { get; set; }
        string? DatabaseName { get; set; }
    }
}
