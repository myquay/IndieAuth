using System.Text.Json;

namespace AspNet.Security.IndieAuth.Infrastructure;

public class SnakeCaseNamingPolicy : JsonNamingPolicy
{
    public override string ConvertName(string name)
    {
        return StringUtils.ToSnakeCase(name);
    }
}