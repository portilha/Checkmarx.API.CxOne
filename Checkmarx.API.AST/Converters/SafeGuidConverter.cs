using Newtonsoft.Json;
using System;

namespace Checkmarx.API.AST.Converters
{
    public class SafeGuidConverter : JsonConverter<Guid>
    {
        public override Guid ReadJson(
            JsonReader reader,
            Type objectType,
            Guid existingValue,
            bool hasExistingValue,
            JsonSerializer serializer)
        {
            if (reader.TokenType == JsonToken.String &&
                Guid.TryParse(reader.Value?.ToString(), out var guid))
            {
                return guid;
            }

            // Ignore invalid values
            return Guid.Empty;
        }

        public override void WriteJson(JsonWriter writer, Guid value, JsonSerializer serializer)
        {
            writer.WriteValue(value);
        }
    }
}
