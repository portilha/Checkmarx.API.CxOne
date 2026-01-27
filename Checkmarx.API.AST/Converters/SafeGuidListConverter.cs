using Newtonsoft.Json;
using System;
using System.Collections.Generic;

namespace Checkmarx.API.AST.Converters
{
    public class SafeGuidListConverter : JsonConverter<List<Guid>>
    {
        public override List<Guid> ReadJson(
            JsonReader reader,
            Type objectType,
            List<Guid> existingValue,
            bool hasExistingValue,
            JsonSerializer serializer)
        {
            var result = new List<Guid>();

            if (reader.TokenType != JsonToken.StartArray)
                return result;

            while (reader.Read() && reader.TokenType != JsonToken.EndArray)
            {
                if (reader.TokenType == JsonToken.String &&
                    Guid.TryParse(reader.Value?.ToString(), out var guid))
                {
                    result.Add(guid);
                }
                // else: silently ignore bad values
            }

            return result;
        }

        public override void WriteJson(JsonWriter writer, List<Guid> value, JsonSerializer serializer)
        {
            writer.WriteStartArray();
            foreach (var guid in value)
                writer.WriteValue(guid);
            writer.WriteEndArray();
        }
    }
}
