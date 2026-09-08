using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Models.SCA;
using Checkmarx.API.AST.Services.KicsResults;
using Checkmarx.API.AST.Services.SASTResults;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;

namespace Checkmarx.API.AST.Utils
{
    public static class EnumUtils
    {
        public static T GetEnumValueByDescription<T>(string description) where T : struct, Enum
        {
            if (string.IsNullOrWhiteSpace(description))
                throw new ArgumentNullException(nameof(description), "Enum description cannot be null or empty.");

            foreach (var field in typeof(T).GetFields())
            {
                if (Attribute.GetCustomAttribute(field, typeof(DescriptionAttribute)) is DescriptionAttribute attr)
                {
                    if (attr.Description.Equals(description, StringComparison.OrdinalIgnoreCase))
                        return (T)field.GetValue(null);
                }
                else
                {
                    if (field.Name.Equals(description, StringComparison.OrdinalIgnoreCase))
                        return (T)field.GetValue(null);
                }
            }

            throw new InvalidOperationException($"'{description}' is not a valid {typeof(T).Name}.");
        }

        public static string GetDescription(this Enum value)
        {
            var field = value.GetType().GetField(value.ToString());
            var attribute = field.GetCustomAttribute<DescriptionAttribute>();

            return attribute?.Description ?? value.ToString();
        }

        public static List<ResultState> GetStateEnumMemberList<T>() where T : Enum
        {
            if (typeof(T) == typeof(ResultsState))
            {
                return Enum.GetValues(typeof(ResultsState))
                        .Cast<ResultsState>()
                        .Select(state => new SASTResultState
                        {
                            Id = (int)state,
                            Name = typeof(ResultsState)
                                .GetField(state.ToString())
                                ?.GetCustomAttribute<EnumMemberAttribute>()?.Value ?? state.ToString(),
                            State = state
                        })
                        .OfType<ResultState>()
                        .ToList();
            }
            else if (typeof(T) == typeof(ScaVulnerabilityStatus))
            {
                return Enum.GetValues(typeof(ScaVulnerabilityStatus))
                        .Cast<ScaVulnerabilityStatus>()
                        .Select(state => new SCAResultState
                        {
                            Id = (int)state,
                            Name = typeof(ScaVulnerabilityStatus)
                                .GetField(state.ToString())
                                ?.GetCustomAttribute<EnumMemberAttribute>()?.Value ?? state.ToString(),
                            State = state
                        })
                        .OfType<ResultState>()
                        .ToList();
            }
            else if (typeof(T) == typeof(KicsStateEnum))
            {
                return Enum.GetValues(typeof(KicsStateEnum))
                        .Cast<KicsStateEnum>()
                        .Select(state => new KicsResultState
                        {
                            Id = (int)state,
                            Name = typeof(KicsStateEnum)
                                .GetField(state.ToString())
                                ?.GetCustomAttribute<EnumMemberAttribute>()?.Value ?? state.ToString(),
                            State = state
                        })
                        .OfType<ResultState>()
                        .ToList();
            }
            else
            {
                throw new ArgumentException($"Unsupported enum type: {typeof(T).Name}. Supported types are ResultsState, ScaVulnerabilityStatus, and KicsStateEnum.");
            }
        }

        public static string GetEnumMemberValue(this Enum enumValue)
        {
            var memberInfo = enumValue.GetType().GetMember(enumValue.ToString()).FirstOrDefault();
            var attribute = memberInfo?.GetCustomAttribute<EnumMemberAttribute>();
            return attribute?.Value ?? enumValue.ToString();
        }
    }
}
