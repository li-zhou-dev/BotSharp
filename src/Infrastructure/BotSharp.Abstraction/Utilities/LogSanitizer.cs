using System.Text.RegularExpressions;

namespace BotSharp.Abstraction.Utilities;

/// <summary>
/// Masks tokens, emails and phone numbers inside text that is about to be logged.
/// Names and addresses cannot be recognised in free text and are left as they are.
/// </summary>
public static class LogSanitizer
{
    private const RegexOptions Options = RegexOptions.Compiled | RegexOptions.CultureInvariant;
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(200);

    private static readonly Regex JwtPattern = new(
        @"eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]*", Options, MatchTimeout);

    private static readonly Regex TokenParameterPattern = new(
        @"\b((?:access_|refresh_|id_)?token)=[^&\s""'\\]+", Options | RegexOptions.IgnoreCase, MatchTimeout);

    private static readonly Regex BearerPattern = new(
        @"\bBearer\s+[A-Za-z0-9\-._~+/]{8,}=*", Options | RegexOptions.IgnoreCase, MatchTimeout);

    private static readonly Regex EmailPattern = new(
        @"(?<![A-Za-z0-9._%+*-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}", Options, MatchTimeout);

    // North American numbers; also accepts the JSON-escaped plus sign (+).
    private static readonly Regex PhonePattern = new(
        @"(?<![\w.])(?:\+|\\u002B)?(?:1[-. ]?)?\(?[2-9]\d{2}\)?[-. ]?[2-9]\d{2}[-. ]?\d{4}(?!\w)",
        Options | RegexOptions.IgnoreCase, MatchTimeout);

    public static string Sanitize(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        try
        {
            text = ReplaceIfContains(text, "eyJ", JwtPattern, "[REDACTED_JWT]");
            text = ReplaceIfContains(text, "token=", TokenParameterPattern, "$1=[REDACTED]");
            text = ReplaceIfContains(text, "Bearer", BearerPattern, "Bearer [REDACTED]");
            text = text.Contains('@') ? EmailPattern.Replace(text, match => MaskEmail(match.Value)) : text;
            return PhonePattern.Replace(text, match => MaskPhone(match.Value));
        }
        catch (RegexMatchTimeoutException)
        {
            return "[masking timed out]";
        }
    }

    private static string ReplaceIfContains(string text, string marker, Regex regex, string replacement)
        => text.Contains(marker, StringComparison.OrdinalIgnoreCase) ? regex.Replace(text, replacement) : text;

    private static string MaskEmail(string email)
    {
        var at = email.LastIndexOf('@');
        return MaskMiddle(email[..at], 1, 1) + email[at..];
    }

    private static string MaskPhone(string phone)
    {
        var digits = new string(phone.Where(char.IsDigit).ToArray());
        var plus = phone.StartsWith('+') || phone.StartsWith("\\u002B", StringComparison.OrdinalIgnoreCase) ? "+" : string.Empty;
        return plus + MaskMiddle(digits, 3, 2);
    }

    private static string MaskMiddle(string value, int keepStart, int keepEnd)
    {
        if (value.Length <= keepStart + keepEnd)
        {
            return new string('*', value.Length);
        }

        return value[..keepStart] + new string('*', value.Length - keepStart - keepEnd) + value[^keepEnd..];
    }
}
