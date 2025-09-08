using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace KeeperBiometric
{
    /// <summary>
    /// Public Key Creation Options for WebAuthn/FIDO2 credential creation
    /// </summary>
    public class PkCreationOptions
    {
        [JsonPropertyName("rp")]
        public RelyingParty Rp { get; set; } = new RelyingParty();

        [JsonPropertyName("user")]
        public UserInfo User { get; set; } = new UserInfo();

        [JsonPropertyName("challenge")]
        public string Challenge { get; set; } = string.Empty;

        [JsonPropertyName("pubKeyCredParams")]
        public List<PubKeyCredParam> PubKeyCredParams { get; set; } = new List<PubKeyCredParam>();

        [JsonPropertyName("timeout")]
        public uint? Timeout { get; set; }

        [JsonPropertyName("excludeCredentials")]
        public List<CredentialDescriptor> ExcludeCredentials { get; set; } = new List<CredentialDescriptor>();

        [JsonPropertyName("authenticatorSelection")]
        public AuthenticatorSelection AuthenticatorSelection { get; set; } = new AuthenticatorSelection();

        [JsonPropertyName("attestation")]
        public string Attestation { get; set; } = "direct";

        [JsonPropertyName("extensions")]
        public Dictionary<string, object> Extensions { get; set; } = new Dictionary<string, object>();

        [JsonPropertyName("hints")]
        public List<string> Hints { get; set; } = new List<string>();
    }

    public class RelyingParty
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;
    }

    public class UserInfo
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("displayName")]
        public string DisplayName { get; set; } = string.Empty;
    }

    public class PubKeyCredParam
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = string.Empty;

        [JsonPropertyName("alg")]
        public int Alg { get; set; }
    }

    public class CredentialDescriptor
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = string.Empty;

        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        [JsonPropertyName("transports")]
        public List<string> Transports { get; set; } = new List<string>();
    }

    public class AuthenticatorSelection
    {
        [JsonPropertyName("authenticatorAttachment")]
        public string AuthenticatorAttachment { get; set; } = "platform";

        [JsonPropertyName("residentKey")]
        public string ResidentKey { get; set; } = "required";

        [JsonPropertyName("requireResidentKey")]
        public bool RequireResidentKey { get; set; }

        [JsonPropertyName("userVerification")]
        public string UserVerification { get; set; } = "required";
    }
}
