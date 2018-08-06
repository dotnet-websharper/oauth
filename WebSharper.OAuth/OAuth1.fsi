module WebSharper.OAuth.OAuth1

open System.Security.Cryptography.X509Certificates

type Token =
    {
        Key : string
        Secret : string
    }

type Signature =
    | PlainText
    | HMACSHA1
    | RSASHA1 of X509Certificate2

type OAuthSettings =
    {
        ClientToken : Token
        RequestTokenEndpoint : string
        AuthorizeTokenEndpoint : string
        AccessTokenEndpoint : string
        SignatureMethod : Signature
        Callback : string option
        Log : string -> unit
    }

type GetOAuthAccessTokenParams =
    {
        Settings : OAuthSettings
        RequestToken : Token
        VerifierKey : string
    }

type CallOAuthServiceParams =
    {
        Settings : OAuthSettings
        AccessToken : Token
        HttpMethod : string
        ServiceUri : string
    }

val GetOAuthRequestToken : settings: OAuthSettings -> Token
val GetOAuthAccessTokenAndAll : paras: GetOAuthAccessTokenParams -> Token * (string * string) list
val GetOAuthAccessToken : paras: GetOAuthAccessTokenParams -> Token
val CallOAuthService : paras: CallOAuthServiceParams -> string

