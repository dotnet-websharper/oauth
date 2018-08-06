module WebSharper.OAuth.OAuth2

open System
open System.Net
open WebSharper.Sitelets
open WebSharper.Web

type ServiceSettings =
    {
        ClientId: string
        ClientSecret: string
        AuthorizationEndpoint: string
        TokenEndpoint: string
    }

    static member AppHarbor : id: string * secret: string -> ServiceSettings

    static member Facebook : id: string * secret: string -> ServiceSettings

    static member FPish : id: string * secret: string -> ServiceSettings

    static member FPishMini : id: string * secret: string -> ServiceSettings

    static member Github : id: string * secret: string -> ServiceSettings

    static member Google : id: string * secret: string -> ServiceSettings

type Settings =
    {
        Service: ServiceSettings
        RedirectEndpoint: string
        State: string option
        Scope: string option
        Log : string -> unit
    }

type AuthenticationError =
    {
        Message: string option
        Description: string option
        Uri: string option
        State: string option
    }

type AuthenticationToken =
    {
        Token: string
        State: string option
    }

    member AuthorizeRequest : HttpWebRequest -> unit

type AuthenticationResponse =
    | Error of AuthenticationError
    | Success of AuthenticationToken
    | ImplicitSuccess

val GetAuthorizationRequestUrl : settings: Settings -> string
val GetImplicitAuthorizationRequestUrl : settings: Settings -> string

val AuthorizeClient : settings: Settings -> requestUri: Uri -> Async<AuthenticationResponse>

/// Helper to manage an OAuth provider in a Sitelets application.
[<Sealed>]
type Provider<'a when 'a : equality> =

    /// <summary>
    /// Register a client for an OAuth provider.
    /// </summary>
    /// <param name="service">The definition of the OAuth provider.</param>
    /// <param name="redirectEndpoint">The content of the redirect endpoint.</param>
    /// <param name="redirectEndpointAction">
    /// The action on which the redirect endpoint is linked.
    /// </param>
    /// <param name="redirectEndpointUrlPath">
    /// The URL on which the redirect endpoint is linked.
    /// By default, use Router.Infer on redirectEndpointAction.
    /// </param>
    /// <param name="defaultScope">
    /// The scope used by authorization requests, unless overridden.
    /// </param>
    static member Setup
        : service: ServiceSettings
        * redirectEndpoint : (Context<'a> -> AuthenticationResponse -> Async<Content<'a>>)
        * redirectEndpointAction: 'a
        * ?redirectEndpointUrlPath: string
        * ?defaultScope: string
        * ?baseUrl: string
        * ?log: (string -> unit)
        -> Provider<'a>

    /// Retrieve the OAuth redirect endpoint (ie. the page to which
    /// the user gets redirected by the provider). This sitelet must
    /// be summed with your main website.
    member RedirectEndpointSitelet : Sitelet<'a>
    /// Retrieve the OAuth2 settings associated with a given provider,
    /// for example to pass to Client.OAuth2.GetAuthorizationRequestUrl.
    member GetSettings : ?context: Context * ?state: string * ?scope: string -> Settings
    /// Retrieve the OAuth authorization request for an authorization code-based flow.
    member GetAuthorizationRequestUrl : ?context: Context * ?state: string * ?scope: string -> string
    /// Retrieve the OAuth authorization request for an implicit flow.
    member GetImplicitAuthorizationRequestUrl : ?context: Context * ?state: string * ?scope: string -> string
    /// Retrieve the OAuth2 settings associated with a given provider,
    /// for example to pass to Client.OAuth2.GetAuthorizationRequestUrl.
    member GetSettings : baseUrl: string * ?state: string * ?scope: string -> Settings
    /// Retrieve the OAuth authorization request for an authorization code-based flow.
    member GetAuthorizationRequestUrl : baseUrl: string * ?state: string * ?scope: string -> string
    /// Retrieve the OAuth authorization request for an implicit flow.
    member GetImplicitAuthorizationRequestUrl : baseUrl: string * ?state: string * ?scope: string -> string
