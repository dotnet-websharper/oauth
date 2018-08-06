/// Implement the Authorization Code type of authorization grant.
/// (see http://tutorials.jenkov.com/oauth2/authorization.html)
module WebSharper.OAuth.OAuth2

open System
open System.IO
open System.Net
open System.Text
open System.Web
open WebSharper.Sitelets
open WebSharper.Web
open WebSharper.OAuth.Utils

type ServiceSettings =
    {
        ClientId: string
        ClientSecret: string
        AuthorizationEndpoint: string
        TokenEndpoint: string
    }

    static member AppHarbor(id, secret) =
        {
            AuthorizationEndpoint = "https://appharbor.com/user/authorizations/new"
            TokenEndpoint = "https://appharbor.com/tokens"
            ClientId = id
            ClientSecret = secret
        }

    static member Facebook(id, secret) =
        {
            AuthorizationEndpoint = "https://www.facebook.com/dialog/oauth"
            TokenEndpoint = "https://graph.facebook.com/v2.3/oauth/access_token"
            ClientId = id
            ClientSecret = secret
        }

    static member FPish(id, secret) =
        {
            AuthorizationEndpoint = "https://fpish.net/oauth2/Authorize"
            TokenEndpoint = "https://fpish.net/oauth2/AuthorizeToken"
            ClientId = id
            ClientSecret = secret
        }

    static member FPishMini(id, secret) =
        {
            AuthorizationEndpoint = "https://fpish.net/oauth2-mini/Authorize"
            TokenEndpoint = "https://fpish.net/oauth2-mini/AuthorizeToken"
            ClientId = id
            ClientSecret = secret
        }

    static member Github(id, secret) =
        {
            AuthorizationEndpoint = "https://github.com/login/oauth/authorize"
            TokenEndpoint = "https://github.com/login/oauth/access_token"
            ClientId = id
            ClientSecret = secret
        }

    static member Google(id, secret) =
        {
            AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/auth"
            TokenEndpoint = "https://accounts.google.com/o/oauth2/token"
            ClientId = id
            ClientSecret = secret
        }

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

    member this.AuthorizeRequest (req: HttpWebRequest) =
        req.Headers.Add("Authorization", "Bearer " + this.Token)

type AuthenticationResponse =
    | Error of AuthenticationError
    | Success of AuthenticationToken
    | ImplicitSuccess

let getAuthorizationRequestUrl response_type (settings: Settings) =
    normalizeUrlWithParams settings.Service.AuthorizationEndpoint
        [
            yield "response_type", response_type
            yield "client_id", settings.Service.ClientId
            yield "redirect_uri", settings.RedirectEndpoint
            match settings.State with
            | None -> ()
            | Some state -> yield "state", state
            match settings.Scope with
            | None -> ()
            | Some scope -> yield "scope", scope
        ]

let GetAuthorizationRequestUrl settings =
    getAuthorizationRequestUrl "code" settings

let GetImplicitAuthorizationRequestUrl settings =
    getAuthorizationRequestUrl "token" settings

type AccessToken =
    {
        access_token : string
    }

type AccessTokenError =
    {
        error : string
    }

type AccessTokenResponse =
    | Success of string
    | Failure of option<string>

let json = WebSharper.Core.Json.Provider.Create()

let parseJson<'T> (x: string) =
    WebSharper.Core.Json.Parse x
    |> json.GetDecoder<'T>().Decode

let parseAccessTokenString (x: string) =
    let error() =
        try Some ((parseJson<AccessTokenError> x).error)
        with _ -> None
        |> Failure
    try
        match (parseJson<AccessToken> x).access_token with
        | null -> error()
        | t -> Success t
    with e -> error()

let GetAccessToken (settings: Settings) code =
    async {
        // use TLS 1.2
        ServicePointManager.SecurityProtocol <- ServicePointManager.SecurityProtocol ||| SecurityProtocolType.Tls12
        let reqParams =
            [
                "client_id", settings.Service.ClientId
                "client_secret", settings.Service.ClientSecret
                "code", code
                "grant_type", "authorization_code"
                "redirect_uri", settings.RedirectEndpoint
            ]
        //let url = normalizeUrlWithParams settings.Service.TokenEndpoint reqParams
        let url = normalizeUrl settings.Service.TokenEndpoint
        let reqParams =
            reqParams
            |> Seq.map (fun (k, v) -> k + "=" + encode v)
            |> String.concat "&"
        let bytes = Encoding.UTF8.GetBytes(reqParams)
        let req =
            HttpWebRequest.Create(url,
                Method = "POST",
                ContentType = "application/x-www-form-urlencoded",
                ContentLength = bytes.LongLength)
            :?> HttpWebRequest
        do  use reqStream = req.GetRequestStream()
            reqStream.Write(bytes, 0, bytes.Length)
        let! response = req.AsyncGetResponse()
        let! responseBody = async {
            use stream = response.GetResponseStream()
            if response.ContentLength >= 0L then
                let! data = stream.AsyncRead(int response.ContentLength)
                return Encoding.UTF8.GetString(data)
            else
                use r = new System.IO.StreamReader(stream, Encoding.UTF8)
                return r.ReadToEnd()
        }
        settings.Log (sprintf "POST %s\r\n-->\r\n%s" url responseBody)
        if response.ContentType.Contains("json") then
            return parseAccessTokenString responseBody
        else
            let tokenData = HttpUtility.ParseQueryString(responseBody)
            return
                match tokenData.["access_token"] with
                | null ->
                    match tokenData.["error"] with
                    | null -> Failure None
                    | error -> Failure (Some error)
                | d -> Success d
    }

let AuthorizeClient (settings: Settings) (requestUri: Uri) =
    let queryString = HttpUtility.ParseQueryString(requestUri.Query)
    let keys = queryString.AllKeys
    if Seq.exists ((=) "code") keys then
        async {
            let! accessToken = GetAccessToken settings queryString.["code"]
            match accessToken with
            | Success accessToken ->
                return AuthenticationResponse.Success {
                    Token = accessToken
                    State =
                        if Seq.exists ((=) "state") keys then
                            Some queryString.["state"]
                        else None
                }
            | Failure e ->
                return AuthenticationResponse.Error {
                    Message = e
                    Description = None
                    Uri = None
                    State =
                        if Seq.exists ((=) "state") keys then
                            Some queryString.["state"]
                        else None
                }
        }
    else
        match queryString.["error"] with
        | null -> AuthenticationResponse.ImplicitSuccess
        | error ->
            AuthenticationResponse.Error {
                Message = Some error
                Description =
                    if Seq.exists ((=) "error_description") keys then
                        Some queryString.["error_description"]
                    else None
                Uri =
                    if Seq.exists ((=) "error_uri") keys then
                        Some queryString.["error_uri"]
                    else None
                State =
                    if Seq.exists ((=) "state") keys then
                        Some queryString.["state"]
                    else None
            }
        |> async.Return

type Provider<'a when 'a : equality> =
    {
        sitelet : Sitelet<'a>
        guid: System.Guid
        baseUrl: option<string>
    }

module ProviderInternals =

    open System
    open System.Collections.Generic
    open System.Runtime.CompilerServices
    open WebSharper.Sitelets
    open WebSharper.Web

    let allProviders = Dictionary<System.Guid, (string -> Settings) * obj>()

    do System.Net.ServicePointManager.ServerCertificateValidationCallback <-
        System.Net.Security.RemoteCertificateValidationCallback(fun _ _ _ _ -> true)

    type ProviderSetup<'a> =
        {
            BaseUrl: option<string>
            CallbackAction : 'a
            CallbackUrlPath : option<string>
            Service : ServiceSettings
            RedirectEndpoint : Context<'a> -> AuthenticationResponse -> Async<Content<'a>>
            Scope : string option
            Log : option<string -> unit>
        }

    /// Configures OAuth2 settings.
    let makeSettings url guid state scope =
        let baseSettings, f = allProviders.[guid]
        let baseSettings = baseSettings url
        { baseSettings with
            State = state
            Scope =
                match scope with
                | None -> baseSettings.Scope
                | Some scope -> Some scope
        }, f

//    let makeSettings (ctx: Context) guid state scope =
//        makeSettings' (ctx.RequestUri.GetLeftPart(UriPartial.Authority)) guid state scope

    /// Registers an OAuth provider and creates the sitelet
    /// that processes its authentication responses.
    let SetupProvider (setup: ProviderSetup<'a>) =
        let guid = System.Guid.NewGuid()
        let url =
            match setup.CallbackUrlPath with
            | None -> Router.Infer().Link(setup.CallbackAction).ToString()
            | Some url -> url
        allProviders.Add(guid,
            ((fun baseUrl ->
                {
                    Service = setup.Service
                    RedirectEndpoint = baseUrl + url
                    State = None
                    Scope = setup.Scope
                    Log = defaultArg setup.Log ignore
                }),
             box setup.RedirectEndpoint))
        let sitelet =
            Sitelet.Content url setup.CallbackAction
                <| fun ctx -> async {
                    try
                        let baseUrl =
                            match setup.BaseUrl with
                            | Some x -> x
                            | None -> ctx.Request.Uri.GetLeftPart(UriPartial.Authority)
                        let settings, f = makeSettings baseUrl guid None None
                        let! resp = AuthorizeClient settings ctx.Request.Uri
                        return! unbox f ctx resp
                    with e ->
                        let error = "Error: " + e.ToString()
                        setup.Log |> Option.iter (fun f -> f error)
                        return! Content.Custom(
                            Status = Http.Status.InternalServerError,
                            WriteBody = fun s ->
                                use w = new System.IO.StreamWriter(s)
                                w.Write(error)
                        )
                }
        {
            sitelet = sitelet
            guid = guid
            baseUrl = setup.BaseUrl
        }

type Provider<'a when 'a : equality> with

    static member Setup
        (
            service, redirectEndpoint, redirectEndpointAction: 'a,
            ?redirectEndpointUrlPath, ?defaultScope, ?baseUrl, ?log
        ) =
        ProviderInternals.SetupProvider {
            BaseUrl = baseUrl
            CallbackAction = redirectEndpointAction
            Service = service
            RedirectEndpoint = redirectEndpoint
            CallbackUrlPath = redirectEndpointUrlPath
            Scope = defaultScope
            Log = log
        }

    member this.RedirectEndpointSitelet = this.sitelet

    member this.GetSettings (?ctx: Context, ?state, ?scope) =
        let baseUrl =
            match this.baseUrl with
            | Some x -> x
            | None ->
                match ctx with
                | Some ctx -> ctx.RequestUri.GetLeftPart(UriPartial.Authority)
                | None -> failwith "Need either a baseUrl or a context"
        ProviderInternals.makeSettings baseUrl this.guid state scope |> fst

    member this.GetAuthorizationRequestUrl(?ctx: Context, ?state, ?scope) =
        this.GetSettings(?ctx = ctx, ?state = state, ?scope = scope)
        |> GetAuthorizationRequestUrl

    member this.GetImplicitAuthorizationRequestUrl(?ctx: Context, ?state, ?scope) =
        this.GetSettings(?ctx = ctx, ?state = state, ?scope = scope)
        |> GetImplicitAuthorizationRequestUrl

    member this.GetSettings (baseUrl: string, ?state, ?scope) =
        ProviderInternals.makeSettings baseUrl this.guid state scope |> fst

    member this.GetAuthorizationRequestUrl(baseUrl: string, ?state, ?scope) =
        this.GetSettings(baseUrl, ?state = state, ?scope = scope)
        |> GetAuthorizationRequestUrl

    member this.GetImplicitAuthorizationRequestUrl(baseUrl: string, ?state, ?scope) =
        this.GetSettings(baseUrl, ?state = state, ?scope = scope)
        |> GetImplicitAuthorizationRequestUrl
