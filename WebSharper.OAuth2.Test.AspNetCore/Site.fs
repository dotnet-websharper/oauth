namespace WebSharper.OAuth2.Test.AspNetCore

open WebSharper
open WebSharper.Sitelets
open WebSharper.UI
open WebSharper.UI.Server

type Endpoint =
    | [<EndPoint "/">] Home
    | [<EndPoint "/oauth">] OAuth
    | [<EndPoint "/logout">] Logout

module Skin =
    type MainTemplate = Templating.Template<"Main.html">

    let WithTemplate (title: string) (body: Context<Endpoint> -> Async<#seq<Doc>>) ctx =
        async {
            let! body = body ctx
            return! Content.Page(
                MainTemplate()
                    .Title(title)
                    .Body(body :> seq<Doc>)
                    .Doc()
            )
        }

module Site =
    open System
    open System.Net
    open System.IO
    open WebSharper.OAuth
    open WebSharper.UI.Html

    let json = WebSharper.Core.Json.Provider.Create()

    module Google =
        type Response = { id: string; email: string; name: string; picture: string }

        let id = Environment.GetEnvironmentVariable "GOOGLE_CLIENT_ID"
        let secret = Environment.GetEnvironmentVariable "GOOGLE_CLIENT_SECRET"
        let OAuthSettings = OAuth2.ServiceSettings.Google(id, secret)

    let GoogleProvider =
        OAuth2.Provider.Setup(
            redirectEndpointAction = Endpoint.OAuth,
            service = Google.OAuthSettings,
            redirectEndpoint = (fun ctx -> function
                | OAuth2.AuthenticationResponse.ImplicitSuccess ->
                    Content.Text("Implicit token not supported")
                    |> Content.SetStatus Http.Status.InternalServerError
                | OAuth2.AuthenticationResponse.Error err ->
                    Content.Page(
                        Body =
                            [
                                yield h1 [] [text "Authentication"]
                                yield p [] [text (defaultArg err.Message "Unknown error")]
                                if err.Description.IsSome then
                                    yield p [] [text err.Description.Value]
                                yield p [] [a [attr.href (ctx.Link Endpoint.Home)] [text "Back"]]
                            ])
                | OAuth2.AuthenticationResponse.Success token -> async {
                    do! ctx.UserSession.LoginUser(token.Token, false)
                    return! Content.RedirectTemporary Endpoint.Home
                }),
            defaultScope = "email profile"
        )

    let HomePage =
        Skin.WithTemplate "HomePage" <| fun ctx -> async {
            let! loggedIn = ctx.UserSession.GetLoggedInUser()
            match loggedIn with
            | None ->
                let loginUrl = GoogleProvider.GetAuthorizationRequestUrl(ctx)
                return [
                    h1 [] [text "Not logged in."]
                    p [] [a [attr.href loginUrl] [text "Log in"]]
                ]
            | Some loggedIn ->
                let token : OAuth2.AuthenticationToken = { Token = loggedIn; State = None }
                let req =
                    HttpWebRequest.Create("https://www.googleapis.com/userinfo/v2/me")
                    :?> HttpWebRequest
                req.KeepAlive <- false
                req.UserAgent <- "WebSharper.OAuth.OAuth2 Test"
                token.AuthorizeRequest req
                try
                    let! resp = req.AsyncGetResponse()
                    use reader = new StreamReader(resp.GetResponseStream())
                    let resp = reader.ReadToEnd()
                    try
                        let resp =
                            resp
                            |> WebSharper.Core.Json.Parse
                            |> json.GetDecoder<Google.Response>().Decode
                        return [
                            h1 [] [text ("Welcome " + resp.name + "!")]
                            img [attr.src resp.picture] []
                            p [] [a [attr.href (ctx.Link Endpoint.Logout)] [text "Log out"]]
                        ]
                    with e ->
                        return [
                            h1 [] [text "Failed to parse response:"]
                            p [] [text resp]
                        ]
                with :? System.Net.WebException as e ->
                    use reader = new StreamReader(e.Response.GetResponseStream())
                    let resp = reader.ReadToEnd()
                    return [
                        h1 [] [text "Failed to retrieve your user data"]
                        p [] [text resp]
                    ]
        }

    let LogoutPage (ctx: Context<Endpoint>) = async {
        do! ctx.UserSession.Logout()
        return! Content.RedirectTemporary Endpoint.Home
    }

    [<Website>]
    let Main =
        GoogleProvider.RedirectEndpointSitelet
        <|>
        Application.MultiPage (fun ctx endpoint ->
            match endpoint with
            | Endpoint.Home -> HomePage ctx
            | Endpoint.Logout -> LogoutPage ctx
            | Endpoint.OAuth -> failwith "OAuth endpoint should be handled by GoogleProvider"
        )
