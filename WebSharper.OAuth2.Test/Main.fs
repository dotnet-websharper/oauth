namespace WebSharper.OAuth2.Test

open WebSharper.Html.Server
open WebSharper
open WebSharper.Sitelets

type Endpoint =
    | Home
    | OAuth
    | Logout

module Skin =
    open System.Web

    type Page =
        {
            Title : string
            Body : list<Element>
        }

    let MainTemplate =
        Content.Template<Page>("~/Main.html")
            .With("title", fun x -> x.Title)
            .With("body", fun x -> x.Body)

    let WithTemplate title body (context: Context<_>) =
        Content.WithTemplateAsync MainTemplate <| async {
            let! body = body context
            return {
                Title = title
                Body = body
            }
        }

module Site =

    open System
    open System.Net
    open System.IO
    open WebSharper.OAuth

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
                                yield H1 [Text "Authentication"]
                                yield P [Text (defaultArg err.Message "Unknown error")]
                                if err.Description.IsSome then
                                    yield P [Text err.Description.Value]
                                yield P [A [HRef (ctx.Link Endpoint.Home)] -< [Text "Back"]]
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
                    H1 [Text "Not logged in."]
                    P [A [HRef loginUrl] -< [Text "Log in"]]
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
                            H1 [Text ("Welcome " + resp.name + "!")]
                            Img [Src resp.picture]
                            P [A [HRef (ctx.Link Endpoint.Logout)] -< [Text "Log out"]]
                        ]
                    with e ->
                        return [
                            H1 [Text "Failed to parse response:"]
                            P [Text resp]
                        ]
                with :? System.Net.WebException as e ->
                    use reader = new StreamReader(e.Response.GetResponseStream())
                    let resp = reader.ReadToEnd()
                    return [
                        H1 [Text "Failed to retrieve your user data"]
                        P [Text resp]
                    ]
        }

    let LogoutPage (ctx: Context<Endpoint>) = async {
        do! ctx.UserSession.Logout()
        return! Content.RedirectTemporary Endpoint.Home
    }

    let Main =
        Sitelet.Sum [
            Sitelet.Content "/" Home HomePage
            Sitelet.Content "/logout" Logout LogoutPage
            GoogleProvider.RedirectEndpointSitelet
        ]

[<Sealed>]
type Website() =
    interface IWebsite<Endpoint> with
        member this.Sitelet = Site.Main
        member this.Actions = []

type Global() =
    inherit System.Web.HttpApplication()

    member g.Application_Start(sender: obj, args: System.EventArgs) =
        ()

[<assembly: Website(typeof<Website>)>]
do ()
