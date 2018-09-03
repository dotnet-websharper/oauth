namespace WebSharper.OAuth2.Test

open WebSharper
open WebSharper.Sitelets
open WebSharper.UI
open WebSharper.UI.Server
open WebSharper.OAuth2.Test

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

    [<Website>]
    let Main = Site.Main Skin.WithTemplate

type Global() =
    inherit System.Web.HttpApplication()

    member g.Application_Start(sender: obj, args: System.EventArgs) =
        ()
