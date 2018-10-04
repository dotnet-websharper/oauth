// $begin{copyright}
//
// This file is part of WebSharper
//
// Copyright (c) 2008-2018 IntelliFactory
//
// Licensed under the Apache License, Version 2.0 (the "License"); you
// may not use this file except in compliance with the License.  You may
// obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.  See the License for the specific language governing
// permissions and limitations under the License.
//
// $end{copyright}
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
