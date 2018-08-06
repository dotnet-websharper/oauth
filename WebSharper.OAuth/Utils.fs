module internal WebSharper.OAuth.Utils

open System
open System.Web

let nonEncodedChars =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~"
    |> Set.ofSeq

let encode s =
    s
    |> String.collect (fun c ->
        if nonEncodedChars.Contains c
        then string c
        else String.Format("%{0:X2}", int c))

let normalizeUrl url =
    let uri = new Uri(url)
    let mutable normUrl = uri.Scheme + "://" + uri.Host
    if not ((uri.Scheme = "http" && uri.Port = 80) || (uri.Scheme = "https" && uri.Port = 443)) then
        normUrl <- normUrl + ":" + uri.Port.ToString()
    normUrl <- normUrl + uri.AbsolutePath
    normUrl

let normalizeUrlWithParams url ``params`` =
    let url = normalizeUrl url
    let sep = if url.Contains "?" then "&" else "?"
    let ``params`` =
        ``params``
        |> Seq.map (fun (name, value) -> name + "=" + encode value)
        |> String.concat "&"
    url + sep + ``params``

let (<&>) (a : string) (b : string) = a + "&" + b

let makeBaseString httpMethod (uri:string) parameters =
    let baseUri, queryParams =
        if not (uri.Contains "?")
            then (uri, [])
            else
                let b = uri.Split([|'?'|]).[0]
                let kvs = HttpUtility.ParseQueryString(uri.Substring(uri.IndexOf("?")))
                let ps = [ for key in kvs.AllKeys do
                            yield (key, kvs.[key]) ]
                (b, ps)
    let allParams = queryParams @ parameters
    let normUri = normalizeUrl baseUri
    httpMethod <&> encode normUri <&> (
        allParams // 3.4.1.3.2. Parameters Normalization
        |> Seq.sort // order by name (if names are equal - compare values)
        |> Seq.map (fun (k, v) -> k + "=" + encode v) // concat with encoded '='
        |> String.concat "&" // concat all with encoded '&'
        |> encode // encode name and value
    )
