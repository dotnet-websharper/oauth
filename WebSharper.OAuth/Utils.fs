module internal WebSharper.OAuth.Utils

open System
open System.Collections.Generic
open System.Net
open System.Runtime.CompilerServices

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

let parseQueryString (s: string) =
#if NETSTANDARD
    Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(s)
#else
    System.Web.HttpUtility.ParseQueryString(s)
#endif

let splitUriParams (uri: string) =
    match uri.IndexOf '?' with
    | -1 -> uri, []
    | i ->
        let kvs = parseQueryString uri.[i+1..]
        uri.[..i-1], 
#if NETSTANDARD
        [
            for KeyValue(key, values) in kvs do
                for value in values do
                    yield (key, value)
        ]
#else
        [
            for key in kvs.AllKeys do
                yield key, kvs.[key]
        ]
#endif

let makeBaseString httpMethod (uri:string) parameters =
    let baseUri, queryParams = splitUriParams uri
    let allParams = queryParams @ parameters
    let normUri = normalizeUrl baseUri
    httpMethod <&> encode normUri <&> (
        allParams // 3.4.1.3.2. Parameters Normalization
        |> Seq.sort // order by name (if names are equal - compare values)
        |> Seq.map (fun (k, v) -> k + "=" + encode v) // concat with encoded '='
        |> String.concat "&" // concat all with encoded '&'
        |> encode // encode name and value
    )

[<Extension>]
type internal Extensions =
#if NETSTANDARD
    [<Extension>]
    static member TryGet(query: Dictionary<string, Microsoft.Extensions.Primitives.StringValues>, key: string) =
        match query.TryGetValue key with
        | true, x when x.Count >= 0 -> Some x.[0]
        | _ -> None
#else
    [<Extension>]
    static member TryGet(query: System.Collections.Specialized.NameValueCollection, key: string) =
        query.[key] |> Option.ofObj
#endif