module WebSharper.OAuth.OAuth1.Tests

open System
open System.IO
open System.Net
open System.Web

let cert =
    Path.Combine(__SOURCE_DIRECTORY__, "testcert.pfx")

module Twitter =
    let key = Environment.GetEnvironmentVariable "TWITTER_CLIENT_ID"
    let secret = Environment.GetEnvironmentVariable "TWITTER_CLIENT_SECRET"
    let settings = {
        ClientToken = { Key = key; Secret = secret }
        RequestTokenEndpoint = "https://api.twitter.com/oauth/request_token"
        AuthorizeTokenEndpoint = "https://api.twitter.com/oauth/authorize"
        AccessTokenEndpoint = "https://api.twitter.com/oauth/access_token"
        SignatureMethod = Signature.HMACSHA1
        Callback = None
        Log = ignore
        }

module OAuthTestServer = 
    let private template = {
        ClientToken = { Key = "key"; Secret = "secret" }
        RequestTokenEndpoint = "http://term.ie/oauth/example/request_token.php"
        AuthorizeTokenEndpoint = ""
        AccessTokenEndpoint = "http://term.ie/oauth/example/access_token.php"
        SignatureMethod = Unchecked.defaultof<_>
        Callback = None
        Log = ignore
        }

    let plaintext = { template with SignatureMethod = Signature.PlainText }
    let hmacsha1 = { template with SignatureMethod = Signature.HMACSHA1 }
    let rsasha1 = 
        let cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(cert, "123")
        { template with SignatureMethod = Signature.RSASHA1 cert }

let runTest settings callUri = 
    let reqToken = GetOAuthRequestToken settings
    printfn "%s" (reqToken.ToString())

    if callUri <> "" then
        let authUri = sprintf "%s?oauth_token=%s" settings.AuthorizeTokenEndpoint reqToken.Key
        System.Diagnostics.Process.Start("iexplore.exe", authUri) |> ignore

        printfn "Input verifier"
        let verifier = System.Console.ReadLine()
    

        //let accessToken = OAuthService.GetOAuthAccessToken { Settings = settings; RequestToken = reqToken; VerifierKey = verifier }
        //printfn "%s" (accessToken.ToString())
//
//        let resp = OAuthService.CallOAuthService { Settings = settings; AccessToken = accessToken; HttpMethod = "GET"; ServiceUri = callUri }
//        printfn "%s" resp

        let accessTokenAll = GetOAuthAccessTokenAndAll { Settings = settings; RequestToken = reqToken; VerifierKey = verifier }
        printfn "%s" (accessTokenAll.ToString())

//runTest OAuthTestServer.plaintext ""
//runTest OAuthTestServer.hmacsha1 ""
//runTest OAuthTestServer.rsasha1 ""
//runTest Twitter.settings "http://api.twitter.com/1/statuses/retweeted_to_me.json"
