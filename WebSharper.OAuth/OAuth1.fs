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
module WebSharper.OAuth.OAuth1

open System
open System.IO
open System.Net
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text
open WebSharper.OAuth.Utils

type Token =
    {
        Key : string
        Secret : string
    }

    override this.ToString() =
        "Key = " + this.Key + " Secret = " + this.Secret

type Signature =
    | PlainText
    | HMACSHA1
    | RSASHA1 of X509Certificate2

    override this.ToString() =
        match this with
        | PlainText _ -> "PLAINTEXT"
        | HMACSHA1 _ -> "HMAC-SHA1"
        | RSASHA1 _ -> "RSA-SHA1"

// settings names per RFC 5849
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

// out-of-band configuration - if callbacks cannot be received
let OutOfBandConfigration = "oob"

// protocol version
let Version = "1.0"

let makeAuthHeader parameters =
    "OAuth " + (
        parameters
        |> Seq.map (fun (k, v) -> sprintf "%s=\"%s\"" (encode k) (encode v))
        |> String.concat ","
    )

let makeTimestamp () = string <| floor (DateTime.UtcNow - DateTime(1970, 1, 1, 0, 0, 0, 0)).TotalSeconds

let makeNonce () = Guid.NewGuid().ToString().Substring(24)

let sign oauthSettings tokenSecret data =
    match oauthSettings.SignatureMethod with
    | PlainText ->
        (oauthSettings.ClientToken.Secret <&> tokenSecret) |> encode
    | HMACSHA1 ->
        let key = oauthSettings.ClientToken.Secret <&> tokenSecret
        use hashProvider = new HMACSHA1(Encoding.ASCII.GetBytes(key))
        hashProvider.ComputeHash(Encoding.ASCII.GetBytes(data : string)) |> Convert.ToBase64String
    | RSASHA1 cert ->
        use hashAlgorithm = SHA1.Create()
        let formatter = new RSAPKCS1SignatureFormatter(cert.PrivateKey)
        formatter.SetHashAlgorithm("SHA1")
        let hash = hashAlgorithm.ComputeHash(Encoding.ASCII.GetBytes(data))
        formatter.CreateSignature(hash) |> Convert.ToBase64String

let makeHeader (settings: OAuthSettings) uri httpMethod compositeSecret parameters =
    let headerParams =
        [
            "oauth_consumer_key", settings.ClientToken.Key
            "oauth_signature_method", settings.SignatureMethod.ToString()
            "oauth_nonce", makeNonce()
            "oauth_timestamp", makeTimestamp()
            "oauth_version", Version
        ]
        |> List.append parameters
    let baseString = makeBaseString httpMethod uri headerParams
    let signature = sign settings compositeSecret baseString
    let completeParams = ("oauth_signature", signature) :: headerParams
    makeAuthHeader completeParams

let makeTempCredentialsHeader (settings : OAuthSettings) =
    let parameters =
        [
            "oauth_callback", defaultArg settings.Callback OutOfBandConfigration
        ]
    makeHeader settings settings.RequestTokenEndpoint WebRequestMethods.Http.Post "" parameters

let makeTokenRequestHeader (settings : OAuthSettings) token tokenSecret verifier =
    let parameters =
        [
            "oauth_token", token
            "oauth_verifier", verifier
        ]
    makeHeader settings settings.AccessTokenEndpoint WebRequestMethods.Http.Post tokenSecret parameters

let makeCallHeader (settings : OAuthSettings) uri httpMethod token tokenSecret =
    let parameters =
        [
            "oauth_token", token
        ]
    makeHeader settings uri httpMethod tokenSecret parameters

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

let internal normalizeUriWithParams (uri: string) =
    match splitUriParams uri with
    | uri, [] -> uri
    | baseUri, queryParams ->
        let encPs = queryParams
                    |> Seq.map(fun (k, v) -> k + "=" + (encode v) )
                    |> String.concat "&"

        baseUri + "?" + encPs


let internal makeRequest authHeader uri httpMethod log =
    let normUri = normalizeUriWithParams uri
    let req = WebRequest.Create(requestUriString = normUri, Method = httpMethod)
    req.Headers.[HttpRequestHeader.Authorization] <- authHeader
    if httpMethod.ToUpper() = "POST" then // fix for Content-Length
        let reqStream = req.GetRequestStream()
        reqStream.Close()
    let response = req.GetResponse()
    use stream = response.GetResponseStream()
    use reader = new StreamReader(stream)
    let resp = reader.ReadToEnd()
    log (sprintf "%s %s\r\nAuthorization: %s\r\n-->\r\n%s" httpMethod normUri authHeader resp)
    resp

let internal ExtractOAuthTokenFromStr (str:string) =
    let values = str.Split('&')

    let tokenKey = values.[0].Split('=').[1]
    let tokenSecret = values.[1].Split('=').[1]

    {
        Key = WebUtility.UrlDecode tokenKey
        Secret = WebUtility.UrlDecode tokenSecret
    }

let internal ExtractParamsFromStr (str:string) =
    let pairs = str.Split('&')
                |> Seq.map (fun s -> (WebUtility.UrlDecode( s.Split('=').[0] ), WebUtility.UrlDecode( s.Split('=').[1] )))
                |> Seq.toList

    let tokenKey = pairs
                    |> List.pick (fun p -> if (fst p) = "oauth_token" then Some (snd p) else None)
    let tokenSecret = pairs
                        |> List.pick (fun p -> if (fst p) = "oauth_token_secret" then Some (snd p) else None)

    ( {
        Key = tokenKey
        Secret = tokenSecret
    } , pairs)

let GetOAuthRequestToken settings =
    let reqHeader = makeTempCredentialsHeader settings
    let reqRes = makeRequest reqHeader settings.RequestTokenEndpoint WebRequestMethods.Http.Post settings.Log

    ExtractOAuthTokenFromStr reqRes

let GetOAuthAccessTokenAndAll (paras: GetOAuthAccessTokenParams) =
    let tokenRequestHeader = makeTokenRequestHeader paras.Settings paras.RequestToken.Key paras.RequestToken.Secret paras.VerifierKey
    let reqRes = makeRequest tokenRequestHeader paras.Settings.AccessTokenEndpoint WebRequestMethods.Http.Post paras.Settings.Log

    ExtractParamsFromStr reqRes

let GetOAuthAccessToken (paras: GetOAuthAccessTokenParams) =
    fst (GetOAuthAccessTokenAndAll paras)

let CallOAuthService (paras: CallOAuthServiceParams) =
    let header = makeCallHeader paras.Settings paras.ServiceUri paras.HttpMethod paras.AccessToken.Key paras.AccessToken.Secret
    makeRequest header paras.ServiceUri paras.HttpMethod paras.Settings.Log
