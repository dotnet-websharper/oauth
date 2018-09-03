namespace WebSharper.OAuth2.Test.AspNetCore

open System
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Hosting
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Configuration
open Microsoft.Extensions.DependencyInjection
open WebSharper.AspNetCore

type Startup() =

    member this.ConfigureServices(services: IServiceCollection) =
        services.AddAuthentication("WebSharper")
            .AddCookie("WebSharper", fun options -> ())
        |> ignore

    member this.Configure(app: IApplicationBuilder, env: IHostingEnvironment) =
        if env.IsDevelopment() then app.UseDeveloperExceptionPage() |> ignore

        let config =
            ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json")
                .Build()

        app.UseAuthentication()
            .UseStaticFiles()
            .UseWebSharper(env, Site.Main, config.GetSection("websharper"))
            .Run(fun context ->
                context.Response.StatusCode <- 404
                context.Response.WriteAsync("Page not found"))
