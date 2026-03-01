FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY ["Idenrya.Server.csproj", "./"]
RUN dotnet restore "Idenrya.Server.csproj"

COPY . .
RUN dotnet publish "Idenrya.Server.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

COPY --from=build /app/publish .

ENV ASPNETCORE_URLS=https://+:3000
EXPOSE 3000

ENTRYPOINT ["dotnet", "Idenrya.Server.dll"]
