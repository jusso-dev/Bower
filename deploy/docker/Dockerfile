FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet restore Bower.sln
RUN dotnet publish src/Bower.Collector/Bower.Collector.csproj \
    --configuration Release \
    --no-restore \
    --output /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app .
COPY policies ./policies
RUN mkdir -p /var/lib/bower /var/spool/bower \
    && chown -R 1654:1654 /app /var/lib/bower /var/spool/bower
USER 1654
ENV BOWER_LISTEN_URL=http://0.0.0.0:4319
ENV BOWER_QUEUE_PATH=/var/lib/bower/queue.db
ENV BOWER_POLICY_DIRECTORY=/app/policies/default
EXPOSE 4319
VOLUME ["/var/lib/bower", "/var/spool/bower"]
ENTRYPOINT ["dotnet", "Bower.Collector.dll"]
