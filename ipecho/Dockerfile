# 跨平台交叉编译：build 阶段永远跑在构建机原生架构上($BUILDPLATFORM),
# 用 Go 自带的 GOOS/GOARCH 交叉编译出目标架构静态二进制——不走 QEMU 模拟,快。
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /ipecho .

# 运行镜像：scratch + 静态二进制,几 MB,无 shell 无包管理,攻击面最小。
FROM scratch
COPY --from=build /ipecho /ipecho
EXPOSE 8080
USER 65534:65534
ENTRYPOINT ["/ipecho"]
