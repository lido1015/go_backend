# gestion-go

- [gestion-go](#gestion-go)
  - [Dependencies](#dependencies)
    - [Go](#go)
    - [Make](#make)
    - [Swag](#swag)
    - [Upx](#upx)
    - [Private dependencies](#private-dependencies)
  - [Swagger documentation](#swagger-documentation)
  - [Build](#build)
  - [Docker build](#docker-build)
  - [Run](#run)
    - [JSON configuration file](#json-configuration-file)
    - [HTTPS](#https)

## Dependencies

### Go

https://golang.org/doc/install

### Make

```
sudo apt install make
```

### Swag

```
go get -u github.com/swaggo/swag/cmd/swag
```

> Check that `$GOPATH/bin` is in the `PATH`. For know the `GOPATH`, run `go env | grep GOPATH`.

### Upx

```
sudo apt install upx
```

### Private dependencies

Some project dependencies are a private repository, for example: `github.com/NODO-UH/mongo-manager`. So you need to give it access to the private repository to get it, `go get` uses `git` in the background, so all you need is to configure `git` to access the private repository without password being required. For that you need to do:

1. Generate an access token in your GitHub profile
2. Change your global git configuration for access with that token, i recommend the command:
```shell
git config --global url."https://[username]:[token]@github.com".insteadOf "https://github.com"
```
> This configuration affect your global configuration, but can be overwritten with local project configuration, take care about that.
3. Test your configuration running `go get ./...` in your project root.

## Swagger documentation

For generate Swagger documentation run `make doc`. This have dependency with `swag` command.

## Build

For build project run command:

```shell
make build
```

This generate a binary with name `gestion.bin` in your project root directory.

## Docker build

The Dockerfile `Docker/Dockerfile` build a image with a project build, at `/go/gestion-go/gestion.bin` inside the container. This Dockerfile needs **BuildKit** (for mor information see [Build images with BuildKit](https://docs.docker.com/develop/develop-images/build_enhancements/) in Docker documentation), for build image run the command:

```shell
DOCKER_BUILDKIT=1 docker build --no-cache --secret id=github-token,src=[file with github token] -t gestion-go .
```

> * The github user is stdevAdrianPaez, so for now github-token is only accessible for him

## Run

Once the binary is generated, you need add some configuration files to properly execution. All configuration is loaded with the execution arguments:

- `--conf [path]` specifies the path to the JSON configuration file. If not specified, look for the file `config.json`.
- `--http` disables https and runs without encryption over HTTP. If not specified, it runs over HTTPS.
- `--develop` enables development mode. If not specified, it runs in production mode.

### JSON configuration file

```JSON
{
    "ldap": {
        "addr": "10.6.141.41:389",
        "ous": [
            "estudiante",
            "trabajador"
        ],
        "adminUID": "cn=admin,dc=uh,dc=cu",
        "adminPassword": "[password]"
    },
    "dbUri": "mongodb://[user]:[password]@[host]:[port]",
    "managementUri": "mongodb://[user]:[password]@[host]:[port]",
    "emailMatch": [
        {
            "ou": "estudiante",
            "address": "correo.estudiantes.uh.cu"
        },
        {
            "ou": "trabajador",
            "address": "correo.uh.cu"
        }
    ],
    "emailServiceKey": "[SECRET]",
    "securityQuestionsCount": 3
}
```

### HTTPS

For default, project runs in HTTPS mode, except that is runed with --http flag. For HTTPS binaty need files `cert.pem` and `key.pem`, in same directory of binary.
