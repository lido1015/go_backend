package main

import (
	"flag"
	"net/http"
	"strings"

	"github.com/NODO-UH/gestion-go/src/api"
	"github.com/NODO-UH/gestion-go/src/auth"
	"github.com/NODO-UH/gestion-go/src/conf"
	"github.com/NODO-UH/gestion-go/src/database"
	_ "github.com/NODO-UH/gestion-go/src/docs"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"     // swagger embed files
	ginSwagger "github.com/swaggo/gin-swagger" // gin-swagger middleware
)

var (
	confPath    *string
	usageHTTP   *bool
	developMode *bool
)

func init() {
	confPath = flag.String("conf", ".", "path to the folder with the configuration file (sic-conf.yaml)")
	usageHTTP = flag.Bool("http", false, "disable http")
	developMode = flag.Bool("develop", false, "run in develop mode")
	flag.Parse()
}

// @title Gestion UH API
// @version 1.0
// @description Gestion UH API service for centralized user administration
// @contact.email nodo@uh.cu
// @host identity.sic.uh.cu
// @schemes http https

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization

func main() {
	// Init configuration
	conf.InitConfiguration(*confPath)

	// Start MongoDB connection
	database.ConnectProxyDatabase(conf.Configuration.Databases.Proxy.Uri, "gestion-go")

	// Start ManagementDB connection
	database.ConnectManagementDatabase(conf.Configuration.Databases.Management.Uri, "management-db")

	// Start Gin server REST API
	if !*developMode {
		gin.SetMode(gin.ReleaseMode)
	}
	server := gin.New()
	server.Use(gin.Logger())
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowHeaders = append(config.AllowHeaders, "Authorization")
	server.Use(cors.New(config))

	server.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	server.GET("/securityquestions", api.GetSecurityQuestions)
	server.GET("/user/securityquestions", api.GetUserSecurityQuestions)
	authGroup := server.Group("/auth")
	{
		authGroup.POST("/login", api.Login)
		authGroup.POST("/refresh", api.Refresh)
		authGroup.POST("/signup", api.SignUp)
		authGroup.POST("/resetpassword", api.ResetPassword)
	}
	proxy := server.Group("/proxy")
	{
		proxy.Use(AuthorizeJWT())
		proxy.GET("/quota", api.ProxyQuota)
	}

	email := server.Group("/email")
	{
		email.Use(AuthorizeJWT())
		email.GET("/quota", api.EmailQuota)
	}

	server.GET("/user/search", api.Search)
	user := server.Group("/user")
	{
		user.Use(AuthorizeJWT())
		user.POST("/changepassword", api.ChangePassword)
		user.GET("/me", api.Me)
		user.GET("/getVPN", api.GetVPN)

	}

	admin := server.Group("/admin")
	{
		admin.Use(AuthorizeJWT())
		admin.Use(CheckPermissions())
		admin.GET("/roles", api.GetRoles)
		admin.POST("/user/reset", api.ResetUser)
		admin.GET("/user", api.GetUserInfo)
		admin.POST("/user/role", api.SetUserRole)
		admin.POST("/user/changepassword", api.ForceChangePassword)
		admin.POST("/user/changeEmail", api.ChangeUserEmail)
		admin.POST("/user/createVPN", api.CreateVPN)
		admin.POST("/user/deleteVPN", api.DeleteVPN)
		admin.POST("/user/enableVPN", api.EnableVPN)
		admin.POST("/user/disableVPN", api.DisableVPN)
		admin.GET("/user/statusVPN", api.StatusVPN)
		admin.PATCH("/user/editServices", api.EditServicesStatus)
		admin.POST("/user/block", api.BlockUser)
		admin.POST("/user/unblock", api.UnblockUser)
		admin.POST("/reset/workers", api.ResetWorkers)
	}

	if *usageHTTP {
		if err := server.Run(":8080"); err != nil {
			panic(err)
		}
	} else if err := server.RunTLS(":8080", "cert.pem", "key.pem"); err != nil {
		panic(err)
	}
}

func AuthorizeJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		const BearerSchema = "Bearer "
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || len(BearerSchema) >= len(authHeader) {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimPrefix(authHeader, BearerSchema)
		_, claims, err := auth.ValidateToken(tokenString)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("jwtClaims", claims)
	}
}

func CheckPermissions() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Get JWT claims from context
		ctxJwtClaims, exists := ctx.Get("jwtClaims")
		if !exists {
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		// Cast to JWT claims
		jwtClaims, ok := ctxJwtClaims.(*auth.JwtClaims)
		if !ok {
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		// Get user roles from database
		role, err := database.Management.GetUserRole(jwtClaims.User, true)
		if err != nil {
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		// Reutrn StatusUnauthorized if user has no permissions
		if role == nil {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		// Check if user has permissions to access the requested resource
		if !api.HaveAccess(ctx.FullPath(), role.Permissions) {
			ctx.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}
