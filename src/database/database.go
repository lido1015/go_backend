package database

var (
	Proxy      *ProxyManager
	Management *ManagementManager
)

func ConnectProxyDatabase(dbURI, id string) {
	manager, err := InitializeProxyManager(dbURI, id)
	if err != nil {
		panic(err)
	}
	Proxy = manager
}

func ConnectManagementDatabase(dbURI, id string) {
	manager, err := InitializeManagementManager(dbURI, id, false)
	if err != nil {
		panic(err)
	}
	Management = manager
}
