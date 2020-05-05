package options

import "github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"

// SessionOptions contains configuration options for the SessionStore providers.
type SessionOptions struct {
	Type              string             `flag:"session-store-type" cfg:"session_store_type" env:"OAUTH2_PROXY_SESSION_STORE_TYPE"`
	CompressedSession bool               `flag:"session-store-compression" cfg:"session_store_compression" env:"OAUTH2_PROXY_SESSION_STORE_COMPRESSION"`
	CompressionLevel  int                `flag:"session-store-compression-level" cfg:"session_store_compression_level" env:"OAUTH2_PROXY_SESSION_STORE_COMPRESSION_LEVEL"`
	Cipher            *encryption.Cipher `cfg:",internal"`
	Redis             RedisStoreOptions  `cfg:",squash"`
}

// CookieSessionStoreType is used to indicate the CookieSessionStore should be
// used for storing sessions.
var CookieSessionStoreType = "cookie"

// RedisSessionStoreType is used to indicate the RedisSessionStore should be
// used for storing sessions.
var RedisSessionStoreType = "redis"

// RedisStoreOptions contains configuration options for the RedisSessionStore.
type RedisStoreOptions struct {
	ConnectionURL          string   `flag:"redis-connection-url" cfg:"redis_connection_url" env:"OAUTH2_PROXY_REDIS_CONNECTION_URL"`
	UseSentinel            bool     `flag:"redis-use-sentinel" cfg:"redis_use_sentinel" env:"OAUTH2_PROXY_REDIS_USE_SENTINEL"`
	SentinelMasterName     string   `flag:"redis-sentinel-master-name" cfg:"redis_sentinel_master_name" env:"OAUTH2_PROXY_REDIS_SENTINEL_MASTER_NAME"`
	SentinelConnectionURLs []string `flag:"redis-sentinel-connection-urls" cfg:"redis_sentinel_connection_urls" env:"OAUTH2_PROXY_REDIS_SENTINEL_CONNECTION_URLS"`
	UseCluster             bool     `flag:"redis-use-cluster" cfg:"redis_use_cluster" env:"OAUTH2_PROXY_REDIS_USE_CLUSTER"`
	ClusterConnectionURLs  []string `flag:"redis-cluster-connection-urls" cfg:"redis_cluster_connection_urls" env:"OAUTH2_PROXY_REDIS_CLUSTER_CONNECTION_URLS"`
	CAPath                 string   `flag:"redis-ca-path" cfg:"redis_ca_path" env:"OAUTH2_PROXY_REDIS_CA_PATH"`
	InsecureSkipTLSVerify  bool     `flag:"redis-insecure-skip-tls-verify" cfg:"redis_insecure_skip_tls_verify" env:"OAUTH2_PROXY_REDIS_INSECURE_SKIP_TLS_VERIFY"`
}
