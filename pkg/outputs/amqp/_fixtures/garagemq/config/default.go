package config

const (
	dbBuntDB = "buntdb"
	dbBadger = "badger"
)

func Default() *Config {
	return &Config{
		Proto: "amqp-rabbit",
		Users: []User{
			{
				Username: "guest",
				Password: "084e0343a0486ff05530df6c705c8bb4", // guest md5 hash
			},
		},
		TCP: TCPConfig{
			IP:           "0.0.0.0",
			Port:         "5672",
			Nodelay:      false,
			ReadBufSize:  128 << 10, // 128Kb
			WriteBufSize: 128 << 10, // 128Kb
		},
		Admin: AdminConfig{
			IP:   "0.0.0.0",
			Port: "15672",
		},
		Queue: Queue{
			ShardSize:        8 << 10,      // 8k
			MaxMessagesInRAM: 10 * 8 << 10, // 10 buckets
		},
		Db: Db{
			DefaultPath: "db",
			Engine:      dbBadger,
		},
		Vhost: Vhost{
			DefaultPath: "/",
		},
		Security: Security{
			PasswordCheck: "md5",
		},
		Connection: Connection{
			ChannelsMax:  4096,
			FrameMaxSize: 65536,
		},
	}
}
