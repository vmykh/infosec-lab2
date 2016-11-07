package keygen

import (
	"github.com/vmykh/infosec/lab2/rsautils"
	"os"
)

func GenerateAndSaveKeys()  {
	clientKey := rsautils.GenerateKey();
	serverKey := rsautils.GenerateKey();
	trentKey := rsautils.GenerateKey();
	timeserverKey := rsautils.GenerateKey();


	rsautils.SaveGobKey(GetKeyDir() + "/client/client-private.key", clientKey);
	rsautils.SaveGobKey(GetKeyDir() + "/client/client-public.key", clientKey.PublicKey);
	rsautils.SaveGobKey(GetKeyDir() + "/client/trent-public.key", trentKey.PublicKey);
	rsautils.SaveGobKey(GetKeyDir() + "/client/timeserver-public.key", timeserverKey.PublicKey);

	rsautils.SaveGobKey(GetKeyDir() + "/server/server-private.key", serverKey);
	rsautils.SaveGobKey(GetKeyDir() + "/server/server-public.key", serverKey.PublicKey);
	rsautils.SaveGobKey(GetKeyDir() + "/server/trent-public.key", trentKey.PublicKey);
	rsautils.SaveGobKey(GetKeyDir() + "/server/timeserver-public.key", timeserverKey.PublicKey);

	rsautils.SaveGobKey(GetKeyDir() + "/trent/trent-private.key", trentKey);
	rsautils.SaveGobKey(GetKeyDir() + "/trent/trent-public.key", trentKey.PublicKey);
	rsautils.SaveGobKey(GetKeyDir() + "/trent/client-public.key", clientKey.PublicKey);
	rsautils.SaveGobKey(GetKeyDir() + "/trent/server-public.key", serverKey.PublicKey);
	rsautils.SaveGobKey(GetKeyDir() + "/trent/timeserver-public.key", timeserverKey.PublicKey);

	rsautils.SaveGobKey(GetKeyDir() + "timeserver/timeserver-private.key", timeserverKey);
	rsautils.SaveGobKey(GetKeyDir() + "timeserver/timeserver-public.key", timeserverKey.PublicKey);
}

func GetKeyDir() string {
	cwd, err := os.Getwd();
	if err != nil {
		panic(err)
	}

	return cwd + "/keystorage"
}

