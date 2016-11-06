package keygen

import (
	"github.com/vmykh/infosec/lab2/rsautils"
)

const KeyDir = "/home/vmykh/myapps/go/src/github.com/vmykh/infosec/lab2/keystorage/"

func main()  {
	clientKey := rsautils.GenerateKey();
	serverKey := rsautils.GenerateKey();
	trentKey := rsautils.GenerateKey();
	timeserverKey := rsautils.GenerateKey();


	rsautils.SaveGobKey(KeyDir + "client/client-private.key", clientKey);
	rsautils.SaveGobKey(KeyDir + "client/client-public.key", clientKey.PublicKey);
	rsautils.SaveGobKey(KeyDir + "client/trent-public.key", trentKey.PublicKey);
	rsautils.SaveGobKey(KeyDir + "client/timeserver-public.key", timeserverKey.PublicKey);

	rsautils.SaveGobKey(KeyDir + "server/server-private.key", serverKey);
	rsautils.SaveGobKey(KeyDir + "server/server-public.key", serverKey.PublicKey);
	rsautils.SaveGobKey(KeyDir + "server/trent-public.key", trentKey.PublicKey);
	rsautils.SaveGobKey(KeyDir + "server/timeserver-public.key", timeserverKey.PublicKey);

	rsautils.SaveGobKey(KeyDir + "trent/trent-private.key", trentKey);
	rsautils.SaveGobKey(KeyDir + "trent/trent-public.key", trentKey.PublicKey);
	rsautils.SaveGobKey(KeyDir + "trent/client-public.key", clientKey.PublicKey);
	rsautils.SaveGobKey(KeyDir + "trent/server-public.key", serverKey.PublicKey);
	rsautils.SaveGobKey(KeyDir + "trent/timeserver-public.key", timeserverKey.PublicKey);

	rsautils.SaveGobKey(KeyDir + "timeserver/timeserver-private.key", timeserverKey);
	rsautils.SaveGobKey(KeyDir + "timeserver/timeserver-public.key", timeserverKey.PublicKey);
}

