package authz

import (
	"bytes"
	"fmt"
	"github.com/docker/docker/pkg/authorization"
	"github.com/docker/docker/runconfig"
	"os"
	"strings"
	"testing"
	"path/filepath"
)

func TestJson(t *testing.T) {
	byt := []byte(`{"Hostname":"naranderan.r","HostConfig":{"PublishAllPorts":true,"Binds":["/home/local/ZOHOCORP/deepak-3386/Documents/ZohoCode/workspace/2000000000041/2000000000043/2000000014001/workspace:/home/workspace"],"Memory":1073741824,"CpuPeriod":100000,"PidsLimit":1000,"CpuQuota":100000,"CpusetCpus":"1"},"Tty":true,"Image":"cmtools.csez.zohocorpin.com:5000/cide/go","Env":["GROUPID=618136065","TZ=Asia/Calcutta","USERID=618149802"]}`)
	authreq := &authorization.Request{RequestMethod: "GET", RequestURI: "/v1.21/version", User: "user_1", RequestBody: byt}
	decoder := runconfig.ContainerDecoder{}
	config, hostConfig, networkingConfig, err := decoder.DecodeConfig(bytes.NewReader(authreq.RequestBody))
	fmt.Println("config :", config, " hostConfig: ", hostConfig, " networkingConfig: ", networkingConfig, err)
	for _, bind := range hostConfig.Binds {
		mounts := strings.Split(bind, ":")
		host := mounts[0]
		container := mounts[1]
		fmt.Println("host ", host, " container ", container)
	}
}

func TestSymlink(t *testing.T) {
	path := "/home/local/ZOHOCORP/deepak-3386/todel/symlinktest/workspace/project/src/java/com/zoho/CircularLink"
	fmt.Println(filepath.EvalSymlinks(path))
}

func TestPaths(t *testing.T) {
	path := "/home/local/ZOHOCORP/deepak-3386/todel/symlinktest/workspace/project/src/java/com/zoho/"
	cleanPath, err := os.Lstat(path)
	if err != nil {
		panic(err)
	}
	fmt.Println(cleanPath.Mode())
}
