package main

import (
	"fmt"
	"encoding/base64"
)

func main(){

	fmt.Println(base64.StdEncoding.EncodeToString([]byte("{\"auths\":{\"index.boxlinker.com\":{\"auth\":\"ZGVtbzpqdXN0NGZ1bg==\"}}}")))
}
