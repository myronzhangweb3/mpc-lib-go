package main

import (
	"context"
	"fmt"
	"net/http"
	"okx-threshold-lib-demo/ecdsa_threshold/web_server/server/global"
	"okx-threshold-lib-demo/ecdsa_threshold/web_server/server/internal"
	"os"
	"os/signal"
	"path/filepath"
	"time"
)

var (
	err error
)

func main() {

	port := "8080"
	if len(os.Args) == 2 {
		port = os.Args[1]
	}

	global.RootDir, err = os.Getwd()
	if err != nil {
		panic(err)
	}
	global.RootDir = filepath.Join(global.RootDir, "key")
	fmt.Println("Key root dir: " + global.RootDir)

	engine := internal.NewRouter()
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: engine,
	}
	go func() {
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			fmt.Sprintf("Gin server start error: %s\n", err.Error())
			panic(err.Error())
		}
	}()
	fmt.Println(fmt.Sprintf("Server Listen: http://0.0.0.0:%v", port))
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		fmt.Sprintf("Gin server stop error: %s\n", err.Error())
	}
	fmt.Println("genofusion server shutdown!")
}
