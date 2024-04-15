- [[gitrepo]]
	- https://github.com/princeparmar/storx-new.git
	- https://github.com/StorX2-0/storxweb
	- https://github.com/StorX2-0/gateway-mt.git
	- https://github.com/kaiburns79/storx-frontend.git
- storx-upgrade
	- app.env is required `/Users/pradipparmar/Library/Application Support/Storj/Local-Network/app.env`
	- **setup command** is required with **clean database**. as it needs to add new field in database.
	- setup steps
		- clone storx-frontend repo from boris
		- clean all database and config
		- update app.config in "Local-Network"
		- install storx extension.
		- try for the upgrade option from UI and go till payment page.
		- from that copy address and complete payment through extension.
		- wait for completed status on payment page.
	- need to update duration values in `payments.go:1093`
		- change minutes to hour/24 to get days
		- after 23rd to 30th day user should get first email saying it will be expired on [date]
		- and after 30th day user should get email for expiration.
		- in `StartMonitoringUserProjects` loop use sleep for 24 hours
	- update email sender `payments.go:868`. in function `sendEmail`
- Need to setup
	- backend
	  collapsed:: true
		- storx-new [this will generate]
	- WebUI
	  collapsed:: true
		- build UI from storxweb
		- copy static files from go root, and build from
		  collapsed:: true
			- [run from storx] GOOS=js GOARCH=wasm go build -o ../storxweb/static/wasm/access.wasm ./satellite/console/wasm
			- [run from storxweb] cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" "./static/wasm"
- Setup process
	- when we deploy system on server we need to update localhost with server ip or hostname in storage node config and satellite config.
	- start storj-sim, auth, gateway-mt, link service
	- create database mystorx
	- storxweb > satellite path in satelite config > console.static-dir: /Users/pradipparmar/git/personal/storx/storxweb
	- linksharing config file "/Users/pradipparmar/Library/Application Support/Storj/Linksharing/config.yaml" #storx-imp
	-
	-
	-
	-
	- before linkshare run update path in linkshare config
	-
	- Open [localhost:10002](http://localhost:10002/)
- Server Setup
-
  ```bash
  authservice run      --allowed-satellites 12QDEFYUJt57ahN1rSuur36vk3L4DoPW9GrQznwsQAAVh55mV6n@stage7.storx.io:10000 --auth-token my-test-auth-token --endpoint https://stagegateway7.storx.io --listen-addr 78.129.184.74:80    --kv-backend badger://
  
  gateway-mt run	    	--auth.token my-test-auth-token 	 	  --auth.base-url https://stageauth7.storx.io 	  	 --domain-name stagegateway7.storx.io 	  	 --server.address stagegateway7.storx.io:80 	  	 --insecure-disable-tls
  
  linksharing setup --defaults dev --public-url https://stagels7.storx.io --address=":80" --auth-service.base-url https://stageauth7.storx.io --auth-service.token my-test-auth-token
  ```
- to cleanup
  collapsed:: true
	- storx config /Users/pradipparmar/Library/Application Support/Storj
	- remove postgres
- verify user from database => login psql with mystorx database and update user table =>
	-
	  ```sql
	  UPDATE "satellite/0".users SET status = 1 WHERE email = 'prince.soamedia@gmail.com';
	  SELECT * FROM "satellite/0".users ;
	  ```
- if **allowed satellite** is not working then try using 127.0.0.1 instead of localhost
- satellite config in ubuntu => `/home/ubuntu/.local/share/storj/local-network/storagenode`
