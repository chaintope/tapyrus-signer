Sample init scripts and service configuration for tapyrus-signerd
==================================================================

Sample script is in `contrib/init`.

How to setup on Cent OS
------------------------------------------------------------------

1. Build and install tapyrus signer

```
$ cargo build --release
$ sudo cp target/release/tapyrus-signerd /usr/bin/
```

2. Put init file

```
$ sudo cp contrib/init/tapyrus-signerd.init /etc/init.d/
$ sudo chmod 755 /etc/init.d/tapyrus-signerd
$ sudo chkconfig --add tapyrus-signerd
$ sudo chkconfig tapyrus-signerd on
``` 

3. Put config file

Put your config file into `/etc/tapyrus/tapyrus-signer.toml`. You can find example of config file in `tests/resources/signer_config_sample.toml`.

Then put below in `/etc/sysconfig/tapyrus-signerd`
```
TAPYRUS_SIGNERD_OPTS="-c /etc/tapyrus/tapyrus-signer.toml --skip-waiting-ibd" 
```

4. Start service

```
$ sudo service tapyrus-signerd start
``` 
