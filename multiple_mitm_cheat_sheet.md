----------------------------------------------------------------
add to /usr/local/etc/nginx/nginx.conf
`include /usr/local/etc/nginx/proxy-gateway;`


----------------------------------------------------------------
touch a new file: /usr/local/etc/nginx/proxy-gateway
```
stream {
    server {
        listen 8090;

        #TCP traffic will be proxied to the "proxy_backend" upstream group
        proxy_pass proxy_backend;

        proxy_buffer_size 256k;  # Optimize buffer sizes based on traffic
        #proxy_buffers 4 128k;
        proxy_timeout 30s;
        proxy_connect_timeout 30s;
        proxy_socket_keepalive on;        
    }

    upstream proxy_backend {
        # ip_hash does not work here; using round robin for now
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
        #server 127.0.0.1:8083;
        #server 127.0.0.1:8084;

   }
}
```


----------------------------------------------------------------
mitmdump --mode regular@8081 -s script.py &
mitmdump --mode regular@8082 -s script.py &
mitmdump --mode regular@8083 -s script.py &
mitmdump --mode regular@8084 -s script.py &


----------------------------------------------------------------
mitmdump --mode regular@8081 -s ../mitm-web-cache/script.py -vvv  > ../mitm-web-cache/out.txt



----------------------------------------------------------------
env/bin/pip install -e ".[dev]"