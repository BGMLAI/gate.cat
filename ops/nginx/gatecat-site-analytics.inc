# Include these directives inside the gate.cat server block.
access_log /var/log/nginx/gate.cat.access.log gatecat_access;

location = /events {
    access_log /var/log/nginx/gate.cat.events.log gatecat_events;
    add_header Cache-Control "no-store" always;
    add_header Access-Control-Allow-Origin "https://gate.cat" always;
    return 204;
}
