package com.coderepojon.dbPostgres.services.impl;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;
import java.util.Objects;

@Slf4j
@Service
public class IpInfoService {

    private final RestTemplate rest;

    public IpInfoService(RestTemplateBuilder builder) {
        this.rest = builder.build();
    }

    public record IpDetails(String ip, String city, String region, String country_name, Double latitude, Double longitude, String timezone, String org, Boolean proxy, Map<String, Objects> raw) {}

    public IpDetails lookup(String ip) {
        try {
            String url ="https://ipapi.co/" + ip + "/json/"; // simple example;
            ResponseEntity<Map> response = rest.getForEntity(url, Map.class);
            Map body = response.getBody();
            if (body == null) return null;

//            log.info("IpDetails > " + response.toString());
            Double latitude = body.get("latitude") != null ? Double.valueOf(body.get("latitude").toString()) : null;
            Double longitude = body.get("longitude") !=null ? Double.valueOf(body.get("longitude").toString()) : null;
            String org = (String) body.getOrDefault("org", null);

            // some providers return 'security' or 'proxy' info — try to read 'proxy' or 'threat'
            Boolean proxy = body.containsKey("proxy") ? Boolean.valueOf(String.valueOf(body.get("proxy"))) : null;
            Boolean vpn = body.containsKey("vpn") ? Boolean.valueOf(String.valueOf(body.get("vpn"))) : null;
            Boolean tor = body.containsKey("tor") ? Boolean.valueOf(String.valueOf(body.get("tor"))) : null;

            boolean isVpnOrProxy = ( proxy != null  && proxy) || (vpn != null && vpn) || (tor != null && tor);

            // Fallbacks may be needed
            return new IpDetails(
                    (String) body.get("ip"),
                    (String) body.get("city"),
                    (String) body.get("region"),
                    (String) body.get("country_name"),
                    latitude, longitude,
                    (String) body.get("timezone"),
                    org, isVpnOrProxy, body
            );
        } catch (Exception ex) {
            // log and return null so we don't block login
            // log.warn("IP lookup failed", ex);
            return null;
        }
    }
}
