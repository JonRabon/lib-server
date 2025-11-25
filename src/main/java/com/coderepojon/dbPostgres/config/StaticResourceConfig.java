package com.coderepojon.dbPostgres.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class StaticResourceConfig implements WebMvcConfigurer {

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {

        registry.addResourceHandler("/static/avatars/**")
                .addResourceLocations("file:uploads/avatars/")
                .setCachePeriod(3600); // 1 hour cache
    }
}
