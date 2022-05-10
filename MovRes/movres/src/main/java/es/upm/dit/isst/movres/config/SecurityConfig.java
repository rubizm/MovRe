package es.upm.dit.isst.movres.config;

import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
    http
    .authorizeRequests()//Define who can access the resources
    .antMatchers("/movres/login/admin").permitAll()
    .antMatchers("/listado_admin").hasAnyRole("ADMIN")
    .antMatchers("/listado_client").hasAnyRole("CLIENTE")
    .anyRequest().authenticated().and()
    .formLogin().permitAll().and()
    .logout().permitAll();
    }

    @Autowired
    DataSource ds;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth
        .jdbcAuthentication().dataSource(ds)
        .usersByUsernameQuery("select username, password, enabled from users where username=?")
        .authoritiesByUsernameQuery("select username, authority from authorities where username=?");
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web
        .ignoring()
        .antMatchers("/h2/**");  //To check h2 through its web interface
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}

