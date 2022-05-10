package es.upm.dit.isst.movres;

import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalTime;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import es.upm.dit.isst.movres.model.Admin;
import es.upm.dit.isst.movres.model.Cliente;
import es.upm.dit.isst.movres.model.Vmp;
import es.upm.dit.isst.movres.repository.AdminRepository;
import es.upm.dit.isst.movres.repository.ClienteRepository;
import es.upm.dit.isst.movres.repository.VmpRepository;



@SpringBootApplication
public class MovresApplication {
	public static void main(String[] args) {
		SpringApplication.run(MovresApplication.class, args);
	}
	@Bean
	public CommandLineRunner demo(VmpRepository repository, AdminRepository repository2, ClienteRepository repository3) {
	  return (args) -> {
		// save a few vmps
		repository.save(new Vmp(10.5,10.0,false,false,false,true));
		repository.save(new Vmp(12.5,10.0,true,false,false,true));
		repository.save(new Vmp(10.5,12.0,false,false,false, false));
		repository.save(new Vmp(12.5,12.0,false,true,false, true));
		repository.save(new Vmp(14.5,10.0,false,true,false, false));
		repository.save(new Vmp(18.5,12.0,true,false,false, true));

		// save a few admins
		repository2.save(new Admin("danbrown@gmail.com","1234","danbrown","Daniel","Brown Torres"));
		repository2.save(new Admin("ruben@gmail.com","1234","rubenzm","Ruben","Zafra Martin"));

		// save a few clientes
		repository3.save(new Cliente("rodrigo@gmail.com","1234","rodrigo","Rodrigo","Rodrigo"));
	  };
	}

}
