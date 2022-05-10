package es.upm.dit.isst.movres.repository;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

import es.upm.dit.isst.movres.model.Cliente;

public interface ClienteRepository extends CrudRepository <Cliente, String> {
    
}
