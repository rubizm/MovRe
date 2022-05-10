package es.upm.dit.isst.movres.controllerWEB;

import java.util.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.*;
import es.upm.dit.isst.movres.repository.VmpRepository;

import es.upm.dit.isst.movres.model.Vmp;

@Controller
@RequestMapping("/movres")
public class VmpControllerWeb {


    private RestTemplate restTemplate = new RestTemplate();
    
    // Devuelve la vista login.html
    @GetMapping("/login/admin")
    public String loginadmin() {
        return "login_admin";     
    }

    // Devuelve la vista login.html
    @GetMapping("/login/client")
    public String loginclient() {
        return "login_client";     
    }

    @RequestMapping("/listado_admin")
    public String adminLogin(Model model, @RequestParam("email") String email){
        List<Vmp> lista = new ArrayList<Vmp>();
        lista = Arrays.asList(restTemplate.getForEntity("http://localhost:8080/vmp/" + "admin/" + email, Vmp[].class).getBody());
        model.addAttribute("listaAdmin", lista);
        return "listado_admin";
    }

    @RequestMapping("/listado_client")
    public String clientLogin(Model model, @RequestParam("email") String email){
        List<Vmp> lista = new ArrayList<Vmp>();
        lista = Arrays.asList(restTemplate.getForEntity("http://localhost:8080/vmp/" + "cliente/" + email, Vmp[].class).getBody());
        model.addAttribute("listaClient", lista);
        return "listado_client";
    }

}
  