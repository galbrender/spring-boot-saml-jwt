package com.example.demo.api;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/data")
public class DataController {


    @RequestMapping(value = "/list", method = RequestMethod.GET)
    public String list(){

        log.info("listing data");



        return "Public data";
    }
}
