package com.in28minutes.learnspringsecurity.resources;

import java.util.List;
import java.util.logging.Logger;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class TodoResource {

  public static final List<Todo> TODOS =
      List.of(new Todo("in28minutes", "Learn Aws"),
      new Todo("in28minutes", "Get AWS Certified"));

  @GetMapping("/todos")
  public List<Todo> retrieveAllTodos() {
    return TODOS;
  }

  @GetMapping("/users/{username}/todos")
  public Todo retrieveTodosForSpecificUser(@PathVariable String username) {
    return TODOS.get(0);
  }

  @PostMapping("/users/{username}/todos")
  public Todo createTodosForSpecificUser(@PathVariable String username, @RequestBody Todo todo) {
    log.info("Create {} for {}", todo, username);
    return TODOS.get(0);
  }
}


record Todo (String username, String description) {}